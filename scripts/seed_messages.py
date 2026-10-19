#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
Тріаж заявок на доступ: Завантаження тестових повідомлень та симулятор
===============================================================================
Завантажує тестові сценарії з evaluation/golden_dataset.json та симулює вхідний
трафік шляхом надсилання на вебхук n8n або прямого наповнення бази PostgreSQL.

Режими роботи:
  1. Режим вебхука (за замовчуванням): надсилає повідомлення на вебхук-ендпоінт n8n.
  2. Режим PostgreSQL: безпосередньо заповнює таблиці messages, access_requests
     та processing_runs у PostgreSQL для тестування звітів та SQL-запитів офлайн.
  3. Режим Dry-run: перевіряє та виводить дані без фактичного надсилання.

Використання:
  python scripts/seed_messages.py [--target webhook|postgres|dry-run]
                                  [--url http://localhost:5678/webhook/access-request]
                                  [--limit N] [--scenario NAME] [--delay SECONDS]
===============================================================================
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Забезпечення коректного виводу UTF-8 у терміналах Windows
if sys.platform.startswith("win") and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Завантаження dotenv за наявності (без прямого читання файлу)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    import requests
except ImportError:
    requests = None

try:
    import psycopg
except ImportError:
    psycopg = None

BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_PATH = BASE_DIR / "evaluation" / "golden_dataset.json"

# ANSI кольори для терміналу
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner(text: str):
    print(f"\n{BOLD}{CYAN}{'=' * 80}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 80}{RESET}\n")


def seed_via_webhook(dataset: List[Dict[str, Any]], webhook_url: str, delay_sec: float) -> Dict[str, int]:
    """
    Надсилає кожне повідомлення на вебхук n8n через HTTP POST.
    """
    if not requests:
        print(f"{RED}Помилка: пакет 'requests' є обов'язковим для режиму вебхука.{RESET}")
        sys.exit(1)

    stats = {"success": 0, "failed": 0, "total": len(dataset)}
    print(f"Цільовий вебхук: {BOLD}{webhook_url}{RESET}")
    print(f"Відправка {len(dataset)} повідомлень з інтервалом {delay_sec}с...\n")

    for idx, item in enumerate(dataset, 1):
        inp = item["input"]
        payload = {
            "source_message_id": inp["source_message_id"],
            "channel_id": inp["channel_id"],
            "author_id": inp["author_id"],
            "thread_ts": inp.get("thread_ts"),
            "message_text": inp["message_text"],
            "thread_context": item.get("thread_context", [])
        }

        t0 = time.time()
        try:
            resp = requests.post(webhook_url, json=payload, timeout=15)
            latency = (time.time() - t0) * 1000

            if resp.status_code in (200, 201):
                stats["success"] += 1
                status_str = f"{GREEN}HTTP {resp.status_code}{RESET}"
            else:
                stats["failed"] += 1
                status_str = f"{RED}HTTP {resp.status_code}{RESET}"

            print(f"[{idx:02d}/{len(dataset)}] {item['id']} ({item['scenario']}) -> {status_str} ({latency:.1f}ms)")
        except requests.exceptions.RequestException as e:
            stats["failed"] += 1
            print(f"[{idx:02d}/{len(dataset)}] {item['id']} ({item['scenario']}) -> {RED}FAILED{RESET} ({str(e)})")

        if delay_sec > 0 and idx < len(dataset):
            time.sleep(delay_sec)

    return stats


def seed_via_postgres(dataset: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Безпосередньо наповнює PostgreSQL даними (messages, access_requests, processing_runs)
    відповідно до схеми sql/001_init.sql.
    """
    if not psycopg:
        print(f"{RED}Помилка: пакет 'psycopg' є обов'язковим для прямого наповнення PostgreSQL.{RESET}")
        sys.exit(1)

    host = os.getenv("POSTGRES_HOST", "localhost")
    port = int(os.getenv("POSTGRES_PORT", "5432"))
    user = os.getenv("POSTGRES_USER", "techops")
    password = os.getenv("POSTGRES_PASSWORD", "techops_secret_pass")
    dbname = os.getenv("POSTGRES_DB", "access_requests")

    conn_str = f"host={host} port={port} user={user} password={password} dbname={dbname} connect_timeout=3"
    print(f"Підключення до PostgreSQL: {BOLD}{user}@{host}:{port}/{dbname}{RESET}...")

    stats = {"messages": 0, "requests": 0, "runs": 0}

    try:
        with psycopg.connect(conn_str, autocommit=True) as conn:
            with conn.cursor() as cur:
                print(f"{GREEN}Успішно підключено до PostgreSQL!{RESET}\n")

                for item in dataset:
                    inp = item["input"]
                    pre = item.get("pre_guardrails", {})
                    llm = item["expected_llm_output"]
                    routes = item.get("expected_routing", [])

                    # 1. Вставка в таблицю messages
                    cur.execute(
                        """
                        INSERT INTO messages (
                            source_message_id,
                            channel_id,
                            thread_ts,
                            author_id,
                            raw_message_text,
                            sanitized_text,
                            has_sensitive_data,
                            is_prompt_injection,
                            classification,
                            processing_status
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (source_message_id) DO UPDATE SET
                            sanitized_text = EXCLUDED.sanitized_text,
                            has_sensitive_data = EXCLUDED.has_sensitive_data,
                            is_prompt_injection = EXCLUDED.is_prompt_injection,
                            processing_status = 'processed';
                        """,
                        (
                            inp["source_message_id"],
                            inp["channel_id"],
                            inp.get("thread_ts"),
                            inp["author_id"],
                            inp["message_text"],
                            pre.get("sanitized_text", inp["message_text"]),
                            pre.get("has_sensitive_data", False),
                            pre.get("is_prompt_injection", False),
                            llm.get("classification", "access_request"),
                            "processed"
                        )
                    )
                    stats["messages"] += 1

                    # 2. Вставка в таблицю access_requests (Примітка: is_complete є GENERATED ALWAYS у PostgreSQL)
                    req_list = llm.get("requests", [])
                    for req_idx, req in enumerate(req_list):
                        rt_info = routes[req_idx] if req_idx < len(routes) else {"route": "devops_manual_review", "status": "ready_for_review"}
                        
                        cur.execute(
                            """
                            INSERT INTO access_requests (
                                source_message_id,
                                target_user,
                                resource,
                                environment,
                                access_level,
                                justification,
                                duration,
                                status,
                                route,
                                missing_fields,
                                clarification_question,
                                risk_flags,
                                extracted_data
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                            """,
                            (
                                inp["source_message_id"],
                                req.get("target_user"),
                                req.get("resource"),
                                req.get("environment"),
                                req.get("access_level"),
                                req.get("justification"),
                                req.get("duration"),
                                rt_info.get("status", "ready_for_review"),
                                rt_info.get("route", "standard_approval"),
                                json.dumps(req.get("missing_fields", [])),
                                req.get("clarification_question"),
                                json.dumps(req.get("risk_flags", [])),
                                json.dumps(req)
                            )
                        )
                        stats["requests"] += 1

                    # 3. Вставка в таблицю processing_runs
                    tokens_in = len(inp["message_text"].split()) * 2 + 300
                    tokens_out = len(json.dumps(llm).split())
                    # Тариф gemini-3.1-flash-lite з README ($0.25 in / $1.50 out за 1M)
                    cost_usd = (tokens_in * 0.25 + tokens_out * 1.50) / 1_000_000.0

                    cur.execute(
                        """
                        INSERT INTO processing_runs (
                            source_message_id,
                            model_id,
                            schema_valid,
                            error_type,
                            latency_ms,
                            input_tokens,
                            output_tokens,
                            estimated_cost_usd
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                        """,
                        (
                            inp["source_message_id"],
                            os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite"),
                            True,
                            None,
                            450,
                            tokens_in,
                            tokens_out,
                            cost_usd
                        )
                    )
                    stats["runs"] += 1

                print(f"{GREEN}Пряме заповнення PostgreSQL успішно завершено!{RESET}")
                print(f"  Повідомлень додано: {stats['messages']}")
                print(f"  Заявок на доступ додано: {stats['requests']}")
                print(f"  Запусків обробки додано: {stats['runs']}")

    except Exception as e:
        print(f"{RED}Помилка підключення до PostgreSQL: {str(e)}{RESET}")
        print(f"{YELLOW}Підказка: Переконайтеся, що контейнер postgres запущено: docker compose -f infra/docker-compose.yml up -d{RESET}")
        sys.exit(1)

    return stats


def dry_run(dataset: List[Dict[str, Any]]):
    """
    Відображає повідомлення, які були б завантажені, без фактичного надсилання.
    """
    print_banner("Симуляція без відправки (Dry-Run)")
    print(f"Загалом завантажено тестових випадків: {len(dataset)}\n")

    for idx, item in enumerate(dataset, 1):
        inp = item["input"]
        print(f"[{idx:02d}] {BOLD}{item['id']}{RESET} | Сценарій: {item['scenario']}")
        print(f"     Автор: {inp['author_id']} | Канал: {inp['channel_id']} | Тред: {inp.get('thread_ts')}")
        print(f"     Повідомлення: \"{inp['message_text'][:90]}...\"")
        print(f"     Секрети: {item['pre_guardrails'].get('has_sensitive_data')} | Ін'єкція: {item['pre_guardrails'].get('is_prompt_injection')}")
        print(f"     Заявок: {len(item['expected_llm_output'].get('requests', []))}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Симулятор та завантажувач тестових повідомлень для тріажу заявок")
    parser.add_argument("--target", "-t", choices=["webhook", "postgres", "dry-run"], default="webhook",
                        help="Цільовий режим: 'webhook' (за замовчуванням), 'postgres' (прямий запис у БД) або 'dry-run'")
    parser.add_argument("--url", "-u", default=None,
                        help="URL вебхука n8n (за замовчуванням: http://localhost:5678/webhook/access-request або $N8N_WEBHOOK_URL)")
    parser.add_argument("--limit", "-l", type=int, default=None,
                        help="Обмежити кількість повідомлень для відправки")
    parser.add_argument("--scenario", "-s", type=str, default=None,
                        help="Фільтрувати за назвою конкретного сценарію")
    parser.add_argument("--delay", "-d", type=float, default=0.2,
                        help="Затримка в секундах між запитами до вебхука (за замовчуванням: 0.2с)")

    args = parser.parse_args()

    print_banner("TechOps Тріаж заявок на доступ: Симулятор завантаження")

    if not DATASET_PATH.exists():
        print(f"{RED}Помилка: Набір даних не знайдено за шляхом {DATASET_PATH}{RESET}")
        sys.exit(1)

    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    if args.scenario:
        dataset = [d for d in dataset if d.get("scenario") == args.scenario]
        print(f"Відфільтровано за сценарієм: {BOLD}{args.scenario}{RESET} ({len(dataset)} елементів)")

    if args.limit:
        dataset = dataset[:args.limit]
        print(f"Обмежено до перших {BOLD}{args.limit}{RESET} елементів")

    if args.target == "dry-run":
        dry_run(dataset)
    elif args.target == "postgres":
        seed_via_postgres(dataset)
    else:
        # Режим вебхука за замовчуванням
        webhook_url = args.url or os.getenv("N8N_WEBHOOK_URL") or "http://localhost:5678/webhook/access-request"
        seed_via_webhook(dataset, webhook_url, args.delay)


if __name__ == "__main__":
    main()
