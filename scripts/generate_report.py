#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# TicketRouter: Automated ticket sorting and routing system.
# Copyright (C) 2026 Віталій Струтинський
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# For commercial licensing options, please contact the author.

"""
===============================================================================
Тріаж заявок на доступ: Генератор аналітичних звітів та показників якості
===============================================================================
Генерує комплексні звіти на основі розділу 5 (Крок 8) та розділу 11 README.md,
виконуючи аналітичні запити зі sql/report.sql до бази даних PostgreSQL.

Категорії звіту:
  - Загальна кількість отриманих повідомлень
  - Повні заявки (status = 'ready_for_review')
  - Неповні заявки (status = 'needs_info')
  - Ризиковані заявки (risk_flags > 0)
  - Повідомлення, що не є заявками (classification = 'not_request')
  - Повідомлення з маскованими секретами (has_sensitive_data = true)
  - Заблоковані prompt injections (is_prompt_injection = true)
  - Рівень валідності схеми (%)
  - Орієнтовна вартість Gemini ($ USD)
  - Розподіл за маршрутами призначення (standard_approval проти devops_manual_review)
  - Топ пропущених обов'язкових полів у неповних заявках

Використання:
  python scripts/generate_report.py [--live | --simulate] [--export md|json]
===============================================================================
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Забезпечення коректного виводу UTF-8 у терміналах Windows
if sys.platform.startswith("win") and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Спроба завантаження dotenv (без прямого читання файлу)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    import psycopg
except ImportError:
    psycopg = None

BASE_DIR = Path(__file__).resolve().parent.parent
SQL_REPORT_PATH = BASE_DIR / "sql" / "report.sql"
GOLDEN_DATASET_PATH = BASE_DIR / "evaluation" / "golden_dataset.json"
REPORTS_DIR = BASE_DIR / "reports"

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


def fetch_from_postgres() -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Підключається до PostgreSQL та виконує аналітичні запити зі sql/report.sql.
    """
    if not psycopg:
        raise RuntimeError("Для виконання запитів до PostgreSQL необхідна бібліотека 'psycopg'.")

    host = os.getenv("POSTGRES_HOST", "localhost")
    port = int(os.getenv("POSTGRES_PORT", "5432"))
    user = os.getenv("POSTGRES_USER", "techops")
    password = os.getenv("POSTGRES_PASSWORD", "techops_secret_pass")
    dbname = os.getenv("POSTGRES_DB", "access_requests")

    conn_str = f"host={host} port={port} user={user} password={password} dbname={dbname} connect_timeout=3"

    with psycopg.connect(conn_str) as conn:
        with conn.cursor() as cur:
            # Запит 1: Загальне зведення метрик
            cur.execute("""
                SELECT 
                    (SELECT COUNT(*) FROM messages) AS total_messages_received,
                    (SELECT COUNT(*) FROM access_requests WHERE status = 'ready_for_review') AS complete_requests,
                    (SELECT COUNT(*) FROM access_requests WHERE status = 'needs_info') AS incomplete_requests,
                    (SELECT COUNT(*) FROM access_requests WHERE jsonb_array_length(risk_flags) > 0) AS risky_requests,
                    (SELECT COUNT(*) FROM messages WHERE classification = 'not_request') AS non_requests,
                    (SELECT COUNT(*) FROM messages WHERE has_sensitive_data = TRUE) AS messages_with_secrets_redacted,
                    (SELECT COUNT(*) FROM messages WHERE is_prompt_injection = TRUE) AS prompt_injections_blocked,
                    ROUND(
                        COALESCE(
                            100.0 * COUNT(*) FILTER (WHERE p.schema_valid = TRUE) / NULLIF(COUNT(*), 0),
                            100.0
                        ), 2
                    ) AS schema_validity_percent,
                    COALESCE(SUM(p.estimated_cost_usd), 0.0) AS total_estimated_cost_usd
                FROM processing_runs p;
            """)
            row = cur.fetchone()
            summary = {
                "total_messages_received": row[0] or 0,
                "complete_requests": row[1] or 0,
                "incomplete_requests": row[2] or 0,
                "risky_requests": row[3] or 0,
                "non_requests": row[4] or 0,
                "messages_with_secrets_redacted": row[5] or 0,
                "prompt_injections_blocked": row[6] or 0,
                "schema_validity_percent": float(row[7] or 100.0),
                "total_estimated_cost_usd": float(row[8] or 0.0)
            }

            # Запит 2: Розподіл за маршрутами призначення
            cur.execute("""
                SELECT 
                    route,
                    status,
                    COUNT(*) AS request_count,
                    ROUND(100.0 * COUNT(*) / NULLIF(SUM(COUNT(*)) OVER (), 0), 1) AS percent_of_total
                FROM access_requests
                GROUP BY route, status
                ORDER BY request_count DESC;
            """)
            routes = []
            for r in cur.fetchall():
                routes.append({
                    "route": r[0],
                    "status": r[1],
                    "count": r[2],
                    "percent": float(r[3] or 0.0)
                })

            # Запит 3: Найчастіші пропущені обов'язкові поля
            cur.execute("""
                SELECT 
                    missing_field.value::text AS missing_field_name,
                    COUNT(*) AS count
                FROM access_requests,
                     jsonb_array_elements_text(missing_fields) AS missing_field
                WHERE status = 'needs_info'
                GROUP BY missing_field_name
                ORDER BY count DESC;
            """)
            missing = []
            for m in cur.fetchall():
                missing.append({
                    "field": m[0],
                    "count": m[1]
                })

            return summary, routes, missing


def simulate_from_golden_dataset() -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Обчислює статистику звіту на основі evaluation/golden_dataset.json.
    Використовується, коли PostgreSQL офлайн або під час симуляції оцінювання.
    """
    if not GOLDEN_DATASET_PATH.exists():
        raise FileNotFoundError(f"Еталонний набір даних не знайдено за шляхом {GOLDEN_DATASET_PATH}")

    with open(GOLDEN_DATASET_PATH, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    total_messages = len(dataset)
    complete_requests = 0
    incomplete_requests = 0
    risky_requests = 0
    non_requests = 0
    secrets_redacted = 0
    injections_blocked = 0
    total_cost = 0.0

    route_counts = {}
    missing_fields_counts = {}

    for item in dataset:
        pre = item.get("pre_guardrails", {})
        if pre.get("has_sensitive_data"):
            secrets_redacted += 1
        if pre.get("is_prompt_injection"):
            injections_blocked += 1

        llm = item["expected_llm_output"]
        classification = llm.get("classification")
        if classification == "not_request" or not llm.get("is_access_request"):
            non_requests += 1

        requests = llm.get("requests", [])
        routes = item.get("expected_routing", [])

        # Оцінка токенів та вартості згідно з тарифами gemini-3.1-flash-lite у README.md ($0.25 in / $1.50 out за 1M)
        in_tok = len(item["input"]["message_text"].split()) * 2 + 300
        out_tok = len(json.dumps(llm).split())
        cost = (in_tok * 0.25 + out_tok * 1.50) / 1_000_000.0
        total_cost += cost

        for idx, req in enumerate(requests):
            rt_info = routes[idx] if idx < len(routes) else {"route": "devops_manual_review", "status": "ready_for_review"}
            status = rt_info.get("status", "ready_for_review")
            route = rt_info.get("route", "standard_approval")

            if status == "ready_for_review":
                complete_requests += 1
            elif status == "needs_info":
                incomplete_requests += 1

            risk_flags = req.get("risk_flags", [])
            if len(risk_flags) > 0:
                risky_requests += 1

            # Підрахунок маршрутів
            key = (route, status)
            route_counts[key] = route_counts.get(key, 0) + 1

            # Пропущені поля
            for mf in req.get("missing_fields", []):
                missing_fields_counts[mf] = missing_fields_counts.get(mf, 0) + 1

    total_req_count = max(sum(route_counts.values()), 1)
    route_list = [
        {"route": k[0], "status": k[1], "count": v, "percent": round((v / total_req_count) * 100.0, 1)}
        for k, v in route_counts.items()
    ]
    route_list.sort(key=lambda x: x["count"], reverse=True)

    missing_list = [
        {"field": k, "count": v}
        for k, v in sorted(missing_fields_counts.items(), key=lambda x: x[1], reverse=True)
    ]

    summary = {
        "total_messages_received": total_messages,
        "complete_requests": complete_requests,
        "incomplete_requests": incomplete_requests,
        "risky_requests": risky_requests,
        "non_requests": non_requests,
        "messages_with_secrets_redacted": secrets_redacted,
        "prompt_injections_blocked": injections_blocked,
        "schema_validity_percent": 100.0,
        "total_estimated_cost_usd": round(total_cost, 6)
    }

    return summary, route_list, missing_list


def print_report_tables(summary: Dict[str, Any], routes: List[Dict[str, Any]], missing: List[Dict[str, Any]], source_label: str):
    print_banner(f"TechOps Тріаж та якість: Аналітичний звіт ({source_label})")

    print(f"{BOLD}{CYAN}1. Загальне зведення KPI (README Розділ 11 та SQL Report):{RESET}")
    print(f"  {'-' * 70}")
    print(f"  {'Назва метрики':<42} | {'Значення':<15}")
    print(f"  {'-' * 70}")
    print(f"  {'Всього оброблено повідомлень':<42} | {BOLD}{summary['total_messages_received']}{RESET}")
    print(f"  {'Повні заявки (ready_for_review)':<42} | {GREEN}{summary['complete_requests']}{RESET}")
    print(f"  {'Неповні заявки (needs_info)':<42} | {YELLOW}{summary['incomplete_requests']}{RESET}")
    print(f"  {'Ризиковані заявки (потребують рев\'ю)':<42} | {RED}{summary['risky_requests']}{RESET}")
    print(f"  {'Не є заявками (привітання, подяки)':<42} | {summary['non_requests']}")
    print(f"  {'Секрети замасковано (токени, ключі, паролі)':<42} | {CYAN}{summary['messages_with_secrets_redacted']}{RESET}")
    print(f"  {'Prompt Injections заблоковано':<42} | {RED}{summary['prompt_injections_blocked']}{RESET}")
    print(f"  {'Рівень валідності схеми (%)':<42} | {GREEN}{summary['schema_validity_percent']}%{RESET}")
    print(f"  {'Загальна орієнтовна вартість Gemini ($ USD)':<42} | ${summary['total_estimated_cost_usd']:.4f}")
    print(f"  {'-' * 70}\n")

    print(f"{BOLD}{CYAN}2. Розподіл за маршрутами призначення:{RESET}")
    print(f"  {'-' * 70}")
    print(f"  {'Маршрут':<25} | {'Статус':<18} | {'Кількість':<10} | {'Частка (%)':<10}")
    print(f"  {'-' * 70}")
    for r in routes:
        route_color = GREEN if r["route"] == "standard_approval" else (RED if "devops" in r["route"] else YELLOW)
        print(f"  {route_color}{r['route']:<25}{RESET} | {r['status']:<18} | {r['count']:<10} | {r['percent']}%")
    print(f"  {'-' * 70}\n")

    print(f"{BOLD}{CYAN}3. Топ пропущених обов'язкових полів у неповних заявках:{RESET}")
    print(f"  {'-' * 50}")
    print(f"  {'Назва поля':<30} | {'Кількість':<10}")
    print(f"  {'-' * 50}")
    for m in missing:
        print(f"  {YELLOW}{m['field']:<30}{RESET} | {m['count']}")
    print(f"  {'-' * 50}\n")


def export_markdown_report(summary: Dict[str, Any], routes: List[Dict[str, Any]], missing: List[Dict[str, Any]], filepath: Path, source_label: str):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    md = f"""# 📑 TechOps Тріаж заявок на доступ: Підсумковий звіт

**Сформовано:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  
**Джерело даних:** {source_label}  

---

## 📌 1. Загальне зведення KPI (Розділ 11)

| Метрика | Значення | Опис |
| :--- | :---: | :--- |
| **Всього оброблено повідомлень** | **{summary['total_messages_received']}** | Унікальні проаналізовані повідомлення зі Slack |
| **Повні заявки** | **{summary['complete_requests']}** | Всі обов'язкові поля валідні (`ready_for_review`) |
| **Неповні заявки** | **{summary['incomplete_requests']}** | Пропущені поля, надіслано питання автору (`needs_info`) |
| **Ризиковані заявки** | **{summary['risky_requests']}** | Привілейований доступ, прод БД, root або прапорці безпеки |
| **Не є заявками** | **{summary['non_requests']}** | Привітання, подяки, нерелевантні повідомлення (`not_request`) |
| **Секрети замасковано** | **{summary['messages_with_secrets_redacted']}** | Ключі AWS, паролі, приватні ключі знешкоджено |
| **Prompt Injections заблоковано** | **{summary['prompt_injections_blocked']}** | Перехоплені спроби обходу правил та системного промпту |
| **Рівень валідності схеми** | **{summary['schema_validity_percent']}%** | JSON від Gemini строго відповідає схемі |
| **Орієнтовна вартість** | **${summary['total_estimated_cost_usd']:.4f} USD** | Розраховано за спожитими вхідними та вихідними токенами |

---

## 🚦 2. Розподіл за маршрутами призначення

| Цільовий маршрут | Статус | Кількість | Відсоток |
| :--- | :--- | :---: | :---: |
"""
    for r in routes:
        md += f"| `{r['route']}` | `{r['status']}` | **{r['count']}** | {r['percent']}% |\n"

    md += """
---

## ❓ 3. Топ пропущених обов'язкових полів у неповних заявках

| Назва пропущеного поля | Частота |
| :--- | :---: |
"""
    for m in missing:
        md += f"| `{m['field']}` | **{m['count']}** |\n"

    md += """
---

## 🔒 4. Архітектурні принципи та безпека

- **Жодного автоматичного надання доступу:** Доступ ніколи не надається безпосередньо через LLM.
- **Детерміновані правила:** Усі рішення про маршрутизацію приймаються строго кодом за бізнес-правилами.
- **Pre-LLM Guardrails:** Чутливі дані маскуються мітками `[REDACTED_*]` до виклику моделей штучного інтелекту.
"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(md)


def main():
    parser = argparse.ArgumentParser(description="Генератор аналітичних звітів для тріажу заявок на доступ")
    parser.add_argument("--simulate", action="store_true", help="Згенерувати звіт на основі симуляції еталонного датасету")
    parser.add_argument("--live", action="store_true", help="Примусовий запит до живої бази даних PostgreSQL")
    parser.add_argument("--export", choices=["md", "json"], default="md", help="Формат експорту звіту (за замовчуванням: md)")

    args = parser.parse_args()

    summary = None
    routes = []
    missing = []
    source = "База даних PostgreSQL"

    if args.simulate:
        source = "Симуляція на основі Golden Dataset"
        summary, routes, missing = simulate_from_golden_dataset()
    else:
        try:
            summary, routes, missing = fetch_from_postgres()
        except Exception as e:
            print(f"{YELLOW}Не вдалося виконати запит до PostgreSQL ({str(e)}).{RESET}")
            print(f"{CYAN}Автоматичне перемикання у режим симуляції на основі golden dataset...{RESET}")
            source = "Резервна симуляція (Golden Dataset)"
            summary, routes, missing = simulate_from_golden_dataset()

    print_report_tables(summary, routes, missing, source)

    # Експорт звіту
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.export == "md":
        export_path = REPORTS_DIR / f"triage_report_{ts}.md"
        export_markdown_report(summary, routes, missing, export_path, source)
        print(f"{GREEN}Звіт у форматі Markdown сформовано:{RESET} {export_path}")
    else:
        export_path = REPORTS_DIR / f"triage_report_{ts}.json"
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump({
                "summary": summary,
                "routes": routes,
                "missing_fields": missing,
                "source": source,
                "timestamp": datetime.now().isoformat()
            }, f, indent=2, ensure_ascii=False)
        print(f"{GREEN}Звіт у форматі JSON сформовано:{RESET} {export_path}")


if __name__ == "__main__":
    main()
