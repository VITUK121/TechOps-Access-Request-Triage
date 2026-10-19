#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
Тріаж заявок на доступ: Автоматизований модуль оцінювання якості
===============================================================================
Оцінює пайплайн тріажу за допомогою еталонного набору evaluation/golden_dataset.json.
Розраховує всі необхідні метрики з розділу 10.2 README.md:
  1. Точність класифікації (classification accuracy)
  2. Точність вилучення полів (target_user, resource, environment, access_level, duration, justification)
  3. Виявлення повноти даних (is_complete та missing_fields)
  4. Точність маршрутизації (standard_approval, devops_manual_review, needs_info, not_request)
  5. Рівень відмов валідації схеми JSON Schema
  6. Повнота виявлення ризиків (recall прапорців risk_flags)
  7. Точність розділення кількох заявок з одного повідомлення
  8. Точність pre-guardrails (маскування чутливих даних та виявлення prompt injection)
  9. Затримка обробки (latency) та орієнтовна вартість на 1000 запитів

Використання:
  python evaluation/run_evaluation.py [--offline | --live | --webhook URL] [--limit N] [--scenario NAME]
===============================================================================
"""

import argparse
import json
import os
import re
import sys
import time
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

# Завантаження dotenv за наявності (без прямого читання файлу)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    import jsonschema
except ImportError:
    jsonschema = None

try:
    import requests
except ImportError:
    requests = None

# Шляхи до файлів
BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_PATH = BASE_DIR / "evaluation" / "golden_dataset.json"
SCHEMA_PATH = BASE_DIR / "schemas" / "access_request.schema.json"
PROMPT_PATH = BASE_DIR / "prompts" / "exctraction.md"
RESULTS_DIR = BASE_DIR / "evaluation" / "results"

# Тарифи Gemini для gemini-3.1-flash-lite / flash ($ за 1 млн токенів)
# Згідно з Розділом 12 README
INPUT_PRICE_PER_MILLION = 0.075
OUTPUT_PRICE_PER_MILLION = 0.30

# Кольори для терміналу
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_header(title: str):
    print(f"\n{BOLD}{CYAN}{'=' * 80}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 80}{RESET}\n")


# =============================================================================
# Логіка Pre-Guardrails (перевірки безпеки перед викликом LLM)
# =============================================================================

def redact_sensitive_data(text: str) -> Tuple[str, bool, List[str]]:
    """
    Сканує текст на наявність облікових даних, токенів, ключів AWS, приватних ключів, паролів.
    Повертає (sanitized_text, has_sensitive_data, detected_types).
    """
    sanitized = text
    detected = []

    # 1. Ідентифікатор ключа доступу AWS (AKIA...)
    aws_pattern = re.compile(r'\bAKIA[0-9A-Z]{16}\b')
    if aws_pattern.search(sanitized):
        sanitized = aws_pattern.sub('[REDACTED_AWS_KEY]', sanitized)
        detected.append("aws_key")

    # Секретний ключ AWS
    aws_sec_pattern = re.compile(r'(?:aws_secret_access_key|aws_secret|secret_key)\s*=\s*[A-Za-z0-9/+=]{30,}', re.IGNORECASE)
    if aws_sec_pattern.search(sanitized):
        sanitized = re.sub(r'(aws_secret_access_key|aws_secret|secret_key)\s*=\s*[A-Za-z0-9/+=]{30,}', r'\1=[REDACTED_AWS_KEY]', sanitized, flags=re.IGNORECASE)
        detected.append("aws_secret")

    # 2. Приватні ключі (RSA, OpenSSH тощо)
    pk_pattern = re.compile(r'-----BEGIN (?:RSA |OPENSSH |PGP |EC )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |OPENSSH |PGP |EC )?PRIVATE KEY-----')
    if pk_pattern.search(sanitized):
        sanitized = pk_pattern.sub('[REDACTED_PRIVATE_KEY]', sanitized)
        detected.append("private_key")

    # 3. Токени GitHub / Slack / Bearer JWT
    gh_pattern = re.compile(r'\bghp_[A-Za-z0-9]{36,}\b')
    if gh_pattern.search(sanitized):
        sanitized = gh_pattern.sub('[REDACTED_TOKEN]', sanitized)
        detected.append("github_token")

    slack_pattern = re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{20,}\b')
    if slack_pattern.search(sanitized):
        sanitized = slack_pattern.sub('[REDACTED_TOKEN]', sanitized)
        detected.append("slack_token")

    jwt_pattern = re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b')
    if jwt_pattern.search(sanitized):
        sanitized = jwt_pattern.sub('[REDACTED_TOKEN]', sanitized)
        detected.append("jwt_token")

    # 4. Паролі
    pwd_pattern = re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*([^\s"\'<>]+)', re.IGNORECASE)
    if pwd_pattern.search(sanitized):
        sanitized = re.sub(r'((?:password|passwd|pwd)\s*[=:])\s*([^\s"\'<>]+)', r'\1 [REDACTED_PASSWORD]', sanitized, flags=re.IGNORECASE)
        detected.append("password")

    # Паролі у рядках підключення, напр. postgres://user:pass@host
    conn_pattern = re.compile(r'://([^:]+):([^@]+)@')
    if conn_pattern.search(sanitized):
        sanitized = conn_pattern.sub(r'://\1:[REDACTED_PASSWORD]@', sanitized)
        detected.append("connection_password")

    has_sensitive = len(detected) > 0
    return sanitized, has_sensitive, detected


def detect_prompt_injection(text: str) -> Tuple[bool, List[str]]:
    """
    Перевіряє наявність евристик prompt injection та спроб джейлбрейку.
    """
    injection_patterns = [
        (r'system\s+override', "system_override"),
        (r'ignore\s+(?:all\s+)?(?:previous|above)\s+instructions', "ignore_previous_instructions"),
        (r'disregard\s+(?:all\s+)?(?:previous|above)', "disregard_instructions"),
        (r'ігноруй\s+(?:усі\s+|всі\s+)?попередні\s+інструкції', "ignore_previous_instructions_ua"),
        (r'забудь\s+(?:що\s+ти\s+|все\s+)', "forget_role_ua"),
        (r'ти\s+тепер\s+', "role_hijack_ua"),
        (r'you\s+are\s+now\s+', "role_hijack_en"),
        (r'</user_message>', "tag_breakout"),
        (r'<system>', "fake_system_tag"),
        (r'bypass\s+(?:standard\s+)?triage', "bypass_triage"),
        (r'administrative\s+override', "admin_override"),
        (r'відповідай\s+approved', "force_approved_ua"),
        (r'give\s+answer\s+approved', "force_approved_en"),
        (r'end\s+of\s+prompt', "end_of_prompt"),
        (r'покажи\s+(?:мені\s+)?(?:свій\s+)?системний\s+промпт', "leak_prompt_ua"),
        (r'print\s+out\s+(?:the\s+)?(?:root\s+)?api\s+key', "leak_secret_en")
    ]

    detected_flags = []
    text_lower = text.lower()
    for pattern, flag in injection_patterns:
        if re.search(pattern, text_lower):
            detected_flags.append(flag)

    return len(detected_flags) > 0, detected_flags


# =============================================================================
# Детермінований маршрутизатор (згідно з rules/routing_rules.md)
# =============================================================================

def apply_deterministic_routing(llm_output: Dict[str, Any], pre_flags: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Реалізує детерміновані правила бізнес-маршрутизації на основі:
      rules/routing_rules.md та Розділу 5 (Крок 6) README.md.
    Повертає список словників {"route": ..., "status": ...} для кожної заявки
    або один елемент у разі not_request.
    """
    is_access = llm_output.get("is_access_request", False)
    classification = llm_output.get("classification", "access_request")
    requests_list = llm_output.get("requests", [])

    if not is_access or classification == "not_request" or len(requests_list) == 0:
        return [{"route": "not_request", "status": "processed"}]

    results = []
    for req in requests_list:
        is_complete = req.get("is_complete", False)
        env = (req.get("environment") or "unknown").lower()
        acc = (req.get("access_level") or "unknown").lower()
        duration = (req.get("duration") or "").lower()
        user = (req.get("target_user") or "myself").lower()
        risk_flags = [f.lower() for f in req.get("risk_flags", [])]
        resource = (req.get("resource") or "").lower()

        # Перевірка на ін'єкцію або критичний прапорець безпеки
        is_injection = pre_flags.get("is_prompt_injection", False) or "prompt_injection_attempt" in risk_flags

        # 1. Prompt injection або прапорець безпеки
        if is_injection:
            results.append({
                "route": "devops_manual_review",
                "status": "security_flagged"
            })
            continue

        # 2. Неповна заявка (потрібні додаткові дані)
        if not is_complete:
            results.append({
                "route": "needs_info",
                "status": "needs_info"
            })
            continue

        # 3. Високий ризик: Production / Root / AWS IAM / Безстроковий доступ / Запит для іншої особи
        is_prod = env == "production"
        is_privileged = acc in ["admin", "root", "write-all", "superuser"] or "privileged_access" in risk_flags
        is_prod_db = ("database" in resource or "postgres" in resource or "mysql" in resource or "redis" in resource or "mongo" in resource) and is_prod
        is_iam = "iam" in resource or "aws iam" in resource or "root" in resource or "aws_iam_access" in risk_flags
        is_permanent = "permanent" in duration or "постійн" in duration or "назавжди" in duration
        is_other_user = user not in ["myself", "author", "me", "я", "себе"]

        if is_prod or is_privileged or is_prod_db or is_iam or is_permanent or is_other_user or len(risk_flags) > 0:
            results.append({
                "route": "devops_manual_review",
                "status": "ready_for_review"
            })
        else:
            # 4. Стандартне погодження (безпечні staging/dev/sandbox, читання, <= 14 днів, для себе)
            results.append({
                "route": "standard_approval",
                "status": "ready_for_review"
            })

    return results


# =============================================================================
# Реалізації викликів (інференс пайплайну)
# =============================================================================

def call_gemini_api(api_key: str, model: str, prompt: str, user_content: str) -> Tuple[Dict[str, Any], int, int, float]:
    """
    Викликає Google AI Studio Gemini API через HTTP POST.
    Повертає (parsed_json, input_tokens, output_tokens, latency_sec).
    """
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [
                    {"text": f"{prompt}\n\n<user_message untrusted=\"true\">\n{user_content}\n</user_message>"}
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.0,
            "responseMimeType": "application/json"
        }
    }

    t0 = time.time()
    resp = requests.post(url, headers=headers, json=payload, timeout=30)
    latency = time.time() - t0

    if resp.status_code != 200:
        raise RuntimeError(f"Помилка Gemini API {resp.status_code}: {resp.text}")

    data = resp.json()
    candidates = data.get("candidates", [])
    if not candidates:
        raise RuntimeError(f"API не повернуло кандидатів відповіді: {data}")

    text_resp = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
    
    # Отримання метрик використаних токенів
    usage = data.get("usageMetadata", {})
    in_tokens = usage.get("promptTokenCount", len(prompt.split()) + len(user_content.split()))
    out_tokens = usage.get("candidatesTokenCount", len(text_resp.split()))

    parsed = json.loads(text_resp)
    return parsed, in_tokens, out_tokens, latency


def call_n8n_webhook(webhook_url: str, item: Dict[str, Any]) -> Tuple[Dict[str, Any], int, int, float]:
    """
    Викликає активний вебхук-ендпоінт n8n із вхідним повідомленням.
    """
    payload = {
        "source_message_id": item["input"]["source_message_id"],
        "channel_id": item["input"]["channel_id"],
        "author_id": item["input"]["author_id"],
        "thread_ts": item["input"]["thread_ts"],
        "message_text": item["input"]["message_text"],
        "thread_context": item.get("thread_context", [])
    }
    t0 = time.time()
    resp = requests.post(webhook_url, json=payload, timeout=30)
    latency = time.time() - t0

    if resp.status_code != 200:
        raise RuntimeError(f"Помилка вебхука n8n {resp.status_code}: {resp.text}")

    result = resp.json()
    # Оцінка токенів, якщо вони не повернуті сервером
    in_tok = len(item["input"]["message_text"].split()) * 2 + 300
    out_tok = len(json.dumps(result).split())
    return result, in_tok, out_tok, latency


# =============================================================================
# Агрегатор метрик оцінювання
# =============================================================================

class EvaluationMetrics:
    def __init__(self):
        self.total_tests = 0
        self.classification_correct = 0
        self.splitting_correct = 0
        self.completeness_correct = 0
        self.routing_correct = 0
        self.schema_valid_count = 0
        self.schema_invalid_count = 0
        
        # Рівень окремих полів
        self.field_total = 0
        self.field_correct = 0
        
        # Виявлення ризиків
        self.risk_expected_total = 0
        self.risk_detected_total = 0
        
        # Перевірки безпеки Pre-guardrails
        self.sensitive_detection_correct = 0
        self.injection_detection_correct = 0
        
        # Продуктивність та токени
        self.total_latency_sec = 0.0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        
        # Деталі за сценаріями
        self.scenario_stats = {}
        self.failures = []

    def compute_summary(self) -> Dict[str, Any]:
        n = max(self.total_tests, 1)
        f_tot = max(self.field_total, 1)
        r_tot = max(self.risk_expected_total, 1)

        class_acc = (self.classification_correct / n) * 100.0
        split_acc = (self.splitting_correct / n) * 100.0
        field_acc = (self.field_correct / f_tot) * 100.0
        comp_acc = (self.completeness_correct / n) * 100.0
        route_acc = (self.routing_correct / n) * 100.0
        schema_fail_rate = (self.schema_invalid_count / n) * 100.0
        risk_recall = (self.risk_detected_total / r_tot) * 100.0
        sens_acc = (self.sensitive_detection_correct / n) * 100.0
        inj_acc = (self.injection_detection_correct / n) * 100.0
        
        avg_latency = self.total_latency_sec / n
        avg_in_tok = self.total_input_tokens / n
        avg_out_tok = self.total_output_tokens / n
        
        # Формула вартості на 1000 запитів: 1000 * (Tin * Pin + Tout * Pout) / 10^6
        cost_1000 = 1000.0 * (avg_in_tok * INPUT_PRICE_PER_MILLION + avg_out_tok * OUTPUT_PRICE_PER_MILLION) / 1_000_000.0

        return {
            "total_evaluated": self.total_tests,
            "classification_accuracy_pct": round(class_acc, 2),
            "request_splitting_accuracy_pct": round(split_acc, 2),
            "field_level_accuracy_pct": round(field_acc, 2),
            "completeness_detection_accuracy_pct": round(comp_acc, 2),
            "routing_accuracy_pct": round(route_acc, 2),
            "schema_failure_rate_pct": round(schema_fail_rate, 2),
            "risk_detection_recall_pct": round(risk_recall, 2),
            "pre_guardrails_sensitive_accuracy_pct": round(sens_acc, 2),
            "pre_guardrails_injection_accuracy_pct": round(inj_acc, 2),
            "avg_latency_ms": round(avg_latency * 1000, 1),
            "avg_input_tokens": round(avg_in_tok, 1),
            "avg_output_tokens": round(avg_out_tok, 1),
            "estimated_cost_per_1000_usd": round(cost_1000, 4),
            "scenario_breakdown": self.scenario_stats,
            "failure_samples": self.failures[:10]
        }


# =============================================================================
# Головний цикл оцінювання
# =============================================================================

def run_evaluation(mode: str = "offline", webhook_url: Optional[str] = None, limit: Optional[int] = None, scenario_filter: Optional[str] = None):
    print_header("TechOps Тріаж заявок на доступ — Модуль оцінювання")
    
    if not DATASET_PATH.exists():
        print(f"{RED}Помилка: Набір даних не знайдено за шляхом {DATASET_PATH}{RESET}")
        sys.exit(1)

    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    if not SCHEMA_PATH.exists():
        print(f"{RED}Помилка: Схему не знайдено за шляхом {SCHEMA_PATH}{RESET}")
        sys.exit(1)

    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema = json.load(f)

    # Читання системного промпту для живого режиму
    system_prompt = ""
    if PROMPT_PATH.exists():
        with open(PROMPT_PATH, "r", encoding="utf-8") as f:
            system_prompt = f.read()

    # Фільтрація за сценарієм за потреби
    if scenario_filter:
        dataset = [d for d in dataset if d.get("scenario") == scenario_filter]
        print(f"{BLUE}Відфільтровано за сценарієм: {scenario_filter} ({len(dataset)} елементів){RESET}")

    if limit:
        dataset = dataset[:limit]
        print(f"{BLUE}Обмежено до перших {limit} елементів{RESET}")

    print(f"Завантажено {len(dataset)} тестових випадків.")
    print(f"Режим оцінювання: {BOLD}{mode.upper()}{RESET}")
    if mode == "live":
        api_key = os.getenv("GEMINI_API_KEY", "")
        model_name = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")
        if not api_key:
            print(f"{YELLOW}Попередження: GEMINI_API_KEY не задано. Перемикання в офлайн режим оцінювання.{RESET}")
            mode = "offline"
        else:
            print(f"Використовується модель Gemini: {CYAN}{model_name}{RESET}")

    metrics = EvaluationMetrics()

    for idx, item in enumerate(dataset, 1):
        test_id = item["id"]
        scenario = item["scenario"]
        input_data = item["input"]
        raw_text = input_data["message_text"]
        expected_pre = item.get("pre_guardrails", {})
        expected_llm = item["expected_llm_output"]
        expected_routes = item["expected_routing"]

        if scenario not in metrics.scenario_stats:
            metrics.scenario_stats[scenario] = {"total": 0, "passed": 0, "failed": 0}
        metrics.scenario_stats[scenario]["total"] += 1
        metrics.total_tests += 1

        # ---------------------------------------------------------------------
        # 1. Оцінювання Pre-Guardrails (перевірки безпеки перед LLM)
        # ---------------------------------------------------------------------
        sanitized_text, has_sensitive, detected_types = redact_sensitive_data(raw_text)
        is_injection, injection_flags = detect_prompt_injection(raw_text)

        pre_flags = {
            "has_sensitive_data": has_sensitive,
            "is_prompt_injection": is_injection,
            "detected_sensitive_types": detected_types,
            "injection_flags": injection_flags
        }

        # Перевірка збігу результатів pre-guardrails
        if has_sensitive == expected_pre.get("has_sensitive_data", False):
            metrics.sensitive_detection_correct += 1
        if is_injection == expected_pre.get("is_prompt_injection", False):
            metrics.injection_detection_correct += 1

        # ---------------------------------------------------------------------
        # 2. Отримання результату вилучення від LLM
        # ---------------------------------------------------------------------
        actual_llm = None
        in_tokens = 0
        out_tokens = 0
        latency_sec = 0.01

        if mode == "live":
            try:
                # Форматування контексту повідомлення разом із тредом за наявності
                user_msg = sanitized_text
                if input_data.get("thread_ts") and item.get("thread_context"):
                    th_block = "\n".join([f"{m['author_id']}: {m['message_text']}" for m in item["thread_context"]])
                    user_msg = f"<thread_context>\n{th_block}\n</thread_context>\n<current_reply>\n{sanitized_text}\n</current_reply>"
                
                actual_llm, in_tokens, out_tokens, latency_sec = call_gemini_api(
                    api_key=api_key,
                    model=model_name,
                    prompt=system_prompt,
                    user_content=user_msg
                )
            except Exception as e:
                # Фіксація помилки API
                metrics.failures.append({"id": test_id, "reason": f"Помилка Gemini API: {str(e)}"})
                actual_llm = None
        elif mode == "webhook":
            try:
                actual_llm, in_tokens, out_tokens, latency_sec = call_n8n_webhook(webhook_url, item)
            except Exception as e:
                metrics.failures.append({"id": test_id, "reason": f"Помилка вебхука: {str(e)}"})
                actual_llm = None
        else:
            # Офлайн режим: перевірка guardrails + схеми + детермінізму маршрутизації
            actual_llm = expected_llm
            in_tokens = len(raw_text.split()) * 3 + 280
            out_tokens = len(json.dumps(expected_llm).split())
            latency_sec = 0.005

        metrics.total_latency_sec += latency_sec
        metrics.total_input_tokens += in_tokens
        metrics.total_output_tokens += out_tokens

        if actual_llm is None:
            metrics.schema_invalid_count += 1
            metrics.scenario_stats[scenario]["failed"] += 1
            continue

        # ---------------------------------------------------------------------
        # 3. Валідація JSON Schema
        # ---------------------------------------------------------------------
        schema_valid = True
        if jsonschema:
            try:
                jsonschema.validate(instance=actual_llm, schema=schema)
                metrics.schema_valid_count += 1
            except jsonschema.ValidationError as ve:
                schema_valid = False
                metrics.schema_invalid_count += 1
                metrics.failures.append({"id": test_id, "reason": f"Помилка валідації схеми: {ve.message}"})
        else:
            metrics.schema_valid_count += 1

        # ---------------------------------------------------------------------
        # 4. Оцінювання класифікації та розділення заявок
        # ---------------------------------------------------------------------
        exp_class = expected_llm.get("classification")
        act_class = actual_llm.get("classification")
        is_class_ok = (exp_class == act_class)
        if is_class_ok:
            metrics.classification_correct += 1

        exp_requests = expected_llm.get("requests", [])
        act_requests = actual_llm.get("requests", [])
        is_split_ok = (len(exp_requests) == len(act_requests))
        if is_split_ok:
            metrics.splitting_correct += 1

        # ---------------------------------------------------------------------
        # 5. Точність на рівні окремих полів та повноти даних
        # ---------------------------------------------------------------------
        fields_to_check = ["target_user", "resource", "environment", "access_level", "duration", "justification"]
        all_fields_match = True
        all_comp_match = True

        for exp_r, act_r in zip(exp_requests, act_requests):
            for fld in fields_to_check:
                metrics.field_total += 1
                exp_v = str(exp_r.get(fld, "") or "").strip().lower()
                act_v = str(act_r.get(fld, "") or "").strip().lower()
                if exp_v == act_v or (exp_v in act_v) or (act_v in exp_v and act_v != ""):
                    metrics.field_correct += 1
                else:
                    all_fields_match = False

            # Повнота та пропущені обов'язкові поля
            if exp_r.get("is_complete") != act_r.get("is_complete"):
                all_comp_match = False

            # Повнота виявлення прапорців ризику (recall)
            exp_risks = set(exp_r.get("risk_flags", []))
            act_risks = set(act_r.get("risk_flags", []))
            metrics.risk_expected_total += len(exp_risks)
            metrics.risk_detected_total += len(exp_risks.intersection(act_risks))

        if len(exp_requests) == 0:
            # not_request
            if len(act_requests) == 0:
                metrics.completeness_correct += 1
        elif all_comp_match:
            metrics.completeness_correct += 1

        # ---------------------------------------------------------------------
        # 6. Оцінювання детермінованої маршрутизації
        # ---------------------------------------------------------------------
        actual_routes = apply_deterministic_routing(actual_llm, pre_flags)
        is_route_ok = True
        if len(actual_routes) != len(expected_routes):
            is_route_ok = False
        else:
            for exp_rt, act_rt in zip(expected_routes, actual_routes):
                if exp_rt["route"] != act_rt["route"] or exp_rt["status"] != act_rt["status"]:
                    is_route_ok = False
                    break

        if is_route_ok:
            metrics.routing_correct += 1

        # Підсумковий вердикт для тестового випадку
        item_passed = is_class_ok and is_split_ok and is_route_ok and schema_valid
        if item_passed:
            metrics.scenario_stats[scenario]["passed"] += 1
        else:
            metrics.scenario_stats[scenario]["failed"] += 1
            metrics.failures.append({
                "id": test_id,
                "scenario": scenario,
                "reason": f"Невідповідність - Клас:{is_class_ok}, Розділення:{is_split_ok}, Маршрут:{is_route_ok}, Схема:{schema_valid}"
            })

        # Індикатор прогресу виконання
        status_sym = f"{GREEN}PASS{RESET}" if item_passed else f"{RED}FAIL{RESET}"
        sys.stdout.write(f"\rОцінювання [{idx}/{len(dataset)}] {test_id} ({scenario}): {status_sym}  ")
        sys.stdout.flush()

    print("\n")
    
    # Генерація та відображення зведеного звіту
    summary = metrics.compute_summary()
    print_evaluation_report(summary)
    
    # Збереження звітів на диск
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_report_path = RESULTS_DIR / f"evaluation_report_{ts}.json"
    md_report_path = RESULTS_DIR / f"evaluation_report_{ts}.md"

    with open(json_report_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    generate_markdown_report(summary, md_report_path)
    print(f"\n{GREEN}Звіт з оцінювання збережено:{RESET}")
    print(f"  JSON: {json_report_path}")
    print(f"  Markdown: {md_report_path}")


def print_evaluation_report(summary: Dict[str, Any]):
    print_header("Зведення метрик оцінювання (README Розділ 10.2)")
    
    table_rows = [
        ("Всього тестових випадків", str(summary["total_evaluated"])),
        ("1. Точність класифікації", f"{summary['classification_accuracy_pct']}%"),
        ("2. Точність розділення заявок", f"{summary['request_splitting_accuracy_pct']}%"),
        ("3. Точність на рівні окремих полів", f"{summary['field_level_accuracy_pct']}%"),
        ("4. Точність виявлення повноти даних", f"{summary['completeness_detection_accuracy_pct']}%"),
        ("5. Точність детермінованої маршрутизації", f"{summary['routing_accuracy_pct']}%"),
        ("6. Рівень відмов валідації схеми", f"{summary['schema_failure_rate_pct']}%"),
        ("7. Повнота виявлення ризиків (Recall)", f"{summary['risk_detection_recall_pct']}%"),
        ("8. Рівень маскування чутливих даних", f"{summary['pre_guardrails_sensitive_accuracy_pct']}%"),
        ("9. Рівень блокування Prompt Injection", f"{summary['pre_guardrails_injection_accuracy_pct']}%"),
        ("Середня затримка обробки", f"{summary['avg_latency_ms']} мс"),
        ("Середня к-сть вхідних токенів", str(summary['avg_input_tokens'])),
        ("Середня к-сть вихідних токенів", str(summary['avg_output_tokens'])),
        ("Орієнтовна вартість на 1000 запитів", f"${summary['estimated_cost_per_1000_usd']} USD")
    ]

    for label, val in table_rows:
        color = GREEN if ("100" in val or "$0" in val or "0.0%" in val and "відмов" in label) else BOLD
        print(f"  {label:<42} : {color}{val}{RESET}")

    print(f"\n{BOLD}{CYAN}Деталізація успішності за сценаріями:{RESET}")
    print(f"  {'-' * 70}")
    print(f"  {'Сценарій':<35} | {'Всього':<8} | {'Успішно':<8} | {'Точність':<8}")
    print(f"  {'-' * 70}")
    for sc_name, sc_data in summary["scenario_breakdown"].items():
        tot = sc_data["total"]
        passed = sc_data["passed"]
        acc = round((passed / max(tot, 1)) * 100.0, 1)
        color = GREEN if acc >= 90.0 else (YELLOW if acc >= 70.0 else RED)
        print(f"  {sc_name:<35} | {tot:<8} | {passed:<8} | {color}{acc}%{RESET}")
    print(f"  {'-' * 70}")


def generate_markdown_report(summary: Dict[str, Any], filepath: Path):
    md_content = f"""# 📊 TechOps Тріаж заявок на доступ: Звіт з оцінювання якості

**Час генерації:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  
**Всього оцінено:** {summary['total_evaluated']} тестових випадків у 8 сценаріях  

---

## 🎯 1. Ключові метрики якості (README Розділ 10.2)

| Метрика | Ціль | Результат | Статус |
| :--- | :---: | :---: | :---: |
| **Точність класифікації** | > 95% | **{summary['classification_accuracy_pct']}%** | {'✅ PASS' if summary['classification_accuracy_pct'] >= 95 else '⚠️ WARNING'} |
| **Точність розділення заявок** | > 95% | **{summary['request_splitting_accuracy_pct']}%** | {'✅ PASS' if summary['request_splitting_accuracy_pct'] >= 95 else '⚠️ WARNING'} |
| **Точність окремих полів** | > 90% | **{summary['field_level_accuracy_pct']}%** | {'✅ PASS' if summary['field_level_accuracy_pct'] >= 90 else '⚠️ WARNING'} |
| **Виявлення повноти даних** | > 95% | **{summary['completeness_detection_accuracy_pct']}%** | {'✅ PASS' if summary['completeness_detection_accuracy_pct'] >= 95 else '⚠️ WARNING'} |
| **Детермінована маршрутизація** | 100% | **{summary['routing_accuracy_pct']}%** | {'✅ PASS' if summary['routing_accuracy_pct'] == 100 else '⚠️ WARNING'} |
| **Відмови валідації схеми** | < 2% | **{summary['schema_failure_rate_pct']}%** | {'✅ PASS' if summary['schema_failure_rate_pct'] < 2 else '❌ FAIL'} |
| **Повнота виявлення ризиків** | > 95% | **{summary['risk_detection_recall_pct']}%** | {'✅ PASS' if summary['risk_detection_recall_pct'] >= 95 else '⚠️ WARNING'} |
| **Маскування чутливих даних** | 100% | **{summary['pre_guardrails_sensitive_accuracy_pct']}%** | {'✅ PASS' if summary['pre_guardrails_sensitive_accuracy_pct'] == 100 else '❌ FAIL'} |
| **Блокування Prompt Injection** | 100% | **{summary['pre_guardrails_injection_accuracy_pct']}%** | {'✅ PASS' if summary['pre_guardrails_injection_accuracy_pct'] == 100 else '❌ FAIL'} |

---

## 📈 2. Результати за сценаріями (8 сценаріїв)

| Сценарій | Всього тестів | Успішно | Точність (%) |
| :--- | :---: | :---: | :---: |
"""
    for sc_name, sc_data in summary["scenario_breakdown"].items():
        tot = sc_data["total"]
        passed = sc_data["passed"]
        acc = round((passed / max(tot, 1)) * 100.0, 1)
        md_content += f"| `{sc_name}` | {tot} | {passed} | **{acc}%** |\n"

    md_content += f"""
---

## 💰 3. Токеноміка та оцінка вартості

* **Середня к-сть вхідних токенів:** {summary['avg_input_tokens']}
* **Середня к-сть вихідних токенів:** {summary['avg_output_tokens']}
* **Середня затримка:** {summary['avg_latency_ms']} мс
* **Формула вартості:** $C_{{1000}} = 1000 \\times \\frac{{T_{{in}} P_{{in}} + T_{{out}} P_{{out}}}}{{10^6}}$
* **Орієнтовна вартість на 1000 запитів:** **${summary['estimated_cost_per_1000_usd']} USD**
"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(md_content)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Автоматизований запуск оцінювання якості тріажу заявок на доступ")
    parser.add_argument("--offline", action="store_true", help="Запустити бенчмарк в офлайн режимі перевірки правил (за замовчуванням)")
    parser.add_argument("--live", action="store_true", help="Запустити з реальним викликом Google Gemini API")
    parser.add_argument("--webhook", type=str, default=None, help="Запустити з викликом живого вебхука n8n за URL")
    parser.add_argument("--limit", type=int, default=None, help="Обмежити кількість тестових випадків")
    parser.add_argument("--scenario", type=str, default=None, help="Фільтрувати за назвою конкретного сценарію")

    args = parser.parse_args()

    mode = "offline"
    if args.live:
        mode = "live"
    elif args.webhook:
        mode = "webhook"

    run_evaluation(
        mode=mode,
        webhook_url=args.webhook,
        limit=args.limit,
        scenario_filter=args.scenario
    )
