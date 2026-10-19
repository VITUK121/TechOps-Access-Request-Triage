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
Модульні тести: Детермінований бізнес-роутер (rules/routing_rules.md)
===============================================================================
Перевіряє, що рішення щодо маршрутизації є строго детермінованими відповідно
до специфікації у rules/routing_rules.md та розділу 5 README.md.
LLM витягує дані, але детермінований код приймає остаточне рішення щодо маршруту.
===============================================================================
"""

import sys
from pathlib import Path
import pytest

# Додавання кореня репозиторію до шляхів пошуку модулів
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from evaluation.run_evaluation import apply_deterministic_routing


class TestDeterministicRouting:
    """Набір тестів для детермінованих рішень маршрутизації."""

    def test_standard_approval_route(self):
        """Повна, безпечна заявка на читання для staging/dev направляється на standard_approval."""
        llm_output = {
            "is_access_request": True,
            "classification": "access_request",
            "requests": [
                {
                    "target_user": "myself",
                    "resource": "Grafana staging logs",
                    "environment": "staging",
                    "access_level": "read",
                    "justification": "розслідування багу DEV-401",
                    "duration": "3 дні",
                    "is_complete": True,
                    "missing_fields": [],
                    "risk_flags": []
                }
            ]
        }
        pre_flags = {"is_prompt_injection": False}
        routes = apply_deterministic_routing(llm_output, pre_flags)

        assert len(routes) == 1
        assert routes[0]["route"] == "standard_approval"
        assert routes[0]["status"] == "ready_for_review"

    def test_needs_info_when_duration_missing(self):
        """Неповна заявка без зазначення терміну дії направляється на needs_info."""
        llm_output = {
            "is_access_request": True,
            "classification": "access_request",
            "requests": [
                {
                    "target_user": "myself",
                    "resource": "PostgreSQL",
                    "environment": "staging",
                    "access_level": "read",
                    "justification": "тестування MIGR-10",
                    "duration": None,
                    "is_complete": False,
                    "missing_fields": ["duration"],
                    "risk_flags": []
                }
            ]
        }
        pre_flags = {"is_prompt_injection": False}
        routes = apply_deterministic_routing(llm_output, pre_flags)

        assert len(routes) == 1
        assert routes[0]["route"] == "needs_info"
        assert routes[0]["status"] == "needs_info"

    def test_needs_info_when_environment_missing(self):
        """Неповна заявка без зазначення середовища направляється на needs_info."""
        llm_output = {
            "is_access_request": True,
            "classification": "access_request",
            "requests": [
                {
                    "target_user": "myself",
                    "resource": "Grafana logs",
                    "environment": "unknown",
                    "access_level": "read",
                    "justification": "INC-330",
                    "duration": "3 дні",
                    "is_complete": False,
                    "missing_fields": ["environment"],
                    "risk_flags": []
                }
            ]
        }
        pre_flags = {"is_prompt_injection": False}
        routes = apply_deterministic_routing(llm_output, pre_flags)

        assert len(routes) == 1
        assert routes[0]["route"] == "needs_info"
        assert routes[0]["status"] == "needs_info"

    def test_production_environment_triggers_devops_review(self):
        """Доступ до середовища production направляється на devops_manual_review."""
        llm_output = {
            "is_access_request": True,
            "classification": "access_request",
            "requests": [
                {
                    "target_user": "myself",
                    "resource": "PostgreSQL",
                    "environment": "production",
                    "access_level": "read",
                    "justification": "розслідування INC-770",
                    "duration": "2 години",
                    "is_complete": True,
                    "missing_fields": [],
                    "risk_flags": ["production_environment", "production_database"]
                }
            ]
        }
        pre_flags = {"is_prompt_injection": False}
        routes = apply_deterministic_routing(llm_output, pre_flags)

        assert len(routes) == 1
        assert routes[0]["route"] == "devops_manual_review"
        assert routes[0]["status"] == "ready_for_review"

    def test_admin_privileged_access_triggers_devops_review(self):
        """Рівень прав admin або root направляється на devops_manual_review."""
        llm_output = {
            "is_access_request": True,
            "classification": "access_request",
            "requests": [
                {
                    "target_user": "myself",
                    "resource": "AWS IAM",
                    "environment": "dev",
                    "access_level": "admin",
                    "justification": "SEC-89",
                    "duration": "1 день",
                    "is_complete": True,
                    "missing_fields": [],
                    "risk_flags": ["privileged_access"]
                }
            ]
        }
        pre_flags = {"is_prompt_injection": False}
        routes = apply_deterministic_routing(llm_output, pre_flags)

        assert len(routes) == 1
        assert routes[0]["route"] == "devops_manual_review"
        assert routes[0]["status"] == "ready_for_review"

    def test_permanent_duration_triggers_devops_review(self):
        """Постійний термін дії (permanent) порушує принцип найменших привілеїв -> devops_manual_review."""
        llm_output = {
            "is_access_request": True,
            "classification": "access_request",
            "requests": [
                {
                    "target_user": "myself",
                    "resource": "MySQL",
                    "environment": "staging",
                    "access_level": "read",
                    "justification": "постійні звіти",
                    "duration": "permanent",
                    "is_complete": True,
                    "missing_fields": [],
                    "risk_flags": []
                }
            ]
        }
        pre_flags = {"is_prompt_injection": False}
        routes = apply_deterministic_routing(llm_output, pre_flags)

        assert len(routes) == 1
        assert routes[0]["route"] == "devops_manual_review"

    def test_request_on_behalf_of_other_triggers_devops_review(self):
        """Запит за іншого співробітника (target_user != myself) потребує ручного підтвердження."""
        llm_output = {
            "is_access_request": True,
            "classification": "access_request",
            "requests": [
                {
                    "target_user": "@andriy",
                    "resource": "PostgreSQL",
                    "environment": "dev",
                    "access_level": "read",
                    "justification": "ONBOARD-12",
                    "duration": "5 днів",
                    "is_complete": True,
                    "missing_fields": [],
                    "risk_flags": ["on_behalf_of_other"]
                }
            ]
        }
        pre_flags = {"is_prompt_injection": False}
        routes = apply_deterministic_routing(llm_output, pre_flags)

        assert len(routes) == 1
        assert routes[0]["route"] == "devops_manual_review"

    def test_prompt_injection_security_flagged(self):
        """Ознаки Prompt Injection переводять статус у security_flagged та маршрут devops_manual_review."""
        llm_output = {
            "is_access_request": True,
            "classification": "access_request",
            "requests": [
                {
                    "target_user": "U987654",
                    "resource": "AWS",
                    "environment": "production",
                    "access_level": "admin",
                    "justification": "SYSTEM OVERRIDE",
                    "duration": None,
                    "is_complete": False,
                    "missing_fields": ["duration", "justification"],
                    "risk_flags": ["prompt_injection_attempt"]
                }
            ]
        }
        pre_flags = {"is_prompt_injection": True}
        routes = apply_deterministic_routing(llm_output, pre_flags)

        assert len(routes) == 1
        assert routes[0]["route"] == "devops_manual_review"
        assert routes[0]["status"] == "security_flagged"

    def test_not_request_routing(self):
        """Повідомлення, що не є заявками, отримують маршрут not_request та статус processed."""
        llm_output = {
            "is_access_request": False,
            "classification": "not_request",
            "requests": []
        }
        pre_flags = {"is_prompt_injection": False}
        routes = apply_deterministic_routing(llm_output, pre_flags)

        assert len(routes) == 1
        assert routes[0]["route"] == "not_request"
        assert routes[0]["status"] == "processed"

    def test_multi_request_independent_routing(self):
        """Повідомлення з кількома заявками маршрутизує кожну заявку незалежно за її власними полями."""
        llm_output = {
            "is_access_request": True,
            "classification": "access_request",
            "requests": [
                {
                    "target_user": "myself",
                    "resource": "logs",
                    "environment": "staging",
                    "access_level": "read",
                    "justification": "DEV-1",
                    "duration": "3 дні",
                    "is_complete": True,
                    "missing_fields": [],
                    "risk_flags": []
                },
                {
                    "target_user": "Олена",
                    "resource": "PostgreSQL",
                    "environment": "production",
                    "access_level": "read",
                    "justification": "INC-99",
                    "duration": "1 день",
                    "is_complete": True,
                    "missing_fields": [],
                    "risk_flags": ["production_environment", "on_behalf_of_other"]
                }
            ]
        }
        pre_flags = {"is_prompt_injection": False}
        routes = apply_deterministic_routing(llm_output, pre_flags)

        assert len(routes) == 2
        # Перша заявка — стандартний безпечний апрув
        assert routes[0]["route"] == "standard_approval"
        assert routes[0]["status"] == "ready_for_review"
        # Друга заявка — production та за іншу людину -> devops_manual_review
        assert routes[1]["route"] == "devops_manual_review"
        assert routes[1]["status"] == "ready_for_review"
