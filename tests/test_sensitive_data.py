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
Модульні тести: Виявлення та санітайзинг конфіденційних даних (Pre-Guardrails)
===============================================================================
Перевіряє, що конфіденційні дані (облікові дані AWS, приватні ключі, API-токени,
паролі та рядки підключення) надійно виявляються та маскуються ДО виклику LLM.
===============================================================================
"""

import sys
from pathlib import Path
import pytest

# Додавання кореня репозиторію до шляхів пошуку модулів
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from evaluation.run_evaluation import redact_sensitive_data


class TestSensitiveDataScreening:
    """Тести для виявлення та маскування чутливих даних на основі регулярних виразів."""

    def test_aws_access_key_redaction(self):
        """Перевіряє, що ідентифікатор ключа AWS (AKIA...) надійно маскується."""
        raw = "Мій старий ключ AKIAIOSFODNN7EXAMPLE заблоковано, дайте доступ до dev S3."
        sanitized, has_sensitive, detected = redact_sensitive_data(raw)
        
        assert has_sensitive is True
        assert "aws_key" in detected
        assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
        assert "[REDACTED_AWS_KEY]" in sanitized

    def test_aws_secret_key_redaction(self):
        """Перевіряє, що секретний ключ AWS (aws_secret_access_key=...) надійно маскується."""
        raw = "Секрет aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY скомпрометовано."
        sanitized, has_sensitive, detected = redact_sensitive_data(raw)

        assert has_sensitive is True
        assert "aws_secret" in detected
        assert "wJalrXUtnFEMI" not in sanitized
        assert "[REDACTED_AWS_KEY]" in sanitized

    def test_rsa_private_key_redaction(self):
        """Перевіряє, що багаторядковий блок приватного ключа RSA надійно маскується."""
        raw = (
            "Ось мій ключ:\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Y1m1...super_secret_payload...123456789==\n"
            "-----END RSA PRIVATE KEY-----\n"
            "Відкрийте SSH доступ."
        )
        sanitized, has_sensitive, detected = redact_sensitive_data(raw)

        assert has_sensitive is True
        assert "private_key" in detected
        assert "-----BEGIN RSA PRIVATE KEY-----" not in sanitized
        assert "[REDACTED_PRIVATE_KEY]" in sanitized

    def test_openssh_private_key_redaction(self):
        """Перевіряє, що блок приватного ключа OpenSSH надійно маскується."""
        raw = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA...secret...\n"
            "-----END OPENSSH PRIVATE KEY-----"
        )
        sanitized, has_sensitive, detected = redact_sensitive_data(raw)

        assert has_sensitive is True
        assert "private_key" in detected
        assert "[REDACTED_PRIVATE_KEY]" in sanitized

    def test_github_token_redaction(self):
        """Перевіряє, що персональний токен доступу GitHub (ghp_...) надійно маскується."""
        raw = "Мій токен ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 не має доступу до core-api."
        sanitized, has_sensitive, detected = redact_sensitive_data(raw)

        assert has_sensitive is True
        assert "github_token" in detected
        assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890" not in sanitized
        assert "[REDACTED_TOKEN]" in sanitized

    def test_slack_bot_token_redaction(self):
        """Перевіряє, що токен бота Slack (xoxb-...) надійно маскується."""
        raw = "Скомпрометовано токен бота xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx у чаті."
        sanitized, has_sensitive, detected = redact_sensitive_data(raw)

        assert has_sensitive is True
        assert "slack_token" in detected
        assert "xoxb-123456789012" not in sanitized
        assert "[REDACTED_TOKEN]" in sanitized

    def test_jwt_token_redaction(self):
        """Перевіряє, що Bearer токен JWT надійно маскується."""
        raw = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c повертає 403."
        sanitized, has_sensitive, detected = redact_sensitive_data(raw)

        assert has_sensitive is True
        assert "jwt_token" in detected
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in sanitized
        assert "[REDACTED_TOKEN]" in sanitized

    def test_explicit_password_redaction(self):
        """Перевіряє, що відкриті патерни паролів (password=... або pwd: ...) надійно маскуються."""
        raw = "Пароль password=SuperSecretP@ss123 не підходить до dev PostgreSQL."
        sanitized, has_sensitive, detected = redact_sensitive_data(raw)

        assert has_sensitive is True
        assert "password" in detected
        assert "SuperSecretP@ss123" not in sanitized
        assert "[REDACTED_PASSWORD]" in sanitized

    def test_connection_string_password_redaction(self):
        """Перевіряє, що пароль у рядку підключення URI (postgres://user:pass@host) надійно маскується."""
        raw = "Підключення postgres://db_user:SecretP@ssw0rd99@staging-db.internal:5432/app падає."
        sanitized, has_sensitive, detected = redact_sensitive_data(raw)

        assert has_sensitive is True
        assert "connection_password" in detected
        assert "SecretP@ssw0rd99" not in sanitized
        assert "[REDACTED_PASSWORD]" in sanitized
        assert "staging-db.internal" in sanitized

    def test_clean_message_unmodified(self):
        """Перевіряє, що безпечне повідомлення без секретів проходить без змін із прапорцем has_sensitive_data = False."""
        raw = "Привіт! Надайте мені доступ на читання до логів staging на 3 дні по тасці DEV-101."
        sanitized, has_sensitive, detected = redact_sensitive_data(raw)

        assert has_sensitive is False
        assert len(detected) == 0
        assert sanitized == raw

    def test_multiple_secrets_in_single_message(self):
        """Перевіряє, що коли одне повідомлення містить декілька різних секретів, маскуються всі."""
        raw = "Ключ AKIAIOSFODNN7EXAMPLE та пароль pwd: SecretPass456! для бази."
        sanitized, has_sensitive, detected = redact_sensitive_data(raw)

        assert has_sensitive is True
        assert "aws_key" in detected
        assert "password" in detected
        assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
        assert "SecretPass456!" not in sanitized
        assert "[REDACTED_AWS_KEY]" in sanitized
        assert "[REDACTED_PASSWORD]" in sanitized
