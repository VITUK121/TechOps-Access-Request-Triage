# -*- coding: utf-8 -*-
"""
===============================================================================
Модульні тести: Валідація JSON Schema (schemas/access_request.schema.json)
===============================================================================
Перевіряє, що вихідні структури строго відповідають формальному контракту
JSON Schema. Контролює обмеження enum, обов'язкові поля та цілісність типів.
===============================================================================
"""

import json
from pathlib import Path
import pytest
import jsonschema

BASE_DIR = Path(__file__).resolve().parent.parent
SCHEMA_PATH = BASE_DIR / "schemas" / "access_request.schema.json"
DATASET_PATH = BASE_DIR / "evaluation" / "golden_dataset.json"


@pytest.fixture(scope="module")
def access_request_schema():
    """Завантажує офіційну схему JSON Schema."""
    assert SCHEMA_PATH.exists(), f"Файл схеми не знайдено за шляхом {SCHEMA_PATH}"
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


class TestJsonSchemaValidation:
    """Набір тестів для контракту JSON Schema заявки на доступ."""

    def test_valid_access_request_payload(self, access_request_schema):
        """Стандартна валідна заявка успішно проходить валідацію."""
        valid_payload = {
            "is_access_request": True,
            "classification": "access_request",
            "thread_context_applied": False,
            "summary": "Запит доступу на читання до staging logs",
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
                    "clarification_question": None,
                    "risk_flags": []
                }
            ]
        }
        jsonschema.validate(instance=valid_payload, schema=access_request_schema)

    def test_valid_not_request_payload(self, access_request_schema):
        """Валідний об'єкт not_request з порожнім масивом requests проходить валідацію."""
        payload = {
            "is_access_request": False,
            "classification": "not_request",
            "thread_context_applied": False,
            "summary": "Повідомлення подяки, не містить прохання про доступ",
            "requests": []
        }
        jsonschema.validate(instance=payload, schema=access_request_schema)

    def test_missing_top_level_required_fields_fails(self, access_request_schema):
        """Відсутність обов'язкових полів кореневого рівня (наприклад classification) викликає ValidationError."""
        invalid_payload = {
            "is_access_request": True,
            # classification відсутній
            "requests": []
        }
        with pytest.raises(jsonschema.ValidationError) as exc_info:
            jsonschema.validate(instance=invalid_payload, schema=access_request_schema)
        assert "'classification' is a required property" in str(exc_info.value)

    def test_invalid_classification_enum_fails(self, access_request_schema):
        """Значення classification поза списком enum викликає ValidationError."""
        invalid_payload = {
            "is_access_request": True,
            "classification": "invalid_classification_value",
            "requests": []
        }
        with pytest.raises(jsonschema.ValidationError) as exc_info:
            jsonschema.validate(instance=invalid_payload, schema=access_request_schema)
        assert "is not one of" in str(exc_info.value)

    def test_missing_request_item_required_fields_fails(self, access_request_schema):
        """Відсутність обов'язкових полів елемента заявки (наприклад target_user) викликає ValidationError."""
        invalid_payload = {
            "is_access_request": True,
            "classification": "access_request",
            "requests": [
                {
                    # target_user відсутній
                    "resource": "PostgreSQL",
                    "environment": "staging",
                    "access_level": "read",
                    "is_complete": False,
                    "missing_fields": ["duration"],
                    "risk_flags": []
                }
            ]
        }
        with pytest.raises(jsonschema.ValidationError) as exc_info:
            jsonschema.validate(instance=invalid_payload, schema=access_request_schema)
        assert "'target_user' is a required property" in str(exc_info.value)

    def test_invalid_environment_enum_fails(self, access_request_schema):
        """Значення середовища environment поза списком enum викликає ValidationError."""
        invalid_payload = {
            "is_access_request": True,
            "classification": "access_request",
            "requests": [
                {
                    "target_user": "myself",
                    "resource": "PostgreSQL",
                    "environment": "qa_local_custom",  # Невалідний enum
                    "access_level": "read",
                    "is_complete": True,
                    "missing_fields": [],
                    "risk_flags": []
                }
            ]
        }
        with pytest.raises(jsonschema.ValidationError) as exc_info:
            jsonschema.validate(instance=invalid_payload, schema=access_request_schema)
        assert "is not one of" in str(exc_info.value)

    def test_invalid_access_level_enum_fails(self, access_request_schema):
        """Значення access_level поза списком enum викликає ValidationError."""
        invalid_payload = {
            "is_access_request": True,
            "classification": "access_request",
            "requests": [
                {
                    "target_user": "myself",
                    "resource": "PostgreSQL",
                    "environment": "dev",
                    "access_level": "super_god_mode",  # Невалідний enum
                    "is_complete": True,
                    "missing_fields": [],
                    "risk_flags": []
                }
            ]
        }
        with pytest.raises(jsonschema.ValidationError) as exc_info:
            jsonschema.validate(instance=invalid_payload, schema=access_request_schema)
        assert "is not one of" in str(exc_info.value)

    def test_unexpected_additional_properties_fails(self, access_request_schema):
        """Додаткові непередбачені поля на будь-якому рівні викликають ValidationError."""
        invalid_payload = {
            "is_access_request": True,
            "classification": "access_request",
            "requests": [],
            "injected_extra_field": "hack"
        }
        with pytest.raises(jsonschema.ValidationError) as exc_info:
            jsonschema.validate(instance=invalid_payload, schema=access_request_schema)
        assert "Additional properties are not allowed" in str(exc_info.value)

    def test_all_golden_dataset_examples_strictly_conform(self, access_request_schema):
        """Перевіряє, що всі 80 прикладів у golden_dataset.json відповідають схемі."""
        assert DATASET_PATH.exists(), f"Датасет не знайдено за шляхом {DATASET_PATH}"
        with open(DATASET_PATH, "r", encoding="utf-8") as f:
            dataset = json.load(f)

        assert len(dataset) >= 80
        for item in dataset:
            llm_output = item["expected_llm_output"]
            jsonschema.validate(instance=llm_output, schema=access_request_schema)
