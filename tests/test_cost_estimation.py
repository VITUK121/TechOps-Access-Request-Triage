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
Тести розрахунку вартості викликів Google Gemini API (Токеноміка)
===============================================================================
Перевіряють коректність формул та тарифів Google AI Studio згідно з README.md:
  1. Модель gemini-3.5-flash-lite:
     - Вхідний трафік: $0.30 за 1 000 000 токенів
     - Вихідний трафік: $2.50 за 1 000 000 токенів
     - При Tin ≈ 620 токенів та Tout ≈ 230 токенів:
       C_1000 = 1000 * (620 * 0.30 + 230 * 2.50) / 10^6 = $0.761 USD

  2. Модель gemini-3.1-flash-lite:
     - Вхідний трафік: $0.25 за 1 000 000 токенів
     - Вихідний трафік: $1.50 за 1 000 000 токенів
     - При Tin ≈ 620 токенів та Tout ≈ 230 токенів:
       C_1000 = 1000 * (620 * 0.25 + 230 * 1.50) / 10^6 = $0.50 USD
===============================================================================
"""

import pytest


# Тарифи відповідно до оновленого розділу "Токеноміка" в README.md
PRICING_CONFIG = {
    "gemini-3.5-flash-lite": {
        "input_price_per_million": 0.30,
        "output_price_per_million": 2.50,
    },
    "gemini-3.1-flash-lite": {
        "input_price_per_million": 0.25,
        "output_price_per_million": 1.50,
    },
}

# Еталонні середні обсяги токенів з README.md
BENCHMARK_AVG_IN_TOKENS = 620
BENCHMARK_AVG_OUT_TOKENS = 230


def calculate_request_cost(tokens_in: int, tokens_out: int, model: str) -> float:
    """Розраховує вартість одного запиту до моделі Gemini."""
    if model not in PRICING_CONFIG:
        raise ValueError(f"Невідома модель: {model}")
    pricing = PRICING_CONFIG[model]
    p_in = pricing["input_price_per_million"]
    p_out = pricing["output_price_per_million"]
    return (tokens_in * p_in + tokens_out * p_out) / 1_000_000.0


def calculate_cost_per_1000_requests(tokens_in: int, tokens_out: int, model: str) -> float:
    """
    Формула з README.md:
    C_1000 = 1000 * ( (Tin * Pin / 10^6) + (Tout * Pout / 10^6) )
    """
    return 1000.0 * calculate_request_cost(tokens_in, tokens_out, model)


class TestGeminiCostEstimation:
    """Набір тестів для перевірки розрахунку вартості токенів Gemini."""

    def test_gemini_35_flash_lite_single_request_cost(self):
        """Перевірка вартості 1 запиту для дорожчої моделі gemini-3.5-flash-lite."""
        cost = calculate_request_cost(
            tokens_in=BENCHMARK_AVG_IN_TOKENS,
            tokens_out=BENCHMARK_AVG_OUT_TOKENS,
            model="gemini-3.5-flash-lite",
        )
        # 620 * 0.30 / 1e6 = 0.000186 USD
        # 230 * 2.50 / 1e6 = 0.000575 USD
        # Разом: 0.000761 USD
        assert cost == pytest.approx(0.000761, rel=1e-6)

    def test_gemini_35_flash_lite_cost_per_1000_benchmark(self):
        """
        Перевірка розрахунку вартості 1000 запитів для gemini-3.5-flash-lite:
        Tin = 620, Tout = 230 -> $0.761 USD.
        """
        cost_1000 = calculate_cost_per_1000_requests(
            tokens_in=BENCHMARK_AVG_IN_TOKENS,
            tokens_out=BENCHMARK_AVG_OUT_TOKENS,
            model="gemini-3.5-flash-lite",
        )
        assert cost_1000 == pytest.approx(0.761, abs=1e-3)

    def test_gemini_31_flash_lite_single_request_cost(self):
        """Перевірка вартості 1 запиту для дешевшої моделі gemini-3.1-flash-lite."""
        cost = calculate_request_cost(
            tokens_in=BENCHMARK_AVG_IN_TOKENS,
            tokens_out=BENCHMARK_AVG_OUT_TOKENS,
            model="gemini-3.1-flash-lite",
        )
        # 620 * 0.25 / 1e6 = 0.000155 USD
        # 230 * 1.50 / 1e6 = 0.000345 USD
        # Разом: 0.000500 USD
        assert cost == pytest.approx(0.000500, rel=1e-6)

    def test_gemini_31_flash_lite_cost_per_1000_benchmark(self):
        """
        Перевірка розрахунку вартості 1000 запитів для gemini-3.1-flash-lite:
        Tin = 620, Tout = 230 -> $0.50 USD.
        """
        cost_1000 = calculate_cost_per_1000_requests(
            tokens_in=BENCHMARK_AVG_IN_TOKENS,
            tokens_out=BENCHMARK_AVG_OUT_TOKENS,
            model="gemini-3.1-flash-lite",
        )
        assert cost_1000 == pytest.approx(0.500, abs=1e-3)

    def test_cost_ratio_between_models(self):
        """
        Перевірка співвідношення цін: дорожча модель gemini-3.5-flash-lite
        при однакових обсягах токенів коштує приблизно в 1.522 раза дорожче.
        0.761 / 0.500 = 1.522
        """
        cost_35 = calculate_cost_per_1000_requests(
            tokens_in=BENCHMARK_AVG_IN_TOKENS,
            tokens_out=BENCHMARK_AVG_OUT_TOKENS,
            model="gemini-3.5-flash-lite",
        )
        cost_31 = calculate_cost_per_1000_requests(
            tokens_in=BENCHMARK_AVG_IN_TOKENS,
            tokens_out=BENCHMARK_AVG_OUT_TOKENS,
            model="gemini-3.1-flash-lite",
        )
        ratio = cost_35 / cost_31
        assert ratio == pytest.approx(1.522, abs=1e-2)

    def test_zero_tokens_cost(self):
        """Перевірка нульової вартості при відсутності токенів."""
        assert calculate_request_cost(0, 0, "gemini-3.1-flash-lite") == 0.0
        assert calculate_cost_per_1000_requests(0, 0, "gemini-3.5-flash-lite") == 0.0

    def test_unknown_model_raises_error(self):
        """Перевірка викидання помилки при спробі розрахунку для невідомої моделі."""
        with pytest.raises(ValueError):
            calculate_request_cost(100, 100, "gemini-unknown-model")
