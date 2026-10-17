-- ============================================================================
-- Обробник заявок TechOps: Звіт з маршрутизації та якості розбору
-- Генерує статистику, передбачену розділами 3 та 4 тестового завдання:
-- Повні, неповні, ризикові заявки, не-заявки + розбивка вартості та метрик.
-- ============================================================================

-- ============================================================================
-- 1. Загальний підсумок (Основні вимоги тестового завдання)
-- ============================================================================
SELECT 
    -- 1. Загальна кількість отриманих вхідних повідомлень
    (SELECT COUNT(*) FROM messages) AS total_messages_received,

    -- 2. Повні заявки (Усі обов'язкові поля заповнені, готові до перевірки)
    (SELECT COUNT(*) FROM access_requests WHERE status = 'ready_for_review') AS complete_requests,

    -- 3. Неповні заявки (Бракує терміну, ресурсу, обґрунтування тощо — сформовано запитання)
    (SELECT COUNT(*) FROM access_requests WHERE status = 'needs_info') AS incomplete_requests,

    -- 4. Ризикові заявки (Привілейований доступ, prod db, root або прапорці ін'єкцій)
    (SELECT COUNT(*) FROM access_requests WHERE jsonb_array_length(risk_flags) > 0) AS risky_requests,

    -- 5. Не-заявки (Спам, подяки, загальні запитання, поза контекстом)
    (SELECT COUNT(*) FROM messages WHERE classification = 'not_request') AS non_requests,

    -- 6. Повідомлення, що містили конфіденційні дані або секрети, які було замасковано
    (SELECT COUNT(*) FROM messages WHERE has_sensitive_data = TRUE) AS messages_with_secrets_redacted,

    -- 7. Повідомлення зі спробами маніпуляції промптом (Prompt Injection)
    (SELECT COUNT(*) FROM messages WHERE is_prompt_injection = TRUE) AS prompt_injections_blocked,

    -- 8. Технічна якість: Відсоток відповідей, що відповідають схемі JSON Schema (%)
    ROUND(
        COALESCE(
            100.0 * COUNT(*) FILTER (WHERE p.schema_valid = TRUE) / NULLIF(COUNT(*), 0),
            100.0
        ), 2
    ) AS schema_validity_percent,

    -- 9. Загальна оціночна вартість запитів до Gemini ($ USD)
    COALESCE(SUM(p.estimated_cost_usd), 0.0) AS total_estimated_cost_usd

FROM processing_runs p;

-- ============================================================================
-- 2. Розподіл за маршрутами призначення
-- ============================================================================
SELECT 
    route,
    status,
    COUNT(*) AS request_count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 1) AS percent_of_total
FROM access_requests
GROUP BY route, status
ORDER BY request_count DESC;

-- ============================================================================
-- 3. Найчастіші пропущені поля в неповних заявках
-- ============================================================================
SELECT 
    missing_field.value::text AS missing_field_name,
    COUNT(*) AS count
FROM access_requests,
     jsonb_array_elements_text(missing_fields) AS missing_field
WHERE status = 'needs_info'
GROUP BY missing_field_name
ORDER BY count DESC;
