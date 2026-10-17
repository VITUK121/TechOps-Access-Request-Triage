-- ============================================================================
-- Обробник заявок TechOps: Схема бази даних
-- Автоматично виконується під час першої ініціалізації контейнера PostgreSQL.
-- ============================================================================

-- Увімкнення розширення UUID для унікальних ідентифікаторів заявок
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- 1. MESSAGES: Вхідні необроблені та очищені події зі Slack
-- ============================================================================
CREATE TABLE IF NOT EXISTS messages (
    id BIGSERIAL PRIMARY KEY,
    source_message_id TEXT NOT NULL UNIQUE,       -- Timestamp або UUID повідомлення зі Slack
    channel_id TEXT NOT NULL,                     -- Канал Slack (наприклад, #techops-access)
    thread_ts TEXT,                               -- Timestamp треду, якщо це відповідь
    author_id TEXT NOT NULL,                      -- Ідентифікатор користувача Slack (наприклад, U123456)
    
    -- Вміст та санітайзинг (Вимоги безпеки)
    raw_message_text TEXT NOT NULL,               -- Початковий текст повідомлення
    sanitized_text TEXT NOT NULL,                 -- Текст після маскування секретів та PII
    has_sensitive_data BOOLEAN DEFAULT FALSE,     -- Ознака: виявлено облікові дані або токени
    is_prompt_injection BOOLEAN DEFAULT FALSE,    -- Ознака: виявлено спробу маніпуляції LLM
    
    -- Високорівнева класифікація повідомлення
    -- 'access_request', 'not_request', 'thread_supplement', 'spam'
    classification TEXT NOT NULL DEFAULT 'access_request',
    
    -- Статус обробки: 'processed', 'processing_error', 'skipped'
    processing_status TEXT NOT NULL DEFAULT 'pending',
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_messages_thread_ts ON messages(thread_ts);
CREATE INDEX IF NOT EXISTS idx_messages_classification ON messages(classification);
CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at);

-- ============================================================================
-- 2. ACCESS_REQUESTS: Структуровані заявки на доступ, витягнуті LLM та роутером
-- (Одне повідомлення може містити 0, 1 або декілька заявок на доступ)
-- ============================================================================
CREATE TABLE IF NOT EXISTS access_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_message_id TEXT NOT NULL REFERENCES messages(source_message_id) ON DELETE CASCADE,
    parent_request_id UUID REFERENCES access_requests(id) ON DELETE SET NULL, -- Зв'язок у разі доповнення в треді
    
    -- Основні параметри доступу
    target_user TEXT,                             -- Користувач, якому потрібен доступ (автор або колега)
    resource TEXT,                                -- База даних, AWS, K8s, GitHub тощо
    environment TEXT,                             -- 'production', 'staging', 'dev', 'sandbox'
    access_level TEXT,                            -- 'read', 'write', 'admin', 'root' тощо
    justification TEXT,                           -- Робоче або інцидентне обґрунтування
    duration TEXT,                                -- '3 days', 'temporary_incident', 'permanent'
    
    -- Статус оцінювання та повноти заявки
    -- 'ready_for_review': усі обов'язкові поля присутні
    -- 'needs_info': неповна заявка, потрібне уточнення від автора
    -- 'security_flagged': містить високий ризик або спробу ін'єкції
    -- 'invalid_format': аварійний статус у разі помилки розбору LLM
    status TEXT NOT NULL DEFAULT 'ready_for_review',
    
    -- Детермінований маршрут (Визначається виключно кодом, НІКОЛИ самою LLM)
    -- 'standard_approval': рутинний безпечний доступ
    -- 'devops_manual_review': production, admin, чутливі ресурси або високий ризик
    -- 'rejected': пряме порушення політик безпеки
    route TEXT NOT NULL DEFAULT 'devops_manual_review',
    
    -- Відстеження повноти та правил безпеки
    is_complete BOOLEAN GENERATED ALWAYS AS (status = 'ready_for_review') STORED,
    missing_fields JSONB NOT NULL DEFAULT '[]'::jsonb,         -- наприклад, ["duration", "justification"]
    clarification_question TEXT,                               -- Одне цільове запитання до автора
    risk_flags JSONB NOT NULL DEFAULT '[]'::jsonb,             -- наприклад, ["privileged_access", "prod_db"]
    
    -- Повний необроблений JSON із результату LLM для аудиту
    extracted_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_access_requests_status ON access_requests(status);
CREATE INDEX IF NOT EXISTS idx_access_requests_route ON access_requests(route);
CREATE INDEX IF NOT EXISTS idx_access_requests_environment ON access_requests(environment);

-- ============================================================================
-- 3. PROCESSING_RUNS: Технічний аудит, валідація схеми та облік витрат Gemini
-- ============================================================================
CREATE TABLE IF NOT EXISTS processing_runs (
    id BIGSERIAL PRIMARY KEY,
    source_message_id TEXT NOT NULL REFERENCES messages(source_message_id) ON DELETE CASCADE,
    
    model_id TEXT NOT NULL,                       
    schema_valid BOOLEAN NOT NULL DEFAULT TRUE,   -- Чи відповідає відповідь LLM схемі JSON Schema?
    error_type TEXT,                              -- 'json_syntax_error', 'schema_mismatch' тощо
    
    -- Продуктивність та токеноміка
    latency_ms INTEGER,                           -- Час виконання запиту в мілісекундах
    input_tokens INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    estimated_cost_usd NUMERIC(12, 8) DEFAULT 0.0,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_processing_runs_schema_valid ON processing_runs(schema_valid);
CREATE INDEX IF NOT EXISTS idx_processing_runs_created_at ON processing_runs(created_at);
