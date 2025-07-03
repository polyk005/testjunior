-- Создание таблицы пользователей (если ещё не создана)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL
);

-- Создание таблицы refresh токенов
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    user_agent VARCHAR(512) NOT NULL,
    ip VARCHAR(64) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    issued_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Индекс для быстрого поиска активных токенов
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id_active ON refresh_tokens(user_id, is_active); 