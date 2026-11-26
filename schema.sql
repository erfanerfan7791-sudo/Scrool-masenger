
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(24) NOT NULL UNIQUE,
    display_name VARCHAR(50) NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);

-- سازگاری با دیتابیس‌های قبلی
ALTER TABLE users
ADD COLUMN IF NOT EXISTS display_name VARCHAR(50);

UPDATE users
SET display_name = username
WHERE display_name IS NULL;

ALTER TABLE users
ALTER COLUMN display_name SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_users_created_at
ON users(created_at DESC);
