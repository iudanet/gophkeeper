-- +goose Up
-- +goose StatementBegin
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    auth_key_hash TEXT NOT NULL,
    public_salt TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    last_login DATETIME
);

CREATE INDEX idx_users_username ON users(username);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_users_username;
DROP TABLE IF EXISTS users;
-- +goose StatementEnd
