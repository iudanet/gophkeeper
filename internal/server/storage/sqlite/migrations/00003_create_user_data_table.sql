-- +goose Up
-- +goose StatementBegin
CREATE TABLE user_data (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    type TEXT NOT NULL,
    data BLOB NOT NULL,
    metadata TEXT,
    version INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    node_id TEXT NOT NULL,
    deleted INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_user_data_user ON user_data(user_id);
CREATE INDEX idx_user_data_version ON user_data(user_id, version);
CREATE INDEX idx_user_data_timestamp ON user_data(user_id, timestamp);
CREATE INDEX idx_user_data_type ON user_data(user_id, type);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_user_data_type;
DROP INDEX IF EXISTS idx_user_data_timestamp;
DROP INDEX IF EXISTS idx_user_data_version;
DROP INDEX IF EXISTS idx_user_data_user;
DROP TABLE IF EXISTS user_data;
-- +goose StatementEnd
