-- +goose Up
-- Responses to API v2 requests sent with an Idempotency-Key. A row is
-- written in the same transaction as the change it records, so a retry
-- either sees the stored response or finds no trace of the first attempt.
CREATE TABLE idempotency_keys (
    user_id     bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    key         text NOT NULL CHECK (length(key) BETWEEN 1 AND 255),
    -- SHA-256 over method, path, If-Match and body: a key reused for a
    -- different request is an error, not a replay.
    fingerprint bytea NOT NULL CHECK (length(fingerprint) = 32),
    status      smallint NOT NULL,
    headers     jsonb NOT NULL,
    body        bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    PRIMARY KEY (user_id, key)
);
CREATE INDEX idempotency_keys_expires ON idempotency_keys (expires_at);

-- +goose Down
DROP TABLE idempotency_keys;
