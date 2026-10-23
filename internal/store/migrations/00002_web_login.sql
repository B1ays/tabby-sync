-- +goose Up
-- An email can be registered by an admin before the first login; the first
-- OIDC login with that verified email is linked to the account.
CREATE UNIQUE INDEX users_email_lower ON users (lower(email)) WHERE email IS NOT NULL;

-- In-progress OIDC logins. The row is found through a random value in a
-- cookie (only its hash is stored) and is consumed exactly once.
CREATE TABLE oidc_flows (
    id_hash       bytea PRIMARY KEY CHECK (length(id_hash) = 32),
    provider      text NOT NULL,
    state         text NOT NULL,
    nonce         text NOT NULL,
    pkce_verifier text NOT NULL,
    return_to     text NOT NULL,
    -- Re-authentication: the ID token must prove a fresh login (auth_time).
    reauth        boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL
);
CREATE INDEX oidc_flows_expires ON oidc_flows (expires_at);

-- Browser sessions. The cookie value is never stored, only its SHA-256;
-- id is the public handle used to list and revoke sessions.
CREATE TABLE sessions (
    id               uuid PRIMARY KEY,
    token_hash       bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    user_id          bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider         text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    authenticated_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at     timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    ip               text,
    user_agent       text CHECK (length(user_agent) <= 256)
);
CREATE INDEX sessions_user_id ON sessions (user_id);
CREATE INDEX sessions_expires ON sessions (expires_at);

-- +goose Down
DROP TABLE sessions;
DROP TABLE oidc_flows;
DROP INDEX users_email_lower;
