-- +goose Up
CREATE TABLE users (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username         text NOT NULL UNIQUE CHECK (length(username) BETWEEN 1 AND 150),
    -- Filled in by the web login (OIDC); identity is (issuer, subject), never email.
    oidc_issuer      text,
    oidc_subject     text,
    email            text,
    active_config_id bigint,
    created_at       timestamptz NOT NULL DEFAULT now(),
    disabled_at      timestamptz,
    UNIQUE (oidc_issuer, oidc_subject),
    CHECK ((oidc_issuer IS NULL) = (oidc_subject IS NULL))
);

CREATE TABLE devices (
    id           uuid PRIMARY KEY,
    user_id      bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    -- SHA-256 of the bearer token; the token itself is never stored.
    token_hash   bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    -- First characters of the token, shown in listings to tell tokens apart.
    token_hint   text NOT NULL,
    scopes       text[] NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    last_ip      text,
    expires_at   timestamptz,
    revoked_at   timestamptz
);
CREATE INDEX devices_user_id ON devices (user_id);

CREATE TABLE configs (
    id                     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id                bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name                   text NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    -- Bumped on every change; exposed as the ETag.
    version                bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    current_revision       integer NOT NULL CHECK (current_revision > 0),
    last_used_with_version text CHECK (length(last_used_with_version) <= 32),
    created_at             timestamptz NOT NULL DEFAULT now(),
    modified_at            timestamptz NOT NULL DEFAULT now(),
    deleted_at             timestamptz,
    UNIQUE (id, user_id)
);
CREATE INDEX configs_user_live ON configs (user_id) WHERE deleted_at IS NULL;
CREATE INDEX configs_deleted ON configs (deleted_at) WHERE deleted_at IS NOT NULL;

-- The active config must belong to the same user.
ALTER TABLE users
    ADD CONSTRAINT users_active_config_fk
    FOREIGN KEY (active_config_id, id) REFERENCES configs (id, user_id)
    ON DELETE SET NULL (active_config_id);

CREATE TABLE config_revisions (
    config_id   bigint NOT NULL,
    user_id     bigint NOT NULL,
    revision    integer NOT NULL CHECK (revision > 0),
    ciphertext  bytea NOT NULL,
    dek_wrapped bytea NOT NULL,
    kek_id      text NOT NULL,
    size        integer NOT NULL CHECK (size >= 0),
    device_id   uuid REFERENCES devices (id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (config_id, revision),
    FOREIGN KEY (config_id, user_id) REFERENCES configs (id, user_id) ON DELETE CASCADE
);
CREATE INDEX config_revisions_kek ON config_revisions (kek_id);

-- Revisions are history: content and ownership never change after insert.
-- Only the wrapped data key may be replaced (key rotation) and device_id may
-- be nulled when a device is deleted.
-- +goose StatementBegin
CREATE FUNCTION config_revisions_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.config_id IS DISTINCT FROM OLD.config_id
       OR NEW.user_id IS DISTINCT FROM OLD.user_id
       OR NEW.revision IS DISTINCT FROM OLD.revision
       OR NEW.ciphertext IS DISTINCT FROM OLD.ciphertext
       OR NEW.size IS DISTINCT FROM OLD.size
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR (NEW.device_id IS DISTINCT FROM OLD.device_id AND NEW.device_id IS NOT NULL) THEN
        RAISE EXCEPTION 'config_revisions rows are immutable';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER config_revisions_immutable
    BEFORE UPDATE ON config_revisions
    FOR EACH ROW EXECUTE FUNCTION config_revisions_immutable();

-- +goose Down
DROP TABLE config_revisions;
DROP FUNCTION config_revisions_immutable();
ALTER TABLE users DROP CONSTRAINT users_active_config_fk;
DROP TABLE configs;
DROP TABLE devices;
DROP TABLE users;
