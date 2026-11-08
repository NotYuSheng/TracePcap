-- Personal preferences (#915 phase 2): theme, network-diagram node labels, conversation-table columns.
-- One row per profile. With login on, the profile is the account's stable subject id, so
-- preferences follow the analyst to any browser. With login off there is no account, and everyone
-- shares the single 'shared' profile, which is by design (#915 decision 1).
CREATE TABLE user_preferences (
    profile_key  VARCHAR(255) PRIMARY KEY,
    preferences  JSONB        NOT NULL DEFAULT '{}'::jsonb,
    updated_at   TIMESTAMP    NOT NULL DEFAULT now()
);
