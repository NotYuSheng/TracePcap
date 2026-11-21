-- Who has signed in, and the TracePcap client roles their last sign-in carried (Settings › Users).
-- Read-only in TracePcap: people, groups and role assignments live in Keycloak. Recorded when the
-- app loads (GET /me) with login on; nothing is recorded with login off, where there are no
-- accounts. Keyed by the token's subject, which survives a username change in Keycloak.
CREATE TABLE signed_in_users (
    subject       VARCHAR(255) PRIMARY KEY,
    username      VARCHAR(255) NOT NULL,
    display_name  VARCHAR(255),
    -- Every client role the token carried on TracePcap's client, including ones TracePcap has no
    -- role for (a typo in Keycloak, or a role deleted here), so Settings can point them out.
    client_roles  TEXT[]       NOT NULL DEFAULT '{}',
    first_seen    TIMESTAMP(3) NOT NULL DEFAULT now(),
    last_seen     TIMESTAMP(3) NOT NULL DEFAULT now()
);
CREATE INDEX signed_in_users_last_seen ON signed_in_users (last_seen DESC);
