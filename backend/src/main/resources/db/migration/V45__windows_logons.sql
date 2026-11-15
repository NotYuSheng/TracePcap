-- Every Windows login seen per host, with when (#812). Until now only one account per host was
-- kept (the first Kerberos login) and every other login was discarded, with no times, so a host
-- used by two people over a capture showed only the first, and nothing said there were others.
CREATE TABLE windows_logons (
    id               BIGSERIAL PRIMARY KEY,
    file_id          UUID         NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    ip               VARCHAR(45)  NOT NULL,
    username         VARCHAR(255) NOT NULL,
    -- kerberos_as_req (signed in) | ldap_dn (looked up in the directory)
    source           VARCHAR(20)  NOT NULL,
    -- LDAP only: the full directory entry, the folder in plain words, USERS|CUSTOM, and the domain
    directory_entry  TEXT,
    folder           VARCHAR(255),
    folder_kind      VARCHAR(10),
    domain           VARCHAR(255),
    first_seen       TIMESTAMP,
    last_seen        TIMESTAMP,
    seen_count       INTEGER      NOT NULL DEFAULT 1
);
CREATE INDEX idx_windows_logons_file_ip ON windows_logons (file_id, ip);

-- How many distinct accounts a host's sign-in label is choosing between. logged_in_user is only
-- set when this is exactly 1; with more, the UI shows "N accounts" and the timeline instead.
ALTER TABLE host_classifications ADD COLUMN logged_in_user_count INTEGER NOT NULL DEFAULT 0;
-- Existing rows: one user was recorded wherever logged_in_user is set.
UPDATE host_classifications SET logged_in_user_count = 1 WHERE logged_in_user IS NOT NULL;
