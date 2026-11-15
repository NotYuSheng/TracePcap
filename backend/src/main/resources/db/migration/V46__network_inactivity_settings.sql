-- Per-network inactivity rule (#468, #488): how long a device, IP or protocol can go unseen before
-- the drift panels show it as "no longer seen". Until it passes the rule, it shows as "quiet".
--   SNAPSHOTS: gone once missing from the last N captures.
--   DAYS:      gone once not seen for more than N days, counted from the latest capture's start
--              (not today, so reviewing old captures doesn't make everything look gone).
-- Default SNAPSHOTS / 1 = gone as soon as it's missing from the latest capture, which is exactly the
-- behaviour before this setting existed, so existing networks look the same until configured.
ALTER TABLE networks
    ADD COLUMN inactivity_mode      VARCHAR(10) NOT NULL DEFAULT 'SNAPSHOTS',
    ADD COLUMN inactivity_threshold INTEGER     NOT NULL DEFAULT 1;
ALTER TABLE networks
    ADD CONSTRAINT chk_networks_inactivity_mode CHECK (inactivity_mode IN ('SNAPSHOTS', 'DAYS')),
    ADD CONSTRAINT chk_networks_inactivity_threshold CHECK (inactivity_threshold >= 1);
