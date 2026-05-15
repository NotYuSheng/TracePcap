-- Track where each geo result came from so the frontend can show accuracy context.
-- 'ipinfo' = live ipinfo.io API (more accurate), 'mmdb' = offline DB-IP MMDB (approximate)
ALTER TABLE ip_geo_cache ADD COLUMN geo_source VARCHAR(10) NOT NULL DEFAULT 'mmdb';
