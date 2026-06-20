-- DNS query log + suspicious-resolver flag (#362).
--
-- `dns_query_log` records, per capture and per DNS-server IP, the domains that server was queried
-- for and how they resolved. Rows are aggregated per (file, server, query name, query type):
--   server_ip      — IP of the DNS server that answered (response packet source).
--   query_name     — domain queried (e.g. "example.com").
--   query_type     — DNS QTYPE name (A, AAAA, MX, PTR, ...).
--   response_code  — DNS RCODE name (NOERROR, NXDOMAIN, SERVFAIL, ...).
--   resolved_ips   — comma-joined answer IPs (A/AAAA records); empty when none.
--   query_count    — number of response packets aggregated into this row.
--   resolvable     — true when the query resolved successfully (NOERROR with at least one answer).
CREATE TABLE dns_query_log (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id       UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    server_ip     VARCHAR(45)  NOT NULL,
    query_name    VARCHAR(255) NOT NULL,
    query_type    VARCHAR(16),
    response_code VARCHAR(16),
    resolved_ips  TEXT,
    query_count   INTEGER NOT NULL DEFAULT 1,
    resolvable    BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_dns_query_log_file_server ON dns_query_log (file_id, server_ip);

-- Flag a DNS server whose share of NXDOMAIN responses exceeds the configured threshold — a signal
-- of DNS tunnelling or a domain-generation algorithm. Set during analysis; see DnsQueryLogExtractor.
ALTER TABLE host_classifications
    ADD COLUMN dns_suspicious BOOLEAN NOT NULL DEFAULT FALSE;
