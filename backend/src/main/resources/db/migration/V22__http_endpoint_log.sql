-- HTTP endpoint log for web/API-server hosts (web/API equivalent of dns_query_log).
--
-- One aggregated row per (file, server, method, path): how often each endpoint was requested and how
-- it responded. Status codes are bucketed by class so we can flag endpoint enumeration (high 4xx).
--   server_ip           — IP of the host that served the response.
--   method / path       — HTTP request method and request URI (the endpoint).
--   request_count       — responses aggregated into this row.
--   success_count       — 2xx/3xx responses.
--   client_error_count  — 4xx responses (enumeration / auth failures / bad requests).
--   server_error_count  — 5xx responses.
--   top_status          — most-frequent status code (for display).
--   content_type        — representative response Content-Type (e.g. application/json, text/html).
--   server_software     — value of the response Server header (e.g. "nginx/1.18.0"); null if absent.
CREATE TABLE http_endpoint_log (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id            UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    server_ip          VARCHAR(45)   NOT NULL,
    method             VARCHAR(16),
    path               TEXT          NOT NULL,
    request_count      INTEGER NOT NULL DEFAULT 1,
    success_count      INTEGER NOT NULL DEFAULT 0,
    client_error_count INTEGER NOT NULL DEFAULT 0,
    server_error_count INTEGER NOT NULL DEFAULT 0,
    top_status         INTEGER,
    content_type       VARCHAR(255),
    server_software    VARCHAR(255)
);

CREATE INDEX idx_http_endpoint_log_file_server ON http_endpoint_log (file_id, server_ip);
