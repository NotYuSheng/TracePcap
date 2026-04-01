CREATE TABLE ip_geo_cache (
    ip           VARCHAR(45) PRIMARY KEY,
    country      VARCHAR(100),
    country_code VARCHAR(2),
    asn          VARCHAR(20),
    org          VARCHAR(255),
    looked_up_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
