ALTER TABLE conversations ADD COLUMN tls_issuer TEXT;
ALTER TABLE conversations ADD COLUMN tls_subject TEXT;
ALTER TABLE conversations ADD COLUMN tls_not_before TIMESTAMP;
ALTER TABLE conversations ADD COLUMN tls_not_after TIMESTAMP;
