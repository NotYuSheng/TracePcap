-- #1235: the server certificate's detail, parsed from the DER Suricata now logs (tls custom fields
-- certificate + chain). NULL when the certificate wasn't seen: TLS 1.3 encrypts it, or Suricata
-- didn't run. Captures analysed before this have NULL until re-analysed.
ALTER TABLE conversations ADD COLUMN tls_sans         TEXT[];
ALTER TABLE conversations ADD COLUMN tls_key_type     VARCHAR(16);
ALTER TABLE conversations ADD COLUMN tls_key_bits     INTEGER;
ALTER TABLE conversations ADD COLUMN tls_sig_alg      VARCHAR(64);
ALTER TABLE conversations ADD COLUMN tls_self_signed  BOOLEAN;
ALTER TABLE conversations ADD COLUMN tls_chain_length INTEGER;
