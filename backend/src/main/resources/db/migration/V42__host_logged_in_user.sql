-- #809: Windows sign-in identity as a host attribute (person-level, distinct from hostname).
-- Populated by the classifier from Kerberos AS-REQ / LDAP claims; feeds WindowsDomainAuthSignal.
ALTER TABLE host_classifications
    ADD COLUMN logged_in_user        VARCHAR(255),
    ADD COLUMN logged_in_user_source VARCHAR(20);
