-- #808/#819: the person's display name (LDAP CN=<name>,CN=Users,...), distinct from the Kerberos
-- principal in logged_in_user. "ccollier" authenticates; "Clark Collier" is who that account is.
-- Populated by the classifier from the LDAP-DN claim; surfaced on the knowledge board's USER entity.
ALTER TABLE host_classifications
    ADD COLUMN logged_in_user_real_name VARCHAR(255);
