-- #918 slice 3: a device on an address more than one device held has its own identity, keyed
-- ip@<start> (an IPv6 address plus a timestamp is up to 64 characters).
ALTER TABLE host_identities ALTER COLUMN ip TYPE VARCHAR(80);

