# Suricata rules import folder

Drop a newer Suricata ruleset here to use it without rebuilding the backend image (#600):

- ET Open's `emerging.rules.tar.gz`, from https://rules.emergingthreats.net/open/suricata/
  (download it on any machine with internet, then copy it here), or
- one or more `.rules` files (with `classification.config` / `reference.config` if you have them).

TracePcap checks this folder every minute, test-loads the bundle with `suricata -T`, and uses it
only if Suricata loads it. A broken bundle is reported in the app and the rules built into the image
stay. Delete the bundle to go back to the built-in rules. Nothing here is committed to git.

The folder is mounted read-only into the backend at `/var/lib/tracepcap/suricata-rules`. Set
`SURICATA_RULES_DIR` in `.env` to use a different host folder.
