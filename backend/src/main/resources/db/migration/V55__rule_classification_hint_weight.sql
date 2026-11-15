-- #926: a rule's device_type is no longer an override but a weighted classification hint. Rules
-- that already had one keep a strong weight (80; other signals add 5 to 35 each), which stays close
-- to the old forced label while being explained, and outvotable by strong contrary evidence.
ALTER TABLE detection_rules ADD COLUMN device_type_weight INTEGER
    CHECK (device_type_weight IS NULL OR device_type_weight BETWEEN 1 AND 100);
UPDATE detection_rules SET device_type_weight = 80 WHERE device_type IS NOT NULL AND device_type <> '';
