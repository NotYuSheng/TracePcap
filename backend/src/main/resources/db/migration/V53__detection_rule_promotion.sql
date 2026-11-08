-- Promote (#925 phase 3): a capture rule can be copied up to a global rule. The copy remembers
-- where it came from, which is what lets the two share a name (both may label the same capture,
-- and the labels are de-duplicated).
ALTER TABLE detection_rules
    ADD COLUMN promoted_from UUID REFERENCES detection_rules (id) ON DELETE SET NULL;
CREATE INDEX idx_detection_rules_file ON detection_rules (file_id) WHERE file_id IS NOT NULL;
