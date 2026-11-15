-- Write the story when analysis finishes: the upload option, and how far that got.
-- story_status is NULL when no story was asked for at upload; otherwise QUEUED, WRITING,
-- READY or FAILED (story_error says why).
ALTER TABLE files ADD COLUMN generate_story BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE files ADD COLUMN story_status VARCHAR(20);
ALTER TABLE files ADD COLUMN story_error TEXT;

-- An upload can opt out of the retention cleanup: kept until someone deletes it.
ALTER TABLE files ADD COLUMN keep_forever BOOLEAN NOT NULL DEFAULT FALSE;
