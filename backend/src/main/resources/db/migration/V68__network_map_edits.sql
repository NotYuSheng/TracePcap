-- The analyst's edits to a capture's network map (#649): which group each moved device was put in,
-- and (later) their own groups, names and notes. One document per capture; the map is still laid
-- out automatically, these only override where things go and what they're called.
CREATE TABLE network_map_edits (
    file_id    UUID         PRIMARY KEY REFERENCES files (id) ON DELETE CASCADE,
    edits      JSONB        NOT NULL,
    updated_at TIMESTAMP    NOT NULL DEFAULT now(),
    updated_by VARCHAR(255)
);
