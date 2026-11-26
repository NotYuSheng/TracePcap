-- Where an HTTP download came from (http://host/path?query), as answer keys and incident reports
-- list it. NULL for files carved from raw streams, and for files extracted before this.
ALTER TABLE extracted_files ADD COLUMN source_url VARCHAR(2000);
