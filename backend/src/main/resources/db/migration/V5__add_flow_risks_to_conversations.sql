ALTER TABLE conversations
    ADD COLUMN flow_risks TEXT[] DEFAULT '{}';
