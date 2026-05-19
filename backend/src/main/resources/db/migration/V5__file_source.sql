-- Add source column to distinguish analysis uploads from monitor snapshots
ALTER TABLE files ADD COLUMN source VARCHAR(20) NOT NULL DEFAULT 'ANALYSIS';
