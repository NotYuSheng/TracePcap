-- Create Lanturn database and user
-- Run this as postgres superuser

-- Create database
CREATE DATABASE lanturn;

-- Create user
CREATE USER lanturn_user WITH PASSWORD 'lanturn_pass';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE lanturn TO lanturn_user;

-- Connect to lanturn database and grant schema privileges
\c lanturn

-- Grant schema privileges
GRANT ALL ON SCHEMA public TO lanturn_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO lanturn_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO lanturn_user;

-- Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO lanturn_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO lanturn_user;
