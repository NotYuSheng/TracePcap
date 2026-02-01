-- Create TracePcap database and user
-- Run this as postgres superuser

-- Create database
CREATE DATABASE tracepcap;

-- Create user
CREATE USER tracepcap_user WITH PASSWORD 'tracepcap_pass';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE tracepcap TO tracepcap_user;

-- Connect to tracepcap database and grant schema privileges
\c tracepcap

-- Grant schema privileges
GRANT ALL ON SCHEMA public TO tracepcap_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO tracepcap_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO tracepcap_user;

-- Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO tracepcap_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO tracepcap_user;
