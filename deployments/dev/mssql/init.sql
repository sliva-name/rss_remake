IF DB_ID('crm') IS NULL CREATE DATABASE crm;
GO
USE master;
GO
IF NOT EXISTS (SELECT 1 FROM sys.server_audits WHERE name = 'dg_audit')
BEGIN
  CREATE SERVER AUDIT dg_audit TO FILE (FILEPATH = '/var/opt/mssql/dg-audit/', MAXSIZE = 50 MB, MAX_ROLLOVER_FILES = 4);
  ALTER SERVER AUDIT dg_audit WITH (STATE = ON);
END
GO
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'dg_scanner')
  CREATE LOGIN dg_scanner WITH PASSWORD = '$(SCANNER_PASSWORD)', CHECK_POLICY = OFF;
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'dg_app')
  CREATE LOGIN dg_app WITH PASSWORD = '$(APP_PASSWORD)', CHECK_POLICY = OFF;
-- Enough for sys.fn_get_audit_file since SQL Server 2022; no CONTROL SERVER needed.
GRANT VIEW SERVER SECURITY AUDIT TO dg_scanner;
GO
USE crm;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'dg_scanner')
BEGIN
  CREATE USER dg_scanner FOR LOGIN dg_scanner;
  ALTER ROLE db_datareader ADD MEMBER dg_scanner;
END
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'dg_app')
BEGIN
  CREATE USER dg_app FOR LOGIN dg_app;
  ALTER ROLE db_owner ADD MEMBER dg_app;
END
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_audit_specifications WHERE name = 'dg_audit_crm')
  CREATE DATABASE AUDIT SPECIFICATION dg_audit_crm FOR SERVER AUDIT dg_audit
    ADD (SELECT, INSERT, UPDATE, DELETE ON DATABASE::crm BY public)
    WITH (STATE = ON);
GO
