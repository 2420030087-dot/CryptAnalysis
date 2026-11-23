-- =========================================================
-- FILESHIELD PROTECTED RESOURCE: PRODUCTION DATABASE DUMP
-- Criticality: CRITICAL
-- Classification: RESTRICTED / CONFIDENTIAL
-- =========================================================

CREATE TABLE IF NOT EXISTS system_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(128) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    mfa_enabled BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO system_users (username, password_hash, role, mfa_enabled) VALUES
('sysadmin', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'admin', 1),
('secops_lead', '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', 'security', 1),
('audit_service', 'b10a8db164e0754105b7a99be72e3fe5ec443ce348a27d6e61280f2d9c34d3b6', 'service', 0);

CREATE TABLE IF NOT EXISTS financial_ledger (
    transaction_id VARCHAR(64) PRIMARY KEY,
    sender_account VARCHAR(32) NOT NULL,
    recipient_account VARCHAR(32) NOT NULL,
    amount_usd DECIMAL(12,2) NOT NULL,
    authorized_by VARCHAR(50) NOT NULL,
    status VARCHAR(20) DEFAULT 'SETTLED'
);

INSERT INTO financial_ledger VALUES
('TX-98234-A', 'CORP-TREASURY-01', 'VENDOR-AWS-CLOUD', 45200.00, 'sysadmin', 'SETTLED'),
('TX-98235-B', 'CORP-TREASURY-01', 'PAYROLL-DISBURSE', 320450.00, 'sysadmin', 'SETTLED');
