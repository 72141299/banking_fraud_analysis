-- =============================================================
-- PROJECT: Banking Transaction Fraud Analysis
-- FILE: schema.sql
-- AUTHOR: [Your Name]
-- DESCRIPTION: Creates the banking_fraud_analysis database
--              with normalized tables, indexes, and constraints
-- =============================================================

-- Drop and recreate database
DROP DATABASE IF EXISTS banking_fraud_analysis;
CREATE DATABASE banking_fraud_analysis
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE banking_fraud_analysis;

-- =============================================================
-- TABLE: customers
-- Stores personal information of bank customers
-- =============================================================
CREATE TABLE customers (
    customer_id     INT             NOT NULL AUTO_INCREMENT,
    full_name       VARCHAR(100)    NOT NULL,
    age             TINYINT         NOT NULL CHECK (age BETWEEN 18 AND 90),
    gender          ENUM('Male','Female','Other') NOT NULL,
    city            VARCHAR(60)     NOT NULL,
    state           VARCHAR(60)     NOT NULL,
    phone           VARCHAR(15)     NOT NULL UNIQUE,
    email           VARCHAR(120)    NOT NULL UNIQUE,
    created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (customer_id),
    INDEX idx_customers_city (city),
    INDEX idx_customers_state (state)
) ENGINE=InnoDB COMMENT='Bank customer master data';


-- =============================================================
-- TABLE: accounts
-- Stores bank accounts linked to customers
-- =============================================================
CREATE TABLE accounts (
    account_id      INT             NOT NULL AUTO_INCREMENT,
    customer_id     INT             NOT NULL,
    account_type    ENUM('Savings','Current','Salary','NRI') NOT NULL,
    branch_name     VARCHAR(100)    NOT NULL,
    balance         DECIMAL(15,2)   NOT NULL DEFAULT 0.00,
    status          ENUM('Active','Inactive','Frozen','Closed') NOT NULL DEFAULT 'Active',
    opened_at       DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (account_id),
    CONSTRAINT fk_accounts_customer
        FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
        ON DELETE RESTRICT ON UPDATE CASCADE,
    INDEX idx_accounts_customer (customer_id),
    INDEX idx_accounts_status (status),
    INDEX idx_accounts_type (account_type)
) ENGINE=InnoDB COMMENT='Bank account details';


-- =============================================================
-- TABLE: transactions
-- Core table storing all financial transactions
-- =============================================================
CREATE TABLE transactions (
    txn_id              BIGINT          NOT NULL AUTO_INCREMENT,
    account_id          INT             NOT NULL,
    amount              DECIMAL(15,2)   NOT NULL CHECK (amount > 0),
    txn_type            ENUM('DEBIT','CREDIT')  NOT NULL,
    txn_time            DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    location_city       VARCHAR(60)     NOT NULL,
    device_id           VARCHAR(64)     NOT NULL,
    ip_address          VARCHAR(45)     NOT NULL,
    merchant_category   VARCHAR(60)     NOT NULL,
    status              ENUM('SUCCESS','FAILED','PENDING') NOT NULL DEFAULT 'SUCCESS',

    PRIMARY KEY (txn_id),
    CONSTRAINT fk_txn_account
        FOREIGN KEY (account_id) REFERENCES accounts(account_id)
        ON DELETE RESTRICT ON UPDATE CASCADE,
    INDEX idx_txn_account      (account_id),
    INDEX idx_txn_time         (txn_time),
    INDEX idx_txn_status       (status),
    INDEX idx_txn_amount       (amount),
    INDEX idx_txn_location     (location_city),
    INDEX idx_txn_device       (device_id),
    INDEX idx_txn_account_time (account_id, txn_time)
) ENGINE=InnoDB COMMENT='All financial transactions';


-- =============================================================
-- TABLE: fraud_alerts
-- Stores detected suspicious transactions with risk scoring
-- =============================================================
CREATE TABLE fraud_alerts (
    alert_id        INT             NOT NULL AUTO_INCREMENT,
    txn_id          BIGINT          NOT NULL,
    fraud_type      VARCHAR(100)    NOT NULL,
    risk_score      TINYINT         NOT NULL CHECK (risk_score BETWEEN 1 AND 100),
    alert_time      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved        TINYINT(1)      NOT NULL DEFAULT 0,
    notes           VARCHAR(255)    NULL,

    PRIMARY KEY (alert_id),
    CONSTRAINT fk_alert_txn
        FOREIGN KEY (txn_id) REFERENCES transactions(txn_id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    INDEX idx_alert_txn        (txn_id),
    INDEX idx_alert_time       (alert_time),
    INDEX idx_alert_type       (fraud_type),
    INDEX idx_alert_risk       (risk_score)
) ENGINE=InnoDB COMMENT='Fraud detection alerts';


-- =============================================================
-- VIEW: vw_transaction_summary
-- Quick summary view joining all four tables
-- =============================================================
CREATE VIEW vw_transaction_summary AS
SELECT
    t.txn_id,
    t.txn_time,
    t.amount,
    t.txn_type,
    t.status          AS txn_status,
    t.location_city,
    t.merchant_category,
    t.device_id,
    a.account_id,
    a.account_type,
    a.branch_name,
    a.balance,
    c.customer_id,
    c.full_name,
    c.city            AS customer_city,
    c.state,
    c.age,
    c.gender,
    fa.alert_id,
    fa.fraud_type,
    fa.risk_score
FROM transactions t
JOIN accounts     a  ON t.account_id  = a.account_id
JOIN customers    c  ON a.customer_id = c.customer_id
LEFT JOIN fraud_alerts fa ON t.txn_id = fa.txn_id;


-- =============================================================
-- VIEW: vw_account_risk_profile
-- Account-level risk aggregation for Power BI
-- =============================================================
CREATE VIEW vw_account_risk_profile AS
SELECT
    a.account_id,
    a.account_type,
    a.branch_name,
    a.balance,
    a.status,
    c.full_name,
    c.city,
    c.state,
    COUNT(t.txn_id)                                     AS total_transactions,
    SUM(t.amount)                                       AS total_volume,
    AVG(t.amount)                                       AS avg_amount,
    MAX(t.amount)                                       AS max_amount,
    COUNT(CASE WHEN t.status = 'FAILED' THEN 1 END)     AS failed_txn_count,
    COUNT(DISTINCT t.location_city)                     AS unique_cities,
    COUNT(DISTINCT t.device_id)                         AS unique_devices,
    COUNT(fa.alert_id)                                  AS fraud_alert_count,
    COALESCE(AVG(fa.risk_score), 0)                     AS avg_risk_score
FROM accounts a
JOIN customers   c  ON a.customer_id = c.customer_id
LEFT JOIN transactions  t  ON a.account_id  = t.account_id
LEFT JOIN fraud_alerts  fa ON t.txn_id      = fa.txn_id
GROUP BY
    a.account_id, a.account_type, a.branch_name, a.balance, a.status,
    c.full_name, c.city, c.state;

SELECT 'Schema created successfully.' AS status;
