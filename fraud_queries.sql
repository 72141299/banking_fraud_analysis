-- =============================================================
-- PROJECT: Banking Transaction Fraud Analysis
-- FILE: fraud_queries.sql
-- DESCRIPTION: Complete SQL analytics — Basic KPIs, Fraud
--              Detection, Window Functions, CTEs, Auto-Alerts
-- =============================================================

USE banking_fraud_analysis;

-- =============================================================
-- SECTION 1: BASIC ANALYTICS
-- =============================================================

-- ── Q1. Total Customers ───────────────────────────────────────
SELECT COUNT(*) AS total_customers
FROM customers;


-- ── Q2. Total Accounts by Type ────────────────────────────────
SELECT
    account_type,
    COUNT(*)          AS total_accounts,
    SUM(balance)      AS total_balance,
    AVG(balance)      AS avg_balance
FROM accounts
GROUP BY account_type
ORDER BY total_accounts DESC;


-- ── Q3. Total Transactions & Volume ──────────────────────────
SELECT
    COUNT(*)          AS total_transactions,
    SUM(amount)       AS total_volume,
    AVG(amount)       AS avg_transaction_value,
    MAX(amount)       AS max_transaction,
    MIN(amount)       AS min_transaction
FROM transactions;


-- ── Q4. Total Transaction Value by Type ───────────────────────
SELECT
    txn_type,
    status,
    COUNT(*)          AS txn_count,
    SUM(amount)       AS total_amount,
    AVG(amount)       AS avg_amount
FROM transactions
GROUP BY txn_type, status
ORDER BY txn_type, status;


-- ── Q5. Top 10 Customers by Transaction Volume ────────────────
SELECT
    c.customer_id,
    c.full_name,
    c.city,
    c.state,
    COUNT(t.txn_id)   AS total_transactions,
    SUM(t.amount)     AS total_volume,
    AVG(t.amount)     AS avg_amount
FROM customers c
JOIN accounts    a ON c.customer_id = a.customer_id
JOIN transactions t ON a.account_id  = t.account_id
GROUP BY c.customer_id, c.full_name, c.city, c.state
ORDER BY total_volume DESC
LIMIT 10;


-- ── Q6. Monthly Transaction Trend ────────────────────────────
SELECT
    DATE_FORMAT(txn_time, '%Y-%m')          AS txn_month,
    COUNT(*)                                AS total_txns,
    SUM(amount)                             AS total_volume,
    SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) AS success_count,
    SUM(CASE WHEN status = 'FAILED'  THEN 1 ELSE 0 END) AS failed_count,
    ROUND(AVG(amount), 2)                   AS avg_amount
FROM transactions
GROUP BY txn_month
ORDER BY txn_month;


-- ── Q7. City-wise Transaction Summary ─────────────────────────
SELECT
    location_city,
    COUNT(*)                                AS txn_count,
    SUM(amount)                             AS total_volume,
    AVG(amount)                             AS avg_amount,
    COUNT(DISTINCT account_id)              AS unique_accounts
FROM transactions
GROUP BY location_city
ORDER BY total_volume DESC
LIMIT 20;


-- ── Q8. Merchant Category Performance ────────────────────────
SELECT
    merchant_category,
    COUNT(*)                                AS txn_count,
    SUM(amount)                             AS total_volume,
    AVG(amount)                             AS avg_amount,
    SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) AS failed_count
FROM transactions
GROUP BY merchant_category
ORDER BY total_volume DESC;


-- =============================================================
-- SECTION 2: FRAUD DETECTION QUERIES
-- =============================================================

-- ── FD1. High-Value Transactions Above ₹50,000 ───────────────
SELECT
    t.txn_id,
    t.account_id,
    c.full_name,
    c.city              AS customer_city,
    t.amount,
    t.txn_type,
    t.txn_time,
    t.location_city,
    t.merchant_category,
    t.device_id,
    t.status,
    CASE
        WHEN t.amount > 200000 THEN 'CRITICAL'
        WHEN t.amount > 100000 THEN 'HIGH'
        ELSE 'MEDIUM'
    END                 AS risk_level
FROM transactions t
JOIN accounts  a ON t.account_id  = a.account_id
JOIN customers c ON a.customer_id = c.customer_id
WHERE t.amount > 50000
  AND t.txn_type = 'DEBIT'
ORDER BY t.amount DESC;


-- ── FD2. Rapid Burst: 3+ Transactions within 10 Minutes ──────
WITH burst_txns AS (
    SELECT
        t1.txn_id,
        t1.account_id,
        t1.txn_time,
        t1.amount,
        t1.status,
        COUNT(t2.txn_id) AS burst_count
    FROM transactions t1
    JOIN transactions t2
        ON  t1.account_id = t2.account_id
        AND t2.txn_time   BETWEEN t1.txn_time
                              AND DATE_ADD(t1.txn_time, INTERVAL 10 MINUTE)
        AND t1.txn_id    <> t2.txn_id
    GROUP BY t1.txn_id, t1.account_id, t1.txn_time, t1.amount, t1.status
    HAVING burst_count >= 2    -- means 3+ total including self
)
SELECT
    b.txn_id,
    b.account_id,
    c.full_name,
    b.txn_time,
    b.amount,
    b.burst_count + 1 AS transactions_in_window,
    b.status
FROM burst_txns b
JOIN accounts  a ON b.account_id  = a.account_id
JOIN customers c ON a.customer_id = c.customer_id
ORDER BY b.burst_count DESC, b.txn_time;


-- ── FD3. Geo-Velocity: Same Account, Different Cities < 2 Hrs ─
WITH city_changes AS (
    SELECT
        t.account_id,
        t.txn_id,
        t.txn_time,
        t.location_city,
        t.amount,
        LAG(t.location_city) OVER (PARTITION BY t.account_id ORDER BY t.txn_time) AS prev_city,
        LAG(t.txn_time)      OVER (PARTITION BY t.account_id ORDER BY t.txn_time) AS prev_time
    FROM transactions t
)
SELECT
    cc.account_id,
    c.full_name,
    cc.txn_id,
    cc.prev_city        AS city_from,
    cc.location_city    AS city_to,
    cc.prev_time        AS time_from,
    cc.txn_time         AS time_to,
    TIMESTAMPDIFF(MINUTE, cc.prev_time, cc.txn_time) AS minutes_apart,
    cc.amount
FROM city_changes cc
JOIN accounts  a ON cc.account_id  = a.account_id
JOIN customers c ON a.customer_id  = c.customer_id
WHERE cc.prev_city IS NOT NULL
  AND cc.prev_city <> cc.location_city
  AND TIMESTAMPDIFF(MINUTE, cc.prev_time, cc.txn_time) < 120
ORDER BY minutes_apart ASC;


-- ── FD4. Night-Time Transactions (1 AM – 4 AM) ───────────────
SELECT
    t.txn_id,
    t.account_id,
    c.full_name,
    t.amount,
    t.txn_type,
    TIME(t.txn_time)    AS txn_time_only,
    DATE(t.txn_time)    AS txn_date,
    t.location_city,
    t.merchant_category,
    t.status,
    CASE
        WHEN t.amount > 100000 THEN 'CRITICAL'
        WHEN t.amount > 50000  THEN 'HIGH'
        WHEN t.amount > 10000  THEN 'MEDIUM'
        ELSE 'LOW'
    END AS risk_level
FROM transactions t
JOIN accounts  a ON t.account_id  = a.account_id
JOIN customers c ON a.customer_id = c.customer_id
WHERE HOUR(t.txn_time) BETWEEN 1 AND 3
  AND t.txn_type = 'DEBIT'
ORDER BY t.amount DESC;


-- ── FD5. Repeated Failed Attempts (3+ FAILEDs, same account) ──
SELECT
    t.account_id,
    c.full_name,
    COUNT(*)            AS failed_attempts,
    MAX(t.amount)       AS max_attempted_amount,
    MIN(t.txn_time)     AS first_attempt,
    MAX(t.txn_time)     AS last_attempt,
    TIMESTAMPDIFF(MINUTE,
        MIN(t.txn_time),
        MAX(t.txn_time))AS time_span_minutes,
    GROUP_CONCAT(DISTINCT t.device_id ORDER BY t.txn_time SEPARATOR ' | ')
                        AS devices_used
FROM transactions t
JOIN accounts  a ON t.account_id  = a.account_id
JOIN customers c ON a.customer_id = c.customer_id
WHERE t.status = 'FAILED'
GROUP BY t.account_id, c.full_name
HAVING failed_attempts >= 3
ORDER BY failed_attempts DESC;


-- ── FD6. Amount Much Higher than Account Average (Z-Score) ────
WITH account_stats AS (
    SELECT
        account_id,
        AVG(amount)         AS avg_amt,
        STDDEV(amount)      AS std_amt
    FROM transactions
    GROUP BY account_id
    HAVING COUNT(*) >= 5    -- need enough data for stats
),
anomalous AS (
    SELECT
        t.txn_id,
        t.account_id,
        t.amount,
        t.txn_time,
        t.merchant_category,
        t.status,
        s.avg_amt,
        s.std_amt,
        ROUND((t.amount - s.avg_amt) / NULLIF(s.std_amt, 0), 2) AS z_score
    FROM transactions t
    JOIN account_stats s ON t.account_id = s.account_id
)
SELECT
    a.txn_id,
    a.account_id,
    c.full_name,
    a.amount,
    ROUND(a.avg_amt, 2)     AS account_avg,
    ROUND(a.std_amt, 2)     AS account_std,
    a.z_score,
    a.txn_time,
    a.merchant_category,
    a.status,
    CASE
        WHEN a.z_score > 4 THEN 'CRITICAL'
        WHEN a.z_score > 3 THEN 'HIGH'
        WHEN a.z_score > 2 THEN 'MEDIUM'
    END AS anomaly_level
FROM anomalous a
JOIN accounts  ac ON a.account_id  = ac.account_id
JOIN customers c  ON ac.customer_id = c.customer_id
WHERE a.z_score > 2
ORDER BY a.z_score DESC;


-- ── FD7. New/Rare Device + High Transaction ───────────────────
WITH device_frequency AS (
    SELECT
        account_id,
        device_id,
        COUNT(*) AS times_used
    FROM transactions
    GROUP BY account_id, device_id
)
SELECT
    t.txn_id,
    t.account_id,
    c.full_name,
    t.device_id,
    df.times_used   AS device_usage_count,
    t.amount,
    t.txn_time,
    t.location_city,
    t.merchant_category,
    t.status
FROM transactions t
JOIN device_frequency df
    ON  t.account_id = df.account_id
    AND t.device_id  = df.device_id
JOIN accounts  a ON t.account_id  = a.account_id
JOIN customers c ON a.customer_id = c.customer_id
WHERE df.times_used = 1        -- device seen only once
  AND t.amount > 30000
  AND t.txn_type = 'DEBIT'
ORDER BY t.amount DESC;


-- ── FD8. Dormant Account Suddenly Active ─────────────────────
WITH last_activity AS (
    SELECT
        account_id,
        MAX(txn_time) AS last_txn_date
    FROM transactions
    WHERE txn_time < DATE_SUB(NOW(), INTERVAL 6 MONTH)
    GROUP BY account_id
),
recent_activity AS (
    SELECT
        account_id,
        COUNT(*)    AS recent_txns,
        SUM(amount) AS recent_volume
    FROM transactions
    WHERE txn_time >= DATE_SUB(NOW(), INTERVAL 3 MONTH)
    GROUP BY account_id
)
SELECT
    la.account_id,
    c.full_name,
    a.account_type,
    a.status        AS account_status,
    la.last_txn_date,
    DATEDIFF(NOW(), la.last_txn_date) AS dormant_days,
    ra.recent_txns,
    ra.recent_volume
FROM last_activity la
JOIN recent_activity ra  ON la.account_id  = ra.account_id
JOIN accounts         a  ON la.account_id  = a.account_id
JOIN customers        c  ON a.customer_id  = c.customer_id
WHERE DATEDIFF(NOW(), la.last_txn_date) > 180
ORDER BY dormant_days DESC;


-- ── FD9. Top 20 Risky Accounts (Composite Risk Score) ─────────
WITH risk_components AS (
    SELECT
        t.account_id,
        -- High value score
        SUM(CASE WHEN t.amount > 50000 THEN 10 ELSE 0 END)          AS high_value_pts,
        -- Night activity score
        SUM(CASE WHEN HOUR(t.txn_time) BETWEEN 1 AND 3 THEN 8 ELSE 0 END) AS night_pts,
        -- Failed attempts score
        SUM(CASE WHEN t.status = 'FAILED' THEN 5 ELSE 0 END)        AS failed_pts,
        -- Multi-city score
        COUNT(DISTINCT t.location_city) * 3                          AS city_pts,
        -- Multi-device score
        COUNT(DISTINCT t.device_id) * 4                              AS device_pts,
        -- Fraud merchant score
        SUM(CASE WHEN t.merchant_category IN
            ('Crypto Exchange','International','Gaming','Online Transfer')
            THEN 7 ELSE 0 END)                                       AS merchant_pts,
        -- Raw counts
        COUNT(*)                                                     AS total_txns,
        SUM(t.amount)                                                AS total_volume,
        COUNT(CASE WHEN t.status = 'FAILED' THEN 1 END)             AS failed_count
    FROM transactions t
    GROUP BY t.account_id
)
SELECT
    rc.account_id,
    c.full_name,
    a.account_type,
    a.branch_name,
    a.status        AS account_status,
    rc.total_txns,
    ROUND(rc.total_volume, 2) AS total_volume,
    rc.failed_count,
    LEAST(
        rc.high_value_pts + rc.night_pts + rc.failed_pts +
        rc.city_pts + rc.device_pts + rc.merchant_pts,
        100
    )               AS composite_risk_score,
    CASE
        WHEN (rc.high_value_pts + rc.night_pts + rc.failed_pts +
              rc.city_pts + rc.device_pts + rc.merchant_pts) > 70 THEN 'CRITICAL'
        WHEN (rc.high_value_pts + rc.night_pts + rc.failed_pts +
              rc.city_pts + rc.device_pts + rc.merchant_pts) > 40 THEN 'HIGH'
        WHEN (rc.high_value_pts + rc.night_pts + rc.failed_pts +
              rc.city_pts + rc.device_pts + rc.merchant_pts) > 20 THEN 'MEDIUM'
        ELSE 'LOW'
    END             AS risk_category
FROM risk_components rc
JOIN accounts  a ON rc.account_id  = a.account_id
JOIN customers c ON a.customer_id  = c.customer_id
ORDER BY composite_risk_score DESC
LIMIT 20;


-- ── FD10. Daily Fraud Trend ───────────────────────────────────
SELECT
    DATE(fa.alert_time)                     AS alert_date,
    COUNT(fa.alert_id)                      AS total_alerts,
    COUNT(DISTINCT fa.fraud_type)           AS unique_fraud_types,
    AVG(fa.risk_score)                      AS avg_risk_score,
    MAX(fa.risk_score)                      AS max_risk_score,
    SUM(t.amount)                           AS flagged_amount
FROM fraud_alerts fa
JOIN transactions t ON fa.txn_id = t.txn_id
GROUP BY alert_date
ORDER BY alert_date;


-- =============================================================
-- SECTION 3: ADVANCED WINDOW FUNCTION QUERIES
-- =============================================================

-- ── WF1. Running Total per Account ───────────────────────────
SELECT
    t.account_id,
    c.full_name,
    t.txn_id,
    t.txn_time,
    t.amount,
    t.txn_type,
    SUM(CASE WHEN t.txn_type = 'CREDIT' THEN  t.amount
             WHEN t.txn_type = 'DEBIT'  THEN -t.amount END)
        OVER (PARTITION BY t.account_id ORDER BY t.txn_time
              ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)
                            AS running_balance,
    ROW_NUMBER() OVER (PARTITION BY t.account_id ORDER BY t.txn_time) AS txn_sequence,
    RANK() OVER (PARTITION BY t.account_id ORDER BY t.amount DESC)    AS amount_rank
FROM transactions t
JOIN accounts  a ON t.account_id  = a.account_id
JOIN customers c ON a.customer_id = c.customer_id
ORDER BY t.account_id, t.txn_time
LIMIT 500;


-- ── WF2. Month-over-Month Transaction Growth ─────────────────
WITH monthly AS (
    SELECT
        DATE_FORMAT(txn_time, '%Y-%m') AS txn_month,
        COUNT(*)                        AS txn_count,
        SUM(amount)                     AS total_volume
    FROM transactions
    GROUP BY txn_month
)
SELECT
    txn_month,
    txn_count,
    ROUND(total_volume, 2)              AS total_volume,
    LAG(txn_count)  OVER (ORDER BY txn_month)  AS prev_month_count,
    LAG(total_volume) OVER (ORDER BY txn_month) AS prev_month_volume,
    ROUND(
        (txn_count - LAG(txn_count) OVER (ORDER BY txn_month))
        / NULLIF(LAG(txn_count) OVER (ORDER BY txn_month), 0) * 100,
    2)                                  AS count_growth_pct,
    ROUND(
        (total_volume - LAG(total_volume) OVER (ORDER BY txn_month))
        / NULLIF(LAG(total_volume) OVER (ORDER BY txn_month), 0) * 100,
    2)                                  AS volume_growth_pct
FROM monthly
ORDER BY txn_month;


-- ── WF3. 7-Day Moving Average of Fraud Alerts ────────────────
WITH daily_alerts AS (
    SELECT
        DATE(alert_time)    AS alert_date,
        COUNT(*)            AS daily_count,
        AVG(risk_score)     AS avg_risk
    FROM fraud_alerts
    GROUP BY alert_date
)
SELECT
    alert_date,
    daily_count,
    ROUND(avg_risk, 1)  AS avg_risk_score,
    ROUND(AVG(daily_count) OVER (
        ORDER BY alert_date
        ROWS BETWEEN 6 PRECEDING AND CURRENT ROW
    ), 2)               AS rolling_7d_avg,
    SUM(daily_count) OVER (ORDER BY alert_date) AS cumulative_alerts
FROM daily_alerts
ORDER BY alert_date;


-- ── WF4. Percentile Ranking of Transactions by Amount ─────────
SELECT
    txn_id,
    account_id,
    amount,
    txn_type,
    merchant_category,
    ROUND(PERCENT_RANK() OVER (ORDER BY amount) * 100, 1) AS percentile_rank,
    NTILE(4) OVER (ORDER BY amount)                        AS quartile,
    CASE NTILE(4) OVER (ORDER BY amount)
        WHEN 4 THEN 'Top 25% - High Value'
        WHEN 3 THEN 'Upper Mid'
        WHEN 2 THEN 'Lower Mid'
        ELSE 'Bottom 25%'
    END                                                    AS value_bucket
FROM transactions
WHERE txn_type = 'DEBIT'
ORDER BY amount DESC;


-- =============================================================
-- SECTION 4: AUTO-INSERT FRAUD ALERTS (Stored Procedure)
-- =============================================================

DELIMITER $$

DROP PROCEDURE IF EXISTS sp_detect_and_alert $$
CREATE PROCEDURE sp_detect_and_alert()
BEGIN
    DECLARE inserted_count INT DEFAULT 0;

    -- ── Rule 1: High-Value DEBIT > ₹80,000 ──────────────────
    INSERT INTO fraud_alerts (txn_id, fraud_type, risk_score, alert_time, notes)
    SELECT
        t.txn_id,
        'High Value Transfer',
        CASE
            WHEN t.amount > 200000 THEN 95
            WHEN t.amount > 100000 THEN 85
            ELSE 75
        END,
        NOW(),
        CONCAT('Amount ₹', FORMAT(t.amount, 2), ' exceeds threshold')
    FROM transactions t
    WHERE t.amount > 80000
      AND t.txn_type = 'DEBIT'
      AND t.status = 'SUCCESS'
      AND NOT EXISTS (
          SELECT 1 FROM fraud_alerts fa
          WHERE fa.txn_id = t.txn_id
            AND fa.fraud_type = 'High Value Transfer'
      );
    SET inserted_count = inserted_count + ROW_COUNT();

    -- ── Rule 2: Night-Time Large Transactions ────────────────
    INSERT INTO fraud_alerts (txn_id, fraud_type, risk_score, alert_time, notes)
    SELECT
        t.txn_id,
        'Night-Time High Value',
        80,
        NOW(),
        CONCAT('Transaction at ', TIME(t.txn_time), ' for ₹', FORMAT(t.amount, 2))
    FROM transactions t
    WHERE HOUR(t.txn_time) BETWEEN 1 AND 3
      AND t.amount > 10000
      AND t.txn_type = 'DEBIT'
      AND NOT EXISTS (
          SELECT 1 FROM fraud_alerts fa
          WHERE fa.txn_id = t.txn_id
            AND fa.fraud_type = 'Night-Time High Value'
      );
    SET inserted_count = inserted_count + ROW_COUNT();

    -- ── Rule 3: Repeated FAILED Attempts ─────────────────────
    INSERT INTO fraud_alerts (txn_id, fraud_type, risk_score, alert_time, notes)
    SELECT
        t.txn_id,
        'Repeated Failed Attempts',
        70,
        NOW(),
        CONCAT('Account has multiple failed transactions')
    FROM transactions t
    WHERE t.status = 'FAILED'
      AND t.account_id IN (
          SELECT account_id
          FROM transactions
          WHERE status = 'FAILED'
          GROUP BY account_id
          HAVING COUNT(*) >= 3
      )
      AND NOT EXISTS (
          SELECT 1 FROM fraud_alerts fa
          WHERE fa.txn_id = t.txn_id
            AND fa.fraud_type = 'Repeated Failed Attempts'
      );
    SET inserted_count = inserted_count + ROW_COUNT();

    -- ── Rule 4: Suspicious Merchant Categories ────────────────
    INSERT INTO fraud_alerts (txn_id, fraud_type, risk_score, alert_time, notes)
    SELECT
        t.txn_id,
        'Unusual Merchant Pattern',
        65,
        NOW(),
        CONCAT('High-risk merchant: ', t.merchant_category)
    FROM transactions t
    WHERE t.merchant_category IN ('Crypto Exchange','International','Gaming')
      AND t.amount > 50000
      AND NOT EXISTS (
          SELECT 1 FROM fraud_alerts fa
          WHERE fa.txn_id = t.txn_id
            AND fa.fraud_type = 'Unusual Merchant Pattern'
      );
    SET inserted_count = inserted_count + ROW_COUNT();

    SELECT CONCAT('sp_detect_and_alert completed. New alerts inserted: ', inserted_count) AS result;
END $$

DELIMITER ;

-- Run the procedure:
CALL sp_detect_and_alert();


-- =============================================================
-- SECTION 5: POWER BI EXPORT QUERIES
-- (Save results as CSV for Power BI import)
-- =============================================================

-- ── Export 1: Transaction Details with Customer Info ──────────
SELECT
    t.txn_id,
    t.txn_time,
    YEAR(t.txn_time)    AS txn_year,
    MONTH(t.txn_time)   AS txn_month,
    MONTHNAME(t.txn_time) AS txn_month_name,
    DATE(t.txn_time)    AS txn_date,
    HOUR(t.txn_time)    AS txn_hour,
    DAYNAME(t.txn_time) AS day_of_week,
    t.amount,
    t.txn_type,
    t.status,
    t.location_city,
    t.merchant_category,
    t.device_id,
    a.account_id,
    a.account_type,
    a.branch_name,
    a.balance,
    a.status            AS account_status,
    c.customer_id,
    c.full_name,
    c.age,
    c.gender,
    c.city              AS customer_city,
    c.state,
    COALESCE(fa.fraud_type, 'Normal')  AS fraud_type,
    COALESCE(fa.risk_score, 0)         AS risk_score,
    CASE WHEN fa.alert_id IS NULL THEN 'No' ELSE 'Yes' END AS is_fraud
FROM transactions t
JOIN accounts     a  ON t.account_id  = a.account_id
JOIN customers    c  ON a.customer_id = c.customer_id
LEFT JOIN fraud_alerts fa ON t.txn_id = fa.txn_id;


-- ── Export 2: Fraud Alert Summary ────────────────────────────
SELECT
    fa.alert_id,
    fa.txn_id,
    fa.fraud_type,
    fa.risk_score,
    fa.alert_time,
    DATE(fa.alert_time)   AS alert_date,
    MONTHNAME(fa.alert_time) AS alert_month,
    t.amount,
    t.txn_type,
    t.location_city,
    t.merchant_category,
    a.account_type,
    c.full_name,
    c.city,
    c.state,
    CASE
        WHEN fa.risk_score >= 80 THEN 'Critical'
        WHEN fa.risk_score >= 60 THEN 'High'
        WHEN fa.risk_score >= 40 THEN 'Medium'
        ELSE 'Low'
    END                   AS risk_level
FROM fraud_alerts fa
JOIN transactions t ON fa.txn_id    = t.txn_id
JOIN accounts     a ON t.account_id = a.account_id
JOIN customers    c ON a.customer_id = c.customer_id
ORDER BY fa.risk_score DESC;


-- ── Export 3: Account Risk Profile for Power BI ───────────────
SELECT * FROM vw_account_risk_profile;

-- End of fraud_queries.sql
SELECT 'All queries executed successfully.' AS status;
