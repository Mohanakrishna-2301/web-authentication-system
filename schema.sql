-- SecureAuth+ Database Schema
-- MySQL 8.0+

CREATE DATABASE IF NOT EXISTS secureauth;
USE secureauth;

-- ============================================================
-- USERS TABLE
-- Stores user & admin account data
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    phone VARCHAR(20) DEFAULT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('user', 'admin') DEFAULT 'user',
    avatar_url VARCHAR(500) DEFAULT NULL,
    email_verified TINYINT(1) DEFAULT 0,
    email_token VARCHAR(255) DEFAULT NULL,
    twofa_enabled TINYINT(1) DEFAULT 0,
    twofa_secret VARCHAR(64) DEFAULT NULL,
    otp_code VARCHAR(10) DEFAULT NULL,
    otp_expires_at DATETIME DEFAULT NULL,
    is_active TINYINT(1) DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- LOGIN HISTORY TABLE
-- Tracks every login attempt for security & transparency
-- ============================================================
CREATE TABLE IF NOT EXISTS login_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45) NOT NULL,
    device_info VARCHAR(500) DEFAULT NULL,
    browser VARCHAR(100) DEFAULT NULL,
    os_info VARCHAR(100) DEFAULT NULL,
    location VARCHAR(200) DEFAULT NULL,
    risk_level ENUM('Low', 'Medium', 'High') DEFAULT 'Low',
    success TINYINT(1) DEFAULT 1,
    failure_reason VARCHAR(255) DEFAULT NULL,
    INDEX idx_user_id (user_id),
    INDEX idx_login_time (login_time),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- USER SESSIONS TABLE
-- Manages active login sessions
-- ============================================================
CREATE TABLE IF NOT EXISTS user_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_token VARCHAR(255) NOT NULL UNIQUE,
    user_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    device_info VARCHAR(500) DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    is_active TINYINT(1) DEFAULT 1,
    INDEX idx_session_token (session_token),
    INDEX idx_user_sessions (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- ADMIN ACTIONS TABLE
-- Keeps audit logs of admin activity
-- ============================================================
CREATE TABLE IF NOT EXISTS admin_actions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    admin_id INT NOT NULL,
    action_type VARCHAR(100) NOT NULL,
    target_user_id INT DEFAULT NULL,
    description TEXT DEFAULT NULL,
    ip_address VARCHAR(45) DEFAULT NULL,
    performed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_admin_id (admin_id),
    FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- SEED: Default admin account
-- Password: Admin@123 (bcrypt hashed)
-- ============================================================
INSERT INTO users (full_name, email, password_hash, role, email_verified)
VALUES ('Admin', 'admin@secureauth.com',
        '$2b$12$LJ3m4ys3Lk0TSwMCCiNgLuG0cEU7bJ8R7wFqYv0xP5mHQpKdUqIHi',
        'admin', 1)
ON DUPLICATE KEY UPDATE id=id;
