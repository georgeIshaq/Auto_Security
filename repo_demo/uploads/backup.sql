-- Database backup with exposed credentials
CREATE DATABASE production_app;

USE production_app;

-- Admin users table with plain text passwords
CREATE TABLE admin_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert admin users with weak passwords
INSERT INTO admin_users (username, password, email) VALUES 
('admin', 'admin123', 'admin@company.com'),
('root', 'rootpassword', 'root@company.com'),
('superuser', 'password123', 'superuser@company.com');

-- API keys table (should not be in backup)
CREATE TABLE api_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    service VARCHAR(50) NOT NULL,
    api_key VARCHAR(255) NOT NULL,
    secret_key VARCHAR(255) NOT NULL
);

INSERT INTO api_keys (service, api_key, secret_key) VALUES 
('stripe', 'sk_live_51234567890abcdef1234567890abcdef1234567890abcdef', 'pk_live_51234567890abcdef1234567890abcdef1234567890abcdef'),
('aws', 'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'),
('github', 'ghp_1234567890abcdef1234567890abcdef12345678', 'webhook_secret_12345');
