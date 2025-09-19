# Vulnerable App Demo

This is a demo application intentionally created with security vulnerabilities for testing and educational purposes.

## ⚠️ WARNING ⚠️

**DO NOT USE IN PRODUCTION!** This application contains numerous security vulnerabilities including:

- Hardcoded API keys and passwords
- SQL injection vulnerabilities
- Weak authentication mechanisms
- Exposed configuration files
- Command injection vulnerabilities
- Path traversal vulnerabilities
- Weak encryption practices

## Vulnerabilities Included

### 1. Exposed Credentials
- API keys (AWS, Stripe, GitHub, OpenAI, etc.)
- Database passwords
- JWT secrets
- Admin credentials

### 2. Code Vulnerabilities
- SQL injection in database queries
- Command injection in file operations
- Path traversal in file access
- Weak password hashing
- No input validation
- Authentication bypass

### 3. Configuration Issues
- Secrets in config files
- Production credentials in .env
- Exposed database schemas
- Weak security headers

## Files with Vulnerabilities

- `app.js` - Main application with hardcoded secrets and vulnerable endpoints
- `config.js` - Configuration file with exposed API keys
- `.env` - Environment file with production secrets
- `auth.js` - Authentication module with weak security
- `database.js` - Database module with SQL injection vulnerabilities
- `utils.js` - Utility functions with various security issues
- `config/production.json` - Production configuration with secrets
- `config/development.json` - Development configuration with credentials
- `secrets.json` - JSON file with API keys and passwords
- `uploads/backup.sql` - Database backup with exposed credentials

## Installation

```bash
npm install
```

## Running

```bash
npm start
```

## Testing

This application is designed to be scanned by security tools to demonstrate vulnerability detection capabilities.

## Educational Use Only

This codebase is intended for:
- Security training
- Vulnerability scanner testing
- Penetration testing practice
- Security awareness education

Never deploy this code to any production environment.
