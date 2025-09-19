// Configuration file with exposed secrets
module.exports = {
    // VULNERABILITY: Database credentials in plain text
    database: {
        host: 'prod-db.company.com',
        port: 3306,
        username: 'db_admin',
        password: 'MyDatabasePassword2024!',
        database: 'production_users'
    },

    // VULNERABILITY: API keys and tokens
    apis: {
        stripe: {
            public_key: 'pk_test_51234567890abcdef1234567890abcdef1234567890abcdef',
            secret_key: 'sk_test_51234567890abcdef1234567890abcdef1234567890abcdef'
        },
        aws: {
            access_key: 'AKIAIOSFODNN7EXAMPLE',
            secret_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            region: 'us-east-1'
        },
        github: {
            token: 'ghp_1234567890abcdef1234567890abcdef12345678',
            webhook_secret: 'webhook_secret_12345'
        },
        openai: {
            api_key: 'sk-1234567890abcdef1234567890abcdef1234567890abcdef'
        }
    },

    // VULNERABILITY: JWT and encryption secrets
    security: {
        jwt_secret: 'super-secret-jwt-key-for-production',
        encryption_key: 'my-32-character-encryption-key-123',
        session_secret: 'session-secret-for-cookies'
    },

    // VULNERABILITY: Third-party service credentials
    services: {
        sendgrid: {
            api_key: 'SG.1234567890abcdef1234567890abcdef.1234567890abcdef1234567890abcdef1234567890abcdef'
        },
        twilio: {
            account_sid: 'AC1234567890abcdef1234567890abcdef',
            auth_token: '1234567890abcdef1234567890abcdef'
        },
        mongodb: {
            connection_string: 'mongodb://admin:password123@cluster0.mongodb.net:27017/production'
        }
    },

    // VULNERABILITY: Email and SMTP credentials
    email: {
        smtp: {
            host: 'smtp.gmail.com',
            port: 587,
            username: 'admin@company.com',
            password: 'GmailPassword123!'
        }
    }
};
