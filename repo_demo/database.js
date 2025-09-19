// Database module with SQL injection vulnerabilities
const mysql = require('mysql');

// VULNERABILITY: Hardcoded database credentials
const dbConfig = {
    host: 'localhost',
    user: 'root',
    password: 'rootpassword123',
    database: 'production_app',
    port: 3306
};

const connection = mysql.createConnection(dbConfig);

// VULNERABILITY: SQL injection in user queries
function getUserById(userId) {
    // Direct string concatenation - SQL injection vulnerability
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    
    return new Promise((resolve, reject) => {
        connection.query(query, (err, results) => {
            if (err) reject(err);
            else resolve(results);
        });
    });
}

// VULNERABILITY: SQL injection in search
function searchUsers(searchTerm) {
    // No parameterized queries
    const query = `SELECT * FROM users WHERE name LIKE '%${searchTerm}%' OR email LIKE '%${searchTerm}%'`;
    
    return new Promise((resolve, reject) => {
        connection.query(query, (err, results) => {
            if (err) reject(err);
            else resolve(results);
        });
    });
}

// VULNERABILITY: SQL injection in user creation
function createUser(userData) {
    const { name, email, password } = userData;
    // Direct string interpolation
    const query = `INSERT INTO users (name, email, password) VALUES ('${name}', '${email}', '${password}')`;
    
    return new Promise((resolve, reject) => {
        connection.query(query, (err, results) => {
            if (err) reject(err);
            else resolve(results);
        });
    });
}

// VULNERABILITY: SQL injection in update operations
function updateUser(userId, updateData) {
    const { name, email } = updateData;
    // Multiple injection points
    const query = `UPDATE users SET name = '${name}', email = '${email}' WHERE id = ${userId}`;
    
    return new Promise((resolve, reject) => {
        connection.query(query, (err, results) => {
            if (err) reject(err);
            else resolve(results);
        });
    });
}

// VULNERABILITY: SQL injection in delete operations
function deleteUser(userId) {
    // No input validation
    const query = `DELETE FROM users WHERE id = ${userId}`;
    
    return new Promise((resolve, reject) => {
        connection.query(query, (err, results) => {
            if (err) reject(err);
            else resolve(results);
        });
    });
}

// VULNERABILITY: Exposed database schema and data
function getDatabaseInfo() {
    const queries = [
        'SHOW TABLES',
        'DESCRIBE users',
        'SELECT COUNT(*) as user_count FROM users',
        'SELECT * FROM admin_users LIMIT 5'
    ];
    
    return new Promise((resolve, reject) => {
        const results = {};
        let completed = 0;
        
        queries.forEach((query, index) => {
            connection.query(query, (err, result) => {
                if (err) {
                    console.error(`Query ${index} failed:`, err);
                } else {
                    results[`query_${index}`] = result;
                }
                
                completed++;
                if (completed === queries.length) {
                    resolve(results);
                }
            });
        });
    });
}

// VULNERABILITY: No connection security
function connectToDatabase() {
    connection.connect((err) => {
        if (err) {
            console.error('Database connection failed:', err);
        } else {
            console.log('Connected to database');
            // VULNERABILITY: Logging credentials
            console.log('Connected with:', dbConfig);
        }
    });
}

module.exports = {
    getUserById,
    searchUsers,
    createUser,
    updateUser,
    deleteUser,
    getDatabaseInfo,
    connectToDatabase
};
