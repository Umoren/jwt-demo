const sqlite3 = require('sqlite3').verbose();

// Create a new database in memory
const db = new sqlite3.Database(':memory:', (err) => {
    if (err) {
        return console.error(err.message);
    }
    console.log('Connected to the in-memory SQlite database.');
});

// Create a users table
db.serialize(() => {
    db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    refreshToken TEXT
  )`);
});

module.exports = db;
