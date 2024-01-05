const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const db = require('./database');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const cors = require('cors');


const app = express();
app.use(bodyParser.json());
app.use(cookieParser())

const corsOptions = {
    origin: 'http://localhost:3000', // Client's URL
    credentials: true,
};

app.use(cors(corsOptions));

// Secret key for JWT
const SECRET_KEY = 'BEdo+rG4bOJUA/7v609QY5sbzuopYmfdIYjNbaDxLSQ='; // In a real app, store this in an environment variable

// User registration endpoint
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(201).json({ id: this.lastID });
    });
});

// Function to generate a fingerprint
function generateFingerprint(req) {
    const hash = crypto.createHash('sha256');
    hash.update(req.headers['user-agent']);
    return hash.digest('hex');
}

// Middleware to verify JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).send('Access Denied');

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            console.log("JWT verification failed:", err.message);
            return res.status(err.name === "TokenExpiredError" ? 401 : 403).send('Invalid Token');
        }
        console.log("JWT verified successfully for user:", user.username);
        req.user = user;
        next();
    });
}

// Function to generate JWT
function generateToken(user) {
    console.log("Generating JWT for user:", user.username);
    return jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '30s' });
}

// Function to generate Refresh Token with fingerprint
function generateRefreshToken(user, fingerprint) {
    console.log("Generating Refresh Token for user:", user.username);
    return jwt.sign({ id: user.id, fp: crypto.createHash('sha256').update(fingerprint).digest('hex') }, SECRET_KEY, { expiresIn: '7d' });
}

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = generateToken(user);
        const fingerprint = generateFingerprint(req);
        console.log('fingerprint after login', fingerprint)
        const refreshToken = generateRefreshToken(user, fingerprint);

        // Set fingerprint as HttpOnly cookie

        res.cookie('fingerprint', fingerprint, { httpOnly: true, path: '/', secure: false, sameSite: 'lax' });
        console.log("Setting fingerprint cookie:", fingerprint);
        // Update refreshToken in database
        db.run("UPDATE users SET refreshToken = ? WHERE id = ?", [refreshToken, user.id], (err) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            // Send response
            res.json({ jwt: token, refreshToken });
        });
    });
});




// Refresh token endpoint
app.post('/token', (req, res) => {
    console.log("Token endpoint called with refresh token:", req.body.refreshToken);
    const { refreshToken } = req.body;
    const fingerprint = req.cookies['fingerprint']; // Retrieve fingerprint from HttpOnly cookie
    console.log('fingerprint', req.cookies[fingerprint])

    // THIS LINE IS STRESSFUL

    // if (!refreshToken || !fingerprint) {
    //     return res.status(401).json({ error: 'No refresh token or fingerprint provided' });
    // }

    db.get("SELECT * FROM users WHERE refreshToken = ?", [refreshToken], (err, user) => {
        if (err || !user) {
            return res.status(403).json({ error: 'Invalid refresh token' });
        }

        jwt.verify(refreshToken, SECRET_KEY, (err, decoded) => {
            if (err) {
                return res.status(403).json({ error: 'Invalid refresh token' });
            }

            // Validate the fingerprint
            const hashedFingerprint = crypto.createHash('sha256').update(fingerprint).digest('hex');
            if (decoded.fp !== hashedFingerprint) {
                return res.status(403).json({ error: 'Fingerprint mismatch' });
            }

            // Generate a new JWT and refresh token
            const newToken = generateToken(user);
            const newRefreshToken = generateRefreshToken(user, fingerprint);
            console.log('new token', newRefreshToken);
            res.json({ jwt: newToken, refreshToken: newRefreshToken });
        });
    });
});
app.get('/protected', authenticateToken, (req, res) => {
    console.log("Accessing protected route");
    // Assuming req.user contains the decoded JWT user data
    if (req.user) {
        // You can access user details from req.user here
        res.json({
            message: "You are accessing a protected route!",
            userData: req.user
        });
    } else {
        res.status(401).json({ message: "Unauthorized access" });
    }
});


// Logout endpoint to invalidate refresh token
app.post('/logout', (req, res) => {
    const { refreshToken } = req.body;
    db.run("UPDATE users SET refreshToken = NULL WHERE refreshToken = ?", [refreshToken], (err) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(204).send();
    });
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
