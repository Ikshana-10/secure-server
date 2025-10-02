const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const sqlite = require('sqlite');
const sqlite3 = require('sqlite3'); // Required for the sqlite package

// --- Server Setup ---
const app = express();
const PORT = 5000;
const saltRounds = 10;
const DB_PATH = 'secure_app.db'; // The name of your database file

let db; // Global variable to hold the database connection

// Enable CORS and JSON body parsing
app.use(cors()); 
app.use(express.json());

// --- Database Initialization Function ---

/**
 * Initializes the SQLite database connection and sets up the necessary tables.
 */
async function initializeDatabase() {
    try {
        db = await sqlite.open({
            filename: DB_PATH,
            driver: sqlite3.Database
        });

        console.log('Database connected successfully.');

        // Create the users table (stores hashed passwords and content)
        await db.exec(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                hash TEXT NOT NULL,
                content TEXT
            );
        `);

        // Create the sessions table (stores active login tokens)
        await db.exec(`
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_email TEXT UNIQUE NOT NULL,
                FOREIGN KEY (user_email) REFERENCES users (email)
            );
        `);

        console.log('Database tables ensured.');

        // Add a default test user if one doesn't exist
        await setupDefaultUser();

    } catch (e) {
        console.error("Database Initialization Error:", e);
        process.exit(1); // Exit if the database cannot be set up
    }
}

// --- Security Middleware & Functions ---

/**
 * Server-side input validation.
 */
const validateInput = (data, requiredFields) => {
    for (const field of requiredFields) {
        if (!data || !data[field] || typeof data[field] !== 'string' || data[field].trim() === '') {
            return `Missing or invalid field: ${field}`;
        }
    }
    return null;
};

/**
 * Middleware for protecting dashboard routes by checking the session table.
 */
const authRequired = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: "Authorization token required" });
    }
    
    const sessionToken = authHeader.split(' ')[1];
    
    // 2. Server-side session validation (Database Lookup)
    try {
        const session = await db.get('SELECT user_email FROM sessions WHERE token = ?', [sessionToken]);
        
        if (!session) {
            return res.status(401).json({ error: "Invalid or expired session token" });
        }
        
        // Attach the validated user email to the request object
        req.userEmail = session.user_email;
        req.sessionToken = sessionToken;
        next();
    } catch (e) {
        console.error("Auth Middleware Error:", e);
        return res.status(500).json({ error: "Server error during authentication." });
    }
};

// --- Authentication Endpoints ---

app.post('/signup', async (req, res) => {
    /** Handles user registration with secure password hashing and DB insertion. */
    const data = req.body;
    const error = validateInput(data, ['email', 'password']);
    if (error) {
        return res.status(400).json({ error });
    }
    
    const email = data.email.trim();
    const password = data.password;

    try {
        // Check if user already exists (Database Query)
        const existingUser = await db.get('SELECT email FROM users WHERE email = ?', [email]);
        if (existingUser) {
            return res.status(409).json({ error: "User already exists" });
        }

        // Secure Password Hashing
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        // Store user in database (SQL Insertion)
        await db.run(
            'INSERT INTO users (email, hash, content) VALUES (?, ?, ?)',
            [email, hashedPassword, 'This content is permanently saved in the database.']
        );

        console.log(`User signed up: ${email}`);
        return res.status(201).json({ message: "Registration successful. Please log in." });
    } catch (e) {
        console.error("Signup Database Error:", e);
        return res.status(500).json({ error: "Server error during registration." });
    }
});

app.post('/login', async (req, res) => {
    /** Handles user login, password check, and session creation in the DB. */
    const data = req.body;
    const error = validateInput(data, ['email', 'password']);
    if (error) {
        return res.status(400).json({ error });
    }
    
    const email = data.email.trim();
    const password = data.password;

    try {
        // Retrieve user (Database Query)
        const user = await db.get('SELECT email, hash FROM users WHERE email = ?', [email]);

        // Check User and Password securely
        if (!user || !(await bcrypt.compare(password, user.hash))) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        // Session Generation (Create/Update session in DB)
        const sessionToken = uuidv4();
        
        // Use REPLACE to either insert a new session or update an existing one for this user
        await db.run(
            'REPLACE INTO sessions (token, user_email) VALUES (?, ?)', 
            [sessionToken, email]
        );
        
        return res.status(200).json({ 
            message: "Login successful", 
            session_token: sessionToken, 
            user_email: email 
        });
    } catch (e) {
        console.error("Login Database Error:", e);
        return res.status(500).json({ error: "Server error during login." });
    }
});

app.post('/logout', authRequired, async (req, res) => {
    /** Handles session destruction (Deletes the session from the DB). */
    try {
        await db.run('DELETE FROM sessions WHERE token = ?', [req.sessionToken]);
        return res.status(200).json({ message: `User ${req.userEmail} logged out successfully.` });
    } catch (e) {
        console.error("Logout Database Error:", e);
        return res.status(500).json({ error: "Server error during logout." });
    }
});

// --- Protected Data Endpoint ---

app.get('/dashboard', authRequired, async (req, res) => {
    /** Protected route to fetch permanent user data. */
    try {
        const user = await db.get('SELECT email, content FROM users WHERE email = ?', [req.userEmail]);
        
        if (!user) {
             return res.status(500).json({ error: "User data not found" });
        }

        return res.status(200).json({
            email: user.email,
            content: user.content || 'No content saved yet.' // Ensure content is not null
        });
    } catch (e) {
        console.error("Dashboard GET Error:", e);
        return res.status(500).json({ error: "Server error retrieving data." });
    }
});

app.post('/dashboard', authRequired, async (req, res) => {
    /** Protected route to update user data permanently. */
    const data = req.body;
    const rawContent = data.content || '';
    
    try {
        // Update user's content in the database
        await db.run(
            'UPDATE users SET content = ? WHERE email = ?',
            [rawContent, req.userEmail]
        );

        return res.status(200).json({ message: "Content saved permanently to SQLite database." });
    } catch (e) {
        console.error("Dashboard POST Error:", e);
        return res.status(500).json({ error: "Server error saving data." });
    }
});


// --- Server Start ---
// Create a default test user asynchronously if they don't exist
const setupDefaultUser = async () => {
    const testEmail = "test@secure.com";
    const testPassword = "Secure123!";
    
    const existingUser = await db.get('SELECT email FROM users WHERE email = ?', [testEmail]);

    if (!existingUser) {
        try {
            const hashedPassword = await bcrypt.hash(testPassword, saltRounds);
            await db.run(
                'INSERT INTO users (email, hash, content) VALUES (?, ?, ?)',
                [testEmail, hashedPassword, 'Welcome! This default data is permanent.']
            );
            console.log(`Default user created and saved permanently: ${testEmail} / ${testPassword}`);
        } catch (e) {
            console.error("Failed to create default user:", e);
        }
    } else {
        console.log(`Default user already exists in the permanent database.`);
    }
};

// Start the database connection, then start the server
async function startServer() {
    await initializeDatabase();
    
    app.listen(PORT, () => {
        console.log(`\nNode.js Secure Backend (Permanent Data) running on port ${PORT}`);
    });
}

startServer();

