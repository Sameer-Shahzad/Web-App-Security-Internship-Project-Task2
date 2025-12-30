const express = require("express");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const cors = require("cors");
const dotenv = require("dotenv");
const morgan = require("morgan");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

// WEEK 5 NEW: CSRF aur Cookie Parser ko require karein
const csrf = require("csurf");
const cookieParser = require("cookie-parser");

dotenv.config();

const { verifyJwt, verifyApiKey } = require("./middleware/auth");

const app = express();

// --- 1. LOGGING SETUP ---
const logsDir = path.join(__dirname, "logs");
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

const accessLogStream = fs.createWriteStream(path.join(logsDir, "access.log"), { flags: "a" });
const authLogStream = fs.createWriteStream(path.join(logsDir, "auth.log"), { flags: "a" });

app.use(express.json()); 
app.use(morgan("combined", { stream: accessLogStream }));

// WEEK 5 NEW: CSRF ke liye cookie-parser zaroori hai
app.use(cookieParser());

// --- 2. SECURITY HEADERS ---
app.use(helmet());
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));

app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none';");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    next();
});

// --- 3. CORS CONFIGURATION ---
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error("Blocked by CORS Policy"));
        }
    },
    methods: ["GET", "POST"]
}));

// --- 4. RATE LIMITING ---
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: "Too many requests, please try again later." }
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    handler: (req, res) => {
        authLogStream.write(`${new Date().toISOString()} - RATE_LIMIT_EXCEEDED - ${req.ip}\n`);
        res.status(429).json({ error: "Too many login attempts. Blocked for 15 mins." });
    }
});

app.use(globalLimiter);

// WEEK 5 NEW: CSRF Protection Middleware
// Ye har POST request par aik secret token check karega
const csrfProtection = csrf({ cookie: true });

// --- 5. USER AUTHENTICATION LOGIC ---
const demoUser = {
    username: process.env.DEMO_USER || "admin",
    passwordHash: bcrypt.hashSync(process.env.DEMO_PASS || "password123", 10),
};

// --- 6. ROUTES ---

// Public Route
app.get("/", (req, res) => {
    res.json({ status: "ok", message: "Secure API is Running" });
});

// WEEK 5 NEW: CSRF Token lene ka route
// Client pehle yahan se token lega, phir POST request bhej sakega
app.get("/api/csrf-token", csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Login Route (Ab is mein CSRF Protection bhi hai)
app.post("/api/auth/login", csrfProtection, loginLimiter, (req, res) => {
    const { username, password } = req.body;

    /* WEEK 5 SQL INJECTION NOTE:
       Agar aap database use kar rahe hain, toh aise query likhein:
       db.query("SELECT * FROM users WHERE username = ?", [username]);
       Ye ? (placeholder) SQL Injection ko rokta hai.
    */

    if (username !== demoUser.username || !bcrypt.compareSync(password, demoUser.passwordHash)) {
        authLogStream.write(`${new Date().toISOString()} - FAILED_LOGIN - ${req.ip} - ${username}\n`);
        return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
        { user: username }, 
        process.env.JWT_SECRET || "secure-secret-key", 
        { expiresIn: "1h" }
    );

    res.json({ message: "Login Successful", token });
});

app.get("/api/v1/profile", verifyJwt, (req, res) => {
    res.json({ message: "Welcome to your profile", user: req.user });
});

app.get("/api/v1/stats", verifyApiKey, (req, res) => {
    res.json({ message: "System stats accessed via API Key" });
});

// --- 7. SERVER START ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`[SUCCESS] Server is locked and loaded on port ${PORT}`);
});

// curl -X POST http://localhost:3000/api/auth/login \
// -H "Content-Type: application/json" \
// -d '{"username":"admin","password":"password1223"}'
// {"error":"Invalid credentials"}%      