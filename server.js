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

const csrf = require("csurf");
const cookieParser = require("cookie-parser");

dotenv.config();

const { verifyJwt, verifyApiKey } = require("./middleware/auth");

const app = express();

const logsDir = path.join(__dirname, "logs");
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

const accessLogStream = fs.createWriteStream(path.join(logsDir, "access.log"), { flags: "a" });
const authLogStream = fs.createWriteStream(path.join(logsDir, "auth.log"), { flags: "a" });

app.use(express.json()); 
app.use(morgan("combined", { stream: accessLogStream }));

app.use(cookieParser());

app.use(helmet());
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));

app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none';");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    next();
});

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

const csrfProtection = csrf({ cookie: true });


const demoUser = {
    username: process.env.DEMO_USER || "admin",
    passwordHash: bcrypt.hashSync(process.env.DEMO_PASS || "password123", 10),
};


app.get("/", (req, res) => {
    res.json({ status: "ok", message: "Secure API is Running" });
});

app.get("/api/csrf-token", csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

app.post("/api/auth/login", loginLimiter, (req, res) => {
    const { username, password } = req.body;

  

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


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`[SUCCESS] Server is locked and loaded on port ${PORT}`);
});

