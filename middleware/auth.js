const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

// Log file setup
const authLogStream = fs.createWriteStream(
  path.join(__dirname, "../logs/auth.log"),
  { flags: "a" }
);

exports.verifyJwt = (req, res, next) => {
  const auth = req.header("authorization");
  if (!auth)
    return res.status(401).json({ error: "Authorization header required" });

  const parts = auth.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer")
    return res.status(401).json({ error: "Malformed token" });

  try {
    const payload = jwt.verify(
      parts[1],
      process.env.JWT_SECRET || "change-this-secret"
    );
    req.user = payload;
    next();
  } catch (err) {
    // Fail2Ban log for bad JWT
    authLogStream.write(
      `${new Date().toISOString()} - BAD_JWT - ${req.ip} - ${err.message}\n`
    );
    return res.status(401).json({ error: "Invalid token" });
  }
};

exports.verifyApiKey = (req, res, next) => {
  const keys = (process.env.API_KEYS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const provided = req.header("x-api-key");

  if (!provided) return res.status(401).json({ error: "API key required" });

  if (!keys.includes(provided)) {
    // Fail2Ban log for bad API Key
    authLogStream.write(
      `${new Date().toISOString()} - BAD_API_KEY - ${req.ip} - ${
        req.originalUrl
      }\n`
    );
    return res.status(403).json({ error: "Invalid API key" });
  }
  next();
};
