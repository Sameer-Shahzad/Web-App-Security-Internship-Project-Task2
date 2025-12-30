# Secure API Example (Weeks 4–6 deliverable)

This repository demonstrates an Express API secured with rate limiting, CORS restrictions, API-key + JWT authentication, security headers (HSTS and CSP), and logging suitable for OS-level intrusion detection (Fail2Ban).

Setup

1. Install Node dependencies

```bash
cd /Users/sameershahzad/Desktop/CYS_Internship_2
npm install
```

2. Copy environment file and edit keys

```bash
cp .env.example .env
# Edit .env: set JWT_SECRET and API_KEYS and ALLOWED_ORIGINS
```

Run

```bash
npm start
# or during development
npm run dev
```

Test endpoints

- Public: curl http://localhost:3000/
- Login (receive JWT):

```bash
curl -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"username":"admin","password":"password123"}'
```

- Use JWT:

```bash
curl http://localhost:3000/protected -H "Authorization: Bearer <TOKEN>"
```

- Use API key:

```bash
curl http://localhost:3000/apikey-data -H "x-api-key: key1"
```

Logs

Logs are written to the `logs/` directory (`access.log` and `auth.log`). Failed login attempts and bad API key/JWT uses are recorded in `logs/auth.log` and are suitable for Fail2Ban monitoring.

Fail2Ban (intrusion detection) sample

On macOS (Homebrew):

```bash
brew install fail2ban
# Create config files from the samples in fail2ban/
# Start or enable service as appropriate for your OS.
```

Sample jail and filter (provided in `fail2ban/`) watch `logs/auth.log` and ban IPs after several failed login attempts.

Security notes

- This demo uses an in-memory demo user and example secrets — replace with a real user store and secure secrets for production.
- Use HTTPS (TLS) in front of this service (HSTS header is set). For production, terminate TLS at a reverse proxy or load balancer.
- Consider adding OAuth via `passport` and integrating with a trusted identity provider for stronger auth.
