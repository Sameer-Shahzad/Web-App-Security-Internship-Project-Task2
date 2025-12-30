#Web Application Security & Ethical Hacking Project

## **Project Overview**

This project was developed during a **Cybersecurity Internship** at DevelopersHub Corporation. The goal was to build a secure Node.js API, perform ethical hacking audits, and implement advanced defense mechanisms against modern web threats.

---

## **Week 4: Advanced Threat Detection & Web Security**

**Goal:** Implement real-time monitoring and harden API endpoints.

* **Intrusion Detection:** Integrated **Fail2Ban** to monitor `auth.log` and automatically block IP addresses after multiple failed login attempts.
* **Rate Limiting:** Applied `express-rate-limit` to prevent brute-force attacks on the login route.
* **Security Headers:** Implemented **Helmet.js** to manage secure HTTP headers like HSTS.
* **CSP Implementation:** Configured a strict **Content Security Policy (CSP)** to mitigate Cross-Site Scripting (XSS) and code injection.

---

## **Week 5: Ethical Hacking & Exploiting Vulnerabilities**

**Goal:** Identify and fix critical vulnerabilities using industry-standard tools.

* **Reconnaissance:** Conducted network and service scanning using **Nmap** and **Nikto** to identify open ports and server versions.
* **SQL Injection (SQLi):**
* **Exploitation:** Used **SQLMap** to identify vulnerable database entry points.
* **The Fix:** Applied **Prepared Statements** (Parameterized Queries) to ensure user input cannot execute malicious SQL commands.


* **CSRF Protection:**
* **Testing:** Verified vulnerabilities using **Burp Suite** interceptor.
* **The Fix:** Integrated `csurf` middleware and `cookie-parser` to enforce unique CSRF tokens for all state-changing requests.



---

## **Week 6: Advanced Security Audits & Final Deployment**

**Goal:** Compliance auditing and final penetration testing.

* **Security Audits:** Performed comprehensive audits using **OWASP ZAP** and **Lynis** to ensure the system follows **OWASP Top 10** best practices.
* **Docker Security:** Followed container security best practices, including image scanning and using non-root users.
* **Final Penetration Test:** Conducted a final end-to-end test using **Metasploit** and **Burp Suite** to document remaining risks and improvements.

---

## **🛠️ Tech Stack & Tools**

* **Backend:** Node.js, Express.js
* **Security:** Helmet, Csurf, Bcrypt, JWT
* **Hacking Tools:** Kali Linux, SQLMap, Burp Suite, Nmap, OWASP ZAP
* **Monitoring:** Fail2Ban, Morgan (Logging)

---

## **Installation & Usage**

1. **Clone the repository:**
```bash
git clone https://github.com/Sameer-Shahzad/Web-App-Security-Internship-Project-Task2.git

```


2. **Install dependencies:**
```bash
npm install

```


3. **Set up Environment Variables:**
Create a `.env` file and add `JWT_SECRET`, `PORT`, and `ALLOWED_ORIGINS`.
4. **Run the Server:**
```bash
node server.js

```
