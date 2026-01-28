# React Frontend Security Guide

**Last Updated:** January 27, 2026

A practical guide focused on securing production React applications. React's built-in protections handle many common vulnerabilities (XSS), allowing this guide to focus on configuration, authentication patterns, and security pitfalls specific to modern React development.

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [React's Built-In Security](#3-reacts-built-in-security)
4. [Authentication & Session Management](#4-authentication--session-management)
5. [Content Security Policy (CSP)](#5-content-security-policy-csp)
6. [CSRF Protection](#6-csrf-protection)
7. [Dependency Security](#7-dependency-security)
8. [Environment Variables & Secrets](#8-environment-variables--secrets)
9. [Browser Security Headers](#9-browser-security-headers)
10. [React-Specific Security Pitfalls](#10-react-specific-security-pitfalls)
11. [Attack Scenarios Prevented](#11-attack-scenarios-prevented)
12. [References](#12-references)

## 1. Overview

React applications run in the browser and communicate with backend APIs. This guide focuses on securing the frontend while recognizing that **true security is enforced server-side**. React's built-in XSS protections handle most injection attacks, so this guide emphasizes authentication, CSP, and React-specific pitfalls.

**What React Already Handles:**

- XSS prevention (JSX auto-escapes by default)
- Safe rendering (strings escaped automatically)
- Protection against HTML injection

**What You Must Configure:**

- Authentication (JWT storage, token refresh)
- Content Security Policy
- CSRF tokens for state-changing requests
- Dependency security
- Proper secret management

**Core Principles:**

- **Trust No Client**: All authorization happens server-side
- **Defense in Depth**: Multiple security layers (CSP + secure cookies + HTTPS)
- **Minimize Attack Surface**: Remove debug code, sanitize user content
- **Keep Dependencies Updated**: npm audit regularly
- **Fail Securely**: Redirect to login on auth errors

## 2. Prerequisites

### Required Tools

- [Node.js 18+](https://nodejs.org/) and npm/pnpm
- [React 18+](https://react.dev/)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Secret scanning (detects API keys, tokens in code)
- [Semgrep](https://semgrep.dev/) or [Opengrep](https://github.com/opengrep/opengrep) - SAST for JavaScript/TypeScript vulnerabilities
- [npm audit](https://docs.npmjs.com/cli/v9/commands/npm-audit) - Built-in dependency scanner

### Recommended Frameworks

This guide uses **React + Vite** for examples, but patterns apply to:

- Next.js (with additional server-side security)
- Create React App
- Remix
- Astro with React

### External Services

| Service            | Purpose                | Providers                                |
| ------------------ | ---------------------- | ---------------------------------------- |
| **Authentication** | JWT/session management | Auth0, Clerk, Firebase Auth, AWS Cognito |
| **API Backend**    | Authorization and data | Your API (see API Security Guide)        |
| **CDN**            | Static asset delivery  | CloudFlare, CloudFront, Fastly           |

## 3. React's Built-In Security

### Automatic XSS Prevention

**React escapes by default:**

```jsx
// SAFE - React escapes user input automatically
function UserProfile({ userName }) {
  return <div>Hello, {userName}</div>;
  // Even if userName = "<script>alert('xss')</script>"
  // React renders: Hello, &lt;script&gt;alert('xss')&lt;/script&gt;
}

// SAFE - JSX attributes are escaped
function Avatar({ userAvatar }) {
  return <img src={userAvatar} alt="Avatar" />;
  // Even malicious userAvatar is escaped
}
```

**What React Does:**

- Escapes `<`, `>`, `&`, `"`, `'` in JSX expressions
- Prevents script execution in rendered content
- Sanitizes attributes (`href`, `src`, etc.)

### When React DOESN'T Protect You

**Dangerous pattern: dangerouslySetInnerHTML**

```jsx
// DANGEROUS - Bypasses React's XSS protection
function UnsafeContent({ htmlContent }) {
  return <div dangerouslySetInnerHTML={{ __html: htmlContent }} />;
  // If htmlContent = "<img src=x onerror=alert('xss')>"
  // XSS executes!
}

// SAFE - Use DOMPurify if you must render HTML
import DOMPurify from "dompurify";

function SafeContent({ htmlContent }) {
  const clean = DOMPurify.sanitize(htmlContent);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

**When to use DOMPurify:**

- Rendering user-generated rich text (blog comments, WYSIWYG editors)
- Displaying HTML from external sources
- Markdown-to-HTML conversion

**Install DOMPurify:**

```bash
npm install dompurify
npm install --save-dev @types/dompurify  # TypeScript
```

### URL Safety

**Dangerous: javascript: URLs**

```jsx
// DANGEROUS - javascript: URLs execute code
function UnsafeLink({ userUrl }) {
  return <a href={userUrl}>Click</a>;
  // If userUrl = "javascript:alert('xss')"
  // XSS executes on click!
}

// SAFE - Validate URLs before use
function SafeLink({ userUrl }) {
  const isSafe =
    userUrl.startsWith("http://") || userUrl.startsWith("https://");

  if (!isSafe) {
    return <span>Invalid link</span>;
  }

  return (
    <a href={userUrl} rel="noopener noreferrer">
      Click
    </a>
  );
}
```

## 4. Authentication & Session Management

### JWT Storage (Recommended Approach)

**NEVER store tokens in localStorage** (vulnerable to XSS).

**Recommended: HttpOnly cookies**

```jsx
// Login API call - backend sets HttpOnly cookie
async function login(email, password) {
  const response = await fetch("https://api.example.com/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include", // Send/receive cookies
    body: JSON.stringify({ email, password }),
  });

  // Server sets: Set-Cookie: token=...; HttpOnly; Secure; SameSite=Strict

  if (response.ok) {
    return await response.json();
  }
  throw new Error("Login failed");
}

// Subsequent API calls automatically include cookie
async function fetchUserData() {
  const response = await fetch("https://api.example.com/user", {
    credentials: "include", // Sends HttpOnly cookie automatically
  });
  return response.json();
}
```

**Why HttpOnly cookies:**

- Not accessible to JavaScript (XSS cannot steal)
- Automatically sent with requests (convenient)
- Can be Secure (HTTPS only) and SameSite (CSRF protection)

**Backend sets cookie:**

```javascript
// Express.js example
app.post("/auth/login", async (req, res) => {
  const user = await authenticate(req.body);
  const token = generateJWT(user);

  res.cookie("token", token, {
    httpOnly: true, // Not accessible to JavaScript
    secure: true, // HTTPS only
    sameSite: "strict", // CSRF protection
    maxAge: 15 * 60 * 1000, // 15 minutes
  });

  res.json({ user });
});
```

### Token Refresh Pattern

**Access token (15 min) + Refresh token (7 days)**

```jsx
import { useState, useEffect } from "react";

function useAuth() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Check if user is authenticated on mount
  useEffect(() => {
    checkAuth();
  }, []);

  // Refresh token before expiration
  useEffect(() => {
    const interval = setInterval(() => {
      refreshToken();
    }, 14 * 60 * 1000); // Refresh every 14 minutes

    return () => clearInterval(interval);
  }, []);

  async function checkAuth() {
    try {
      const response = await fetch("/api/auth/me", {
        credentials: "include",
      });

      if (response.ok) {
        const userData = await response.json();
        setUser(userData);
      }
    } finally {
      setLoading(false);
    }
  }

  async function refreshToken() {
    try {
      await fetch("/api/auth/refresh", {
        method: "POST",
        credentials: "include",
      });
    } catch (error) {
      // Refresh failed - logout user
      setUser(null);
    }
  }

  async function logout() {
    await fetch("/api/auth/logout", {
      method: "POST",
      credentials: "include",
    });
    setUser(null);
  }

  return { user, loading, logout };
}
```

### Protected Routes

```jsx
import { Navigate } from "react-router-dom";

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return children;
}

// Usage
<Routes>
  <Route path="/login" element={<Login />} />
  <Route
    path="/dashboard"
    element={
      <ProtectedRoute>
        <Dashboard />
      </ProtectedRoute>
    }
  />
</Routes>;
```

## 5. Content Security Policy (CSP)

### Why CSP Matters

CSP prevents XSS even if you accidentally bypass React's protections.

**Without CSP:** Any injected script executes
**With CSP:** Only allowed scripts execute

### Configuring CSP (Vite Example)

**vite.config.js:**

```javascript
export default {
  server: {
    headers: {
      "Content-Security-Policy": [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'", // React inline styles
        "img-src 'self' data: https:",
        "font-src 'self' data:",
        "connect-src 'self' https://api.example.com",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
      ].join("; "),
    },
  },
};
```

**Production (Nginx):**

```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' https:; connect-src 'self' https://api.example.com; frame-ancestors 'none';" always;
```

### CSP with Third-Party Scripts

**Problem:** Google Analytics, Stripe, etc need script-src exceptions

**Solution 1: Nonce-based (Recommended)**

```html
<!-- Server generates unique nonce per request -->
<meta property="csp-nonce" content="random-nonce-123" />

<script
  nonce="random-nonce-123"
  src="https://www.googletagmanager.com/gtag/js"
></script>
```

**CSP header:**

```
script-src 'self' 'nonce-random-nonce-123';
```

**Solution 2: Hash-based**

```
script-src 'self' 'sha256-hash-of-script-content';
```

### Detecting CSP Violations

```javascript
// Add CSP violation reporting
"report-uri https://your-endpoint.com/csp-report";

// Or use report-to
"report-to csp-endpoint";

// Backend receives violation reports
app.post("/csp-report", (req, res) => {
  console.log("CSP Violation:", req.body);
  // Alert security team
  res.status(204).end();
});
```

## 6. CSRF Protection

### When You Need CSRF Protection

**CSRF attacks happen when:**

- Your API uses cookies for authentication
- Attacker tricks user into making authenticated request

**Example attack:**

```html
<!-- Attacker's website -->
<form action="https://yourapp.com/api/transfer" method="POST">
  <input name="to" value="attacker" />
  <input name="amount" value="1000" />
</form>
<script>
  document.forms[0].submit();
</script>
```

If user is logged into yourapp.com, cookies are sent automatically!

### Defense: CSRF Tokens

**Backend generates token:**

```javascript
// Express.js with csurf middleware
const csrf = require("csurf");
app.use(csrf({ cookie: true }));

app.get("/api/csrf-token", (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});
```

**React fetches and includes token:**

```jsx
function useCSRF() {
  const [csrfToken, setCSRFToken] = useState("");

  useEffect(() => {
    fetch("/api/csrf-token", { credentials: "include" })
      .then((r) => r.json())
      .then((data) => setCSRFToken(data.csrfToken));
  }, []);

  return csrfToken;
}

function TransferForm() {
  const csrfToken = useCSRF();

  async function handleSubmit(e) {
    e.preventDefault();
    const formData = new FormData(e.target);

    await fetch("/api/transfer", {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken, // Include token
      },
      body: JSON.stringify(Object.fromEntries(formData)),
    });
  }

  return (
    <form onSubmit={handleSubmit}>
      <input name="to" />
      <input name="amount" />
      <button type="submit">Transfer</button>
    </form>
  );
}
```

### Alternative: SameSite Cookies

**Modern browsers support SameSite:**

```javascript
// Backend sets SameSite cookie
res.cookie("token", jwt, {
  httpOnly: true,
  secure: true,
  sameSite: "strict", // or 'lax'
});
```

**SameSite=Strict:** Cookie never sent on cross-site requests (best protection, may break legitimate flows)
**SameSite=Lax:** Cookie sent on top-level navigation (GET only)

**Recommendation:** Use SameSite=Lax + CSRF tokens for state-changing requests.

## 7. Dependency Security

### npm audit

**Run regularly:**

```bash
# Check for vulnerabilities
npm audit

# Fix automatically (may break things)
npm audit fix

# View detailed report
npm audit --json
```

**CI/CD integration:**

```yaml
# GitHub Actions
- name: Security audit
  run: npm audit --audit-level=high
```

### Dependabot

**Enable in GitHub:**

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```

### Avoiding Malicious Packages

**Typosquatting defense:**

```bash
# Check package before installing
npm view package-name

# Verify publisher
npm view react dist.tarball

# Use package-lock.json (commit to git)
npm ci  # In CI/CD (uses lock file)
```

**Lock file prevents:**

- Malicious version bumps
- Supply chain attacks
- Dependency confusion

### SAST with Semgrep or Opengrep

Scan JavaScript/TypeScript code for security vulnerabilities.

**Semgrep vs Opengrep:**

- **[Semgrep](https://semgrep.dev/)** (Paid): AI-powered analysis reduces false positives significantly, better accuracy
- **[Opengrep](https://github.com/opengrep/opengrep)** (Free): Open-source fork, community rules, more false positives

**Recommendation:** Use Semgrep if budget allows (cleaner signal). Use Opengrep for cost-conscious teams.

**Installation:**

```bash
# Semgrep
pip install semgrep

# Opengrep (same CLI)
pip install opengrep
# or use Docker: docker pull opengrep/opengrep
```

**Run security scans:**

```bash
# Scan with security rules (works with both semgrep and opengrep)
semgrep --config=auto src/
# or: opengrep --config=auto src/

# CI-specific security rules
semgrep --config="p/security-audit" --config="p/react" src/

# JSON output for CI/CD
semgrep --config=auto --json -o results.json src/
```

**GitHub Actions Integration:**

```yaml
# .github/workflows/semgrep.yml
name: Semgrep

on:
  pull_request: {}
  push:
    branches: [main]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      # Option 1: Semgrep (paid, fewer false positives)
      - uses: semgrep/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/react
            p/javascript

      # Option 2: Opengrep (free, more false positives)
      # - run: pip install opengrep
      # - run: opengrep --config=auto src/
```

**What Semgrep/Opengrep Catches:**

- XSS vulnerabilities (dangerouslySetInnerHTML misuse)
- Hardcoded secrets in code
- SQL injection patterns
- Command injection
- Insecure randomness
- Path traversal vulnerabilities

### Secret Scanning with TruffleHog

Prevent API keys and secrets from being committed to git.

**Pre-commit Hook:**

```bash
# Install TruffleHog
pip install trufflehog

# Add to .git/hooks/pre-commit
#!/bin/bash
trufflehog filesystem . --fail --no-update
```

**Scan entire git history:**

```bash
# Scan all commits for secrets
trufflehog git file://. --since-commit HEAD~100

# Scan specific files
trufflehog filesystem src/ --fail
```

**GitHub Actions Integration:**

```yaml
# .github/workflows/secrets.yml
name: Secret Scan

on: [push, pull_request]

jobs:
  trufflehog:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0

      - name: TruffleHog
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD
```

**What TruffleHog Detects:**

- AWS keys (ACCESS_KEY_ID, SECRET_ACCESS_KEY)
- API keys (Stripe, Twilio, SendGrid, etc.)
- Database connection strings
- JWT secrets
- Private keys (RSA, SSH)
- OAuth tokens

**Prevention:**

```bash
# Add to .gitignore
.env
.env.local
.env.*.local
secrets/
*.pem
*.key
```

## 8. Environment Variables & Secrets

### What NOT to Put in Frontend

**NEVER in frontend code:**

- Database credentials
- API secret keys
- Private encryption keys
- OAuth client secrets

**Frontend code is PUBLIC** (users can view source).

### Safe Environment Variables

**Vite:**

```bash
# .env (NOT committed to git)
VITE_API_URL=https://api.example.com
VITE_STRIPE_PUBLIC_KEY=pk_test_...
```

```jsx
// Safe - public keys only
const apiUrl = import.meta.env.VITE_API_URL;
const stripeKey = import.meta.env.VITE_STRIPE_PUBLIC_KEY;
```

**Create React App:**

```bash
REACT_APP_API_URL=https://api.example.com
```

```jsx
const apiUrl = process.env.REACT_APP_API_URL;
```

### Runtime Configuration

**For sensitive config, fetch from backend:**

```jsx
function App() {
  const [config, setConfig] = useState(null);

  useEffect(() => {
    // Backend returns config based on user's auth level
    fetch("/api/config", { credentials: "include" })
      .then((r) => r.json())
      .then(setConfig);
  }, []);

  if (!config) return <div>Loading...</div>;

  return <Dashboard config={config} />;
}
```

## 9. Browser Security Headers

### Configure in Production

**Nginx:**

```nginx
# Prevent clickjacking
add_header X-Frame-Options "DENY" always;

# Prevent MIME sniffing
add_header X-Content-Type-Options "nosniff" always;

# Enable XSS filter (legacy browsers)
add_header X-XSS-Protection "1; mode=block" always;

# Enforce HTTPS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# Control referrer
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Permissions policy
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

**CloudFlare (Transform Rules):**

CloudFlare can add headers via Transform Rules in dashboard.

### Headers Explained

**X-Frame-Options: DENY**

- Prevents your site from being embedded in iframe (clickjacking protection)

**X-Content-Type-Options: nosniff**

- Prevents browser from MIME-sniffing (interpreting files as different types)

**Strict-Transport-Security (HSTS)**

- Forces HTTPS for all future requests
- Protects against downgrade attacks

**Referrer-Policy**

- Controls what referrer info is sent
- `strict-origin-when-cross-origin`: Only send origin on cross-origin

**Permissions-Policy**

- Disable unused browser features (camera, microphone, geolocation)

## 10. React-Specific Security Pitfalls

### Dangerous Props

**Never pass user input to dangerous props:**

```jsx
// DANGEROUS - href can be javascript:
<a href={userInput}>Click</a>;

// SAFE - Validate first
function SafeLink({ href }) {
  if (!href.startsWith("http://") && !href.startsWith("https://")) {
    return null;
  }
  return (
    <a href={href} rel="noopener noreferrer">
      Link
    </a>
  );
}
```

### Third-Party Components

**Audit before using:**

```bash
# Check downloads and github stars
npm view react-some-package

# Check for known vulnerabilities
npm audit
```

**Prefer:**

- Well-maintained packages (recent commits)
- High download counts (>100k/week)
- Official or trusted publishers

### React DevTools in Production

**Remove in production builds:**

```javascript
// Vite automatically excludes devtools in production

// Verify:
if (import.meta.env.PROD) {
  console.log("Production mode - DevTools disabled");
}
```

### Source Maps

**Don't expose in production:**

```javascript
// vite.config.js
export default {
  build: {
    sourcemap: false, // Don't generate source maps
  },
};
```

If you need source maps for error tracking:

```javascript
// Upload to error tracking service (Sentry, etc)
// Serve source maps only to authenticated error tracking service
sourcemap: "hidden"; // Generates maps but doesn't link in JS
```

## 11. Attack Scenarios Prevented

**XSS (Cross-Site Scripting)**

- Attack: Inject `<script>alert('xss')</script>` in user input
- Mitigated by: React auto-escaping, DOMPurify for rich content, CSP

**CSRF (Cross-Site Request Forgery)**

- Attack: Attacker tricks user into making authenticated request
- Mitigated by: CSRF tokens, SameSite cookies, verify Origin header

**Clickjacking**

- Attack: Embed your site in invisible iframe, trick user into clicking
- Mitigated by: X-Frame-Options: DENY, CSP frame-ancestors

**Dependency Vulnerabilities**

- Attack: Malicious npm package or vulnerable dependency
- Mitigated by: npm audit, Dependabot, package-lock.json

**Token Theft (XSS → Steal localStorage)**

- Attack: XSS steals JWT from localStorage
- Mitigated by: HttpOnly cookies (not accessible to JavaScript)

**MITM (Man-in-the-Middle)**

- Attack: Intercept HTTP traffic, steal tokens
- Mitigated by: HTTPS only, HSTS header

**Open Redirect**

- Attack: `<a href={userInput}>` redirects to phishing site
- Mitigated by: URL validation, allowlist domains

**Supply Chain Attack**

- Attack: Typosquatted package or compromised dependency
- Mitigated by: Verify packages, use lock file, Dependabot alerts

**Sensitive Data in Frontend**

- Attack: API keys in frontend code extracted by viewing source
- Mitigated by: Only public keys in frontend, secrets in backend

**Session Fixation**

- Attack: Attacker sets user's session ID
- Mitigated by: Regenerate session on login, HttpOnly secure cookies

## 12. References

### React Security

- [React Security Best Practices](https://react.dev/learn/security)
- [DOMPurify](https://github.com/cure53/DOMPurify)
- [React Security Docs](https://legacy.reactjs.org/docs/dom-elements.html#dangerouslysetinnerhtml)

### Web Security

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [SameSite Cookies](https://web.dev/samesite-cookies-explained/)

### Tools

- [npm audit](https://docs.npmjs.com/cli/v9/commands/npm-audit)
- [ESLint Security Plugin](https://github.com/nodesecurity/eslint-plugin-security)
- [Dependabot](https://github.com/dependabot)

### Authentication

- [Auth0](https://auth0.com/)
- [Clerk](https://clerk.dev/)
- [Firebase Auth](https://firebase.google.com/docs/auth)
- [AWS Cognito](https://aws.amazon.com/cognito/)

### Headers

- [SecurityHeaders.com](https://securityheaders.com/) - Test your headers
- [Mozilla Observatory](https://observatory.mozilla.org/) - Security scan
