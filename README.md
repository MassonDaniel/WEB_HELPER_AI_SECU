# TP2-ARCHI — Security Header Scanner

https://easy-security-scribe.lovable.app

A web application that analyzes the security of a website (HTTP headers, cookies, exposed sensitive files, detected technologies and related CVEs), with an AI-generated summary report via the Gemini API.

This project runs entirely locally — no deployment required.

## Architecture

The project is split into two independent parts:

```
TP2-ARCHI/
├── Backend/          # Node.js / Express API
│   ├── index.js
│   ├── package.json
│   ├── .env.example
│   └── .env          (not versioned, contains secrets)
├── Frontend/          # Static web page (vanilla HTML/CSS/JS)
│   ├── index.html
│   ├── style.css
│   └── script.js
└── README.md
```

- **Backend**: exposes two routes (`GET /scan` and `POST /report`), analyzes a target URL and generates a report via the Gemini API.
- **Frontend**: a simple web page that calls the backend API and displays the results (score, categories, report).

The two parts communicate only over HTTP (fetch); there is no direct coupling between them.

## Features

- Checks HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)
- Analyzes cookie security attributes (Secure, HttpOnly, SameSite)
- Detects publicly exposed sensitive files/paths (`.env`, `.git/config`, etc.)
- Detects technologies in use (WordPress, jQuery, React, etc.) with matching CVE lookups (NVD API)
- Overall score and letter grade (A to F)
- Generates a French-language summary report via AI (Gemini), based strictly on the audit data

## Requirements

- Node.js (v18 or higher recommended)
- A free Gemini API key: https://aistudio.google.com/apikey

## Setup and run (local)

### 1. Clone the repository

```bash
git clone <repo-url>
cd TP2-ARCHI
```

### 2. Backend

```bash
cd Backend
npm install
cp .env.example .env
# edit .env and set GEMINI_API_KEY (get one for free at https://aistudio.google.com/apikey)
npm start
```
"(.venv) PS C:\Users\dmass\OneDrive\Bureau\ECE\TP2-ARCHI\Backend> npm start

> tp2-archi@1.0.0 start
> node index.js

◇ injected env (2) from .env // tip: ⌘ suppress logs { quiet: true }
API prête sur http://localhost:3000" It means the server starts and the API is ready.

The server starts on `http://localhost:3000`. Keep this terminal running.

### 3. Frontend

Open `Frontend/index.html` directly in a browser (double-click the file, or use the "Live Server" extension in VS Code).

By default, `Frontend/script.js` points to `http://localhost:3000`. If the backend runs on a different port, update the `API_URL` constant at the top of that file.

### 4. Usage

Enter a URL to scan (e.g. `https://example.com`) in the input field and run the analysis. Once the scan completes, you can generate an AI summary report from the results.

## Environment variables

See `Backend/.env.example` for the list of required variables. The actual `.env` file is never committed to the repository (see `.gitignore`) — each person running the project must provide their own Gemini API key.

## Known limitations

- Technology detection relies on simple regex patterns and is not exhaustive.
- CVE lookups depend on the public NVD API, which applies rate limiting without an API key.
- CORS is fully open (`*`) on the backend, which is acceptable for local/educational use but should be restricted in a production deployment.

## Author

Project built as part of the TP2 — Architecture course.
