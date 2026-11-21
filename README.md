
# Highlander LookingGlass

**See Through the Scam.**

A phishing URL scanner built to help UC Riverside students identify suspicious links and avoid online scams.

Created for **Cutie Hack 2026**.

[Live Website](https://highlander-lookingglass.netlify.app) · [GitHub Repository](https://github.com/rkrynz/highlander-lookingglass)

---

## About

Highlander LookingGlass is a cybersecurity tool designed to make phishing detection simple and accessible.

Users can paste a website link into the scanner to check for suspicious patterns, potential impersonation attempts, and known security threats.

The goal is to help students recognize phishing attempts before entering personal information or passwords.

---

## Features

- **URL Scanner** — Checks links for suspicious patterns.
- **UCR Impersonation Detection** — Identifies websites pretending to be official UCR pages.
- **Brand Impersonation Detection** — Detects suspicious domains imitating popular services.
- **Google Safe Browsing** — Checks URLs against Google's database of known threats.
- **Risk Assessment** — Explains warning signs and provides safety recommendations.
- **Responsive Design** — Works on desktop and mobile devices.

---

## Tech Stack

### Frontend

<p>
  <img src="https://skillicons.dev/icons?i=html,css,js" alt="HTML, CSS, JavaScript" />
</p>

### Backend

<p>
  <img src="https://skillicons.dev/icons?i=netlify,googlecloud" alt="Netlify, Google Cloud" />
</p>

Netlify Functions · Google Safe Browsing API

### Tools

<p>
  <img src="https://skillicons.dev/icons?i=vscode,git,github" alt="VS Code, Git, GitHub" />
</p>

---

## How It Works

1. Paste a website URL into the scanner.
2. Click **Check Link**.
3. The scanner analyzes the URL for suspicious characteristics.
4. A Netlify Function checks the URL using Google Safe Browsing.
5. The scanner displays its findings and recommended precautions.

**Note:** A link with no detected warning signs is not guaranteed to be safe.

---

## Getting Started

Clone the repository:

```bash
git clone https://github.com/rkrynz/highlander-lookingglass.git
```

Open the project in Visual Studio Code and launch `index.html` using a local development server.

Basic URL checks run in the browser. Google Safe Browsing checks require the Netlify backend and a configured API key.

---

## Security

- Google Safe Browsing requests run through a serverless Netlify Function.
- The API key is stored securely as an environment variable.
- URLs are analyzed without automatically opening them in the user's browser.
- Results include explanations to help users recognize potential threats.

---

## Disclaimer

Highlander LookingGlass is an educational cybersecurity project and cannot guarantee that a website is safe.

Always verify links before entering passwords, personal information, or other sensitive data.

---

## Hackathon

**Cutie Hack 2026**  
University of California, Riverside

Built to help students **see through the scam**.
