
# Highlander LookingGlass

### See Through the Scam.

A phishing URL scanner designed to help UC Riverside students recognize suspicious websites and avoid online scams.

Built for **Cutie Hack 2026**.

## Live Demo

**Website:** https://highlander-lookingglass.netlify.app

## About

College students regularly encounter suspicious emails, fake login pages, and phishing links.

Highlander LookingGlass helps users identify potential threats before visiting a website. Simply paste a URL into the scanner to receive a risk assessment and an explanation of any warning signs.

Our goal is to make phishing detection simple, accessible, and easy to understand.

## Features

- **URL Scanner** — Analyzes website links for suspicious patterns.
- **UCR Phishing Detection** — Identifies potential impersonations of official UCR websites.
- **Brand Impersonation Detection** — Checks for suspicious domains imitating popular services.
- **Google Safe Browsing** — Checks URLs against Google's database of known threats.
- **Risk Assessment** — Displays warnings and explains potential security risks.
- **Security Tips** — Helps users understand how to avoid phishing attacks.
- **Responsive Design** — Supports desktop and mobile devices.

## How It Works

1. Paste a website URL into the scanner.
2. Click **Check Link**.
3. Highlander LookingGlass analyzes the URL for suspicious characteristics.
4. A secure backend checks the URL using Google Safe Browsing.
5. The website displays the results and recommended precautions.

A URL with no detected warning signs is not guaranteed to be safe.

## Tech Stack

**Frontend**
- HTML
- CSS
- JavaScript

**Backend**
- Netlify Functions
- Google Safe Browsing API

**Tools**
- Visual Studio Code
- Git & GitHub
- Netlify

## Security

Google Safe Browsing requests are handled through a serverless Netlify Function.

The API key is stored as a private environment variable rather than being exposed in frontend code.

The scanner analyzes submitted URLs without automatically visiting them in the user's browser.

## Run Locally

1. Clone the repository:

   ```bash
   git clone https://github.com/rkrynz/highlander-lookingglass.git
   ```

2. Open the project in Visual Studio Code.

3. Open `index.html` using a local development server.

The basic URL analysis runs in the browser. Google Safe Browsing checks require the configured Netlify backend.

## Disclaimer

Highlander LookingGlass is an educational cybersecurity project.

It cannot guarantee that a website is safe or detect every phishing attempt. Users should always verify website addresses before entering passwords or personal information.

## Hackathon

**Event:** Cutie Hack 2026  
**Project:** Highlander LookingGlass  
**Theme:** Cybersecurity / Phishing Awareness

Made to help students see through the scam.
