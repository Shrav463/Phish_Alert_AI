# Gmail Scam Detector 🛡️

A Chrome extension that automatically scans emails when you open them in Gmail and warns you
if they are phishing, internship scams, visa fraud, or fake job offers. No copy‑pasting needed – the
banner appears right inside Gmail the moment you open a suspicious email.

---

## What problem does this solve?

Students receive realistic‑looking phishing emails every day – fake internship confirmations that ask
for passports, processing fees, or personal documents. Many fall for them because the emails look
legitimate. **Gmail Scam Detector catches these scams automatically** and explains why they’re
dangerous, so students don’t need to become security experts.

---

## How it works (in 4 steps)

1. **You open an email in Gmail** – the extension detects it silently.
2. **The email text is sent to a local backend** (FastAPI) that runs on your machine.
3. **The backend scores the email** using a hybrid approach:
   - A **local machine‑learning model** (TF‑IDF + Logistic Regression) for quick pattern detection.
   - An **optional AI provider** (Gemini/Groq/xAI/OpenAI) for a plain‑English explanation.
   - Both scores are blended into a final risk score.
4. **A color‑coded banner appears at the top of the email** – red for high risk, orange for medium,
   blue for low – with the score, a short explanation, and suspicious phrases.

Everything happens in under 2 seconds. You don’t click any extra button.

---

## Features

- ✅ **Zero‑click protection** – no manual pasting; works the instant you open an email.
- 🧠 **Hybrid detection** – ML model + generative AI for speed and clarity.
- 🎨 **Clean UI** – banner blends into Gmail; disappears when you navigate away.
- 🔄 **Fallback manual scan** – popup to paste any email text you want to check.
- 🔒 **Privacy‑friendly** – emails are only sent to your own backend, never stored.
- ⚙️ **Configurable AI provider** – easily switch between Gemini, Groq, xAI, or OpenAI.



## Tech stack

| Layer         | Technology                             |
|---------------|----------------------------------------|
| Frontend      | Chrome Extension (Manifest V3)         |
| Backend       | Python FastAPI                         |
| ML            | scikit‑learn (TF‑IDF + Logistic Regression) |
| AI (optional) | OpenAI‑compatible API (Groq/Gemini/xAI)|
| Storage       | chrome.storage.local (caching results) |

---

## Project structure
PhishAlertAI/
├── backend/
│ ├── main.py # FastAPI server
│ ├── train_model.py # ML training script
│ ├── requirements.txt
│ ├── model/ # Trained .joblib files
│ └── data/ # Dataset (emails.csv)
│
└── extension/
├── manifest.json # Extension config
├── content.js # Injected into Gmail, UI
├── background.js # API calls, cache, notifications
├── popup.html # Popup manual scan
├── popup.js
└── icons/ # Extension icons

