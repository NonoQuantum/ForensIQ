# ForensIQ — Digital Forensic Analysis Platform

ForensIQ is a web platform built for law enforcement and legal teams to analyze exported chat files. A victim uploads their chat export, the AI reads it, detects harmful content (threats, blackmail, fraud), and generates an official forensic report — all in seconds.

---

## Live Demo

🔗 **Reporter Portal (for victims):** [https://forensiq-jcjm.onrender.com](https://forensiq-jcjm.onrender.com)

🔗 **Analyst Dashboard (for reviewers):** [https://forensiq-jcjm.onrender.com/analyst](https://forensiq-jcjm.onrender.com/analyst)

---

## The Problem

Victims of digital harassment, blackmail, or fraud often have chat conversations as their only evidence. There was no easy way to:
- Verify the file has not been tampered with
- Automatically detect harmful content in Arabic conversations
- Generate a report that can be submitted to authorities

ForensIQ solves all three.

---

## What It Does

1. **Victim uploads** their exported chat file (e.g. a WhatsApp `.txt` or `.zip` export) through a simple web form
2. **SHA-256 hash** is generated instantly — proving the file is untampered
3. **AI analyzes** the conversation and classifies it as: Threats / Blackmail / Fraud / Normal
4. **Analyst dashboard** shows all submitted cases in real time
5. **PDF report** is generated — formatted as a formal legal document ready for submission

---

## AI Model

We use **nuha-2.0**, an Arabic-specialized language model, because:
- Most victims in our target region communicate in Arabic dialects
- Standard models miss indirect threats, sarcasm, and Gulf/Saudi slang
- nuha-2.0 understands context and intent — not just keywords

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| AI | nuha-2.0 via OpenAI-compatible API |
| PDF Generation | fpdf2 |
| Frontend | HTML, CSS, JavaScript |
| Storage | JSON (cases.json) |

---

## Pages

| URL | Who uses it | What it does |
|---|---|---|
| `/` | Victim / Reporter | Upload the chat file |
| `/submitted` | Victim | Confirmation + case reference number |
| `/analyst` | Analyst | Dashboard of all submitted cases |
| `/analyst/<case_id>` | Analyst | Full forensic report for one case |
| `/download/<case_id>` | Analyst | Download PDF report |

---

## Team

**عدل** — Law Track, Hackathon 2026
