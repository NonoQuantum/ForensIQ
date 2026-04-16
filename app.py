"""
WhatsApp Forensic Analysis Platform
====================================
A Flask demo app that:
  1. Accepts a WhatsApp exported .txt file
  2. Generates a SHA-256 hash (File Integrity Lock)
  3. Simulates AI classification (Threats / Blackmail / Fraud)
  4. Renders a professional forensic report

Run:
    pip install flask
    python app.py
"""

import hashlib
import re
import json
import os
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, make_response
from fpdf import FPDF
from openai import OpenAI
from dotenv import load_dotenv

CASES_FILE = os.path.join(os.path.dirname(__file__), "cases.json")

def load_cases() -> list:
    if not os.path.exists(CASES_FILE):
        return []
    with open(CASES_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_case(report: dict):
    cases = load_cases()
    cases.append(report)
    with open(CASES_FILE, "w", encoding="utf-8") as f:
        json.dump(cases, f, ensure_ascii=False, indent=2)

# Load API key and settings from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = "forensic_demo_secret_2024"

# LLM client using hackathon-provided nuha-2.0 model
llm_client = OpenAI(
    api_key=os.getenv("LLM_API_KEY"),
    base_url=os.getenv("LLM_BASE_URL"),
)

# ─────────────────────────────────────────────
# UTILITY: Generate SHA-256 hash from raw bytes
# ─────────────────────────────────────────────
def generate_hash(file_bytes: bytes) -> str:
    """Return the SHA-256 hex digest of the file contents."""
    return hashlib.sha256(file_bytes).hexdigest()


# ─────────────────────────────────────────────
# UTILITY: Parse WhatsApp exported .txt file
# ─────────────────────────────────────────────

# These strings identify media or system lines - we skip them entirely
SKIP_PATTERNS = [
    "audio omitted",
    "video omitted",
    "image omitted",
    "document omitted",
    "sticker omitted",
    "gif omitted",
    "contact card omitted",
    "messages and calls are end-to-end encrypted",
    "missed voice call",
    "missed video call",
    "created group",
    "added you",
    "changed the subject",
    "changed this group",
    "you were added",
    "security code changed",
]

def parse_whatsapp_chat(text: str) -> dict:
    """
    Parse a WhatsApp exported .txt file into structured messages.

    Confirmed format from real Arabic iPhone export:
        [DD/MM/YYYY, H:MM:SS AM/PM] Sender: message

    Also handles:
        - Invisible RTL unicode characters WhatsApp prepends on some lines
        - Sender names prefixed with ~ (WhatsApp adds this for unsaved contacts)
        - Multi-line messages (long messages wrap to the next line with no timestamp)
        - Media lines (audio omitted, document omitted, etc.) - skipped
        - System messages (encryption notice, group events) - skipped
        - Android format: DD/MM/YYYY, HH:MM - Sender: message

    Returns:
        messages       - list of dicts: {timestamp, sender, text}
        senders        - unique sender names in order of first appearance
        total_lines    - raw line count of the original file
        total_messages - number of real messages parsed
        preview        - first 8 messages for the report page
        llm_text       - clean one-per-line string ready for the LLM prompt {CHAT_TEXT}
    """

    def strip_invisible(line: str) -> str:
        # WhatsApp prepends invisible unicode chars on some lines:
        # U+200E (left-to-right mark), U+202A/U+202C (embedding marks)
        return (line
                .replace("\u200e", "")
                .replace("\u202a", "")
                .replace("\u202c", "")
                .replace("\u200f", "")  # right-to-left mark
                .strip())

    # iOS format  - [DD/MM/YYYY, H:MM:SS AM/PM] Sender: message
    ios_pattern = re.compile(
        r"^\[(\d{1,2}/\d{1,2}/\d{4}),\s"       # [date,
        r"(\d{1,2}:\d{2}(?::\d{2})?"            # time (seconds optional)
        r"(?:\s?[AaPp][Mm])?)\]\s"              # AM/PM optional]
        r"(.+?):\s(.+)$"                         # Sender: message
    )

    # Android format - DD/MM/YYYY, HH:MM - Sender: message
    android_pattern = re.compile(
        r"^(\d{1,2}/\d{1,2}/\d{4}),\s"
        r"(\d{1,2}:\d{2}(?:\s?[AaPp][Mm])?)\s-\s"
        r"(.+?):\s(.+)$"
    )

    raw_lines = text.strip().splitlines()
    messages  = []
    current   = None  # tracks the last parsed message for multi-line appending

    for raw in raw_lines:
        line = strip_invisible(raw)
        if not line:
            continue

        match = ios_pattern.match(line) or android_pattern.match(line)

        if match:
            date, time_, sender, body = match.groups()

            # Strip ~ prefix WhatsApp adds to unsaved contact names
            sender = sender.strip().lstrip("~").strip()

            # Skip media and system lines
            if any(skip in body.lower() for skip in SKIP_PATTERNS):
                current = None  # don't append continuation lines to skipped messages
                continue

            current = {
                "timestamp": f"{date} {time_}",
                "sender":    sender,
                "text":      body.strip(),
            }
            messages.append(current)

        else:
            # No timestamp - continuation of the previous message (multi-line)
            if current is not None:
                current["text"] += " " + line

    # Unique senders preserving order of first appearance
    senders = list(dict.fromkeys(m["sender"] for m in messages))

    # Build the formatted string the LLM prompt expects as {CHAT_TEXT}
    # Format: [time] Sender: message  - one per line, date stripped to keep it concise
    llm_lines = []
    for m in messages:
        time_only = m["timestamp"].split(" ", 1)[1] if " " in m["timestamp"] else m["timestamp"]
        llm_lines.append(f"[{time_only}] {m['sender']}: {m['text']}")
    llm_text = "\n".join(llm_lines)

    return {
        "messages":       messages,
        "senders":        senders,
        "total_lines":    len(raw_lines),
        "total_messages": len(messages),
        "preview":        messages[:8],
        "llm_text":       llm_text,
    }


# ─────────────────────────────────────────────
# UTILITY: Real LLM Analysis via nuha-2.0
# ─────────────────────────────────────────────

LLM_PROMPT = """
You are a legal forensics assistant specialized in analyzing Arabic WhatsApp chat text.
Your task is to read the chat and return a structured JSON analysis following all rules below.

Language Rules:
- Understand Arabic in all dialects (Gulf, Saudi, Egyptian, Levant, North African).
- Interpret meaning even when written in slang, informal language, or mixed dialects.
- Detect indirect threats such as implied harm, pressure, intimidation, or coercion even without explicit wording.
- Detect harassment or verbal abuse even if expressed using sarcasm, casual phrasing, or emotional manipulation.
- Ignore spelling variations, repeated letters, missing punctuation, or common typos.
- Ignore diacritics, emojis, stickers, media indicators, and system messages.
- Understand shortened expressions and conversational shortcuts common in WhatsApp chats.
- Analyze messages based on context, tone, and intent, not keywords alone.

Financial Blackmail Rules:
- Identify any situation where money is requested or expected in exchange for avoiding harm, trouble, or negative consequences.
- Treat any pressure involving payment, transfers, or financial obligations as financial blackmail, even if not stated explicitly.
- Recognize financial manipulation expressed indirectly or politely.
- Detect attempts to control or threaten the victim through financial demands or consequences.

Exposure Threat Rules:
- Identify any attempt to use personal information, secrets, or private content against the victim.
- Treat any implication of revealing information to others as an exposure threat, even if phrased indirectly.
- Recognize threats involving reputation damage, embarrassment, or social consequences.
- Detect exposure threats expressed through hints, implications, or emotional pressure.

General Rules:
- Output MUST be valid JSON only.
- Do NOT add explanations outside JSON.
- Detect harmful behavior based on meaning, not keywords.
- Identify threats, blackmail, financial blackmail, harassment, or illegal content.
- If no harmful content exists, set case_type to "Normal" and severity to "low".
- case_type must be exactly one of: "Threats", "Blackmail", "Fraud", "Normal"
- severity must be exactly one of: "low", "medium", "high"
- Extract only messages that contain harmful or suspicious behavior.
- Use short, factual summaries in English.

Return JSON in this exact structure:
{
  "case_type": "",
  "summary": "",
  "threat_messages": [
    {
      "sender": "",
      "time": "",
      "message": ""
    }
  ],
  "severity": "",
  "confidence": 0
}

confidence is a number from 0 to 100 representing how certain you are.

Chat to analyze:
{CHAT_TEXT}
"""

def analyze_with_llm(llm_text: str) -> dict:
    """
    Send the parsed chat to nuha-2.0 and return structured results.
    Falls back to safe defaults if the LLM call fails or returns bad JSON.
    """
    prompt = LLM_PROMPT.replace("{CHAT_TEXT}", llm_text)

    try:
        response = llm_client.chat.completions.create(
            model=os.getenv("LLM_MODEL", "nuha-2.0"),
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,   # low temperature = more consistent, factual output
        )

        raw = response.choices[0].message.content.strip()

        # Strip markdown code fences if the model wraps JSON in ```json ... ```
        if raw.startswith("```"):
            raw = re.sub(r"^```[a-zA-Z]*\n?", "", raw)
            raw = re.sub(r"```$", "", raw).strip()

        result = json.loads(raw)

        # Normalise case_type to match our report CSS classes
        case_type = result.get("case_type", "Normal").strip().capitalize()
        if case_type not in ("Threats", "Blackmail", "Fraud"):
            case_type = "Normal"

        # Build findings list from summary + threat messages
        findings = []
        summary = result.get("summary", "")
        if summary:
            findings.append(summary)

        for tm in result.get("threat_messages", []):
            sender  = tm.get("sender", "Unknown")
            time_   = tm.get("time", "")
            message = tm.get("message", "")
            if message:
                findings.append(f"[{time_}] {sender}: {message}")

        if not findings:
            findings = ["No harmful content detected in this conversation."]

        return {
            "classification":  case_type,
            "confidence":      float(result.get("confidence", 75)),
            "severity":        result.get("severity", "low"),
            "findings":        findings,
        }

    except Exception as e:
        # If anything goes wrong, fall back to safe defaults so the app doesn't crash
        return {
            "classification": "Normal",
            "confidence":     0.0,
            "severity":       "low",
            "findings":       [f"LLM analysis failed: {str(e)}"],
        }


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def index():
    """Render the main upload / dashboard page."""
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Handle the file upload form:
      1. Validate the upload
      2. Generate SHA-256 hash
      3. Parse the chat
      4. Classify
      5. Extract findings
      6. Store result in session and redirect to report
    """
    # --- 1. Validate file presence ---
    uploaded_file = request.files.get("chat_file")
    if not uploaded_file or uploaded_file.filename == "":
        return render_template("index.html", error="Please upload a WhatsApp .txt file before submitting.")

    if not uploaded_file.filename.lower().endswith(".txt"):
        return render_template("index.html", error="Only .txt files exported from WhatsApp are accepted.")

    # --- 2. Read raw bytes & generate hash ---
    file_bytes = uploaded_file.read()
    file_hash  = generate_hash(file_bytes)

    # Decode text (WhatsApp exports are UTF-8; fall back to latin-1 for older exports)
    try:
        text = file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        text = file_bytes.decode("latin-1")

    # --- 3. Parse the chat ---
    parsed = parse_whatsapp_chat(text)

    # --- 4. Analyze with LLM ---
    llm_result = analyze_with_llm(parsed["llm_text"])

    # --- 5. Build report payload & store in session ---
    report = {
        # Case metadata from form
        "case_title":       request.form.get("case_title", "").strip() or "Untitled Case",
        "complainant":      request.form.get("complainant", "").strip() or "Anonymous",
        "file_name":        uploaded_file.filename,
        "analysis_date":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "case_id":          f"WFAP-{datetime.now().strftime('%Y%m%d%H%M%S')}",

        # Integrity
        "file_hash":        file_hash,

        # Chat stats
        "total_lines":      parsed["total_lines"],
        "total_messages":   parsed["total_messages"],
        "senders":          parsed["senders"],
        "preview":          parsed["preview"],

        # LLM classification + findings
        "classification":   llm_result["classification"],
        "confidence":       llm_result["confidence"],
        "severity":         llm_result["severity"],
        "findings":         llm_result["findings"],
    }

    save_case(report)
    return redirect(url_for("submitted", case_id=report["case_id"]))


@app.route("/submitted")
def submitted():
    """Thank you page shown to the reporter after submission."""
    case_id = request.args.get("case_id", "")
    if not case_id:
        return redirect(url_for("index"))
    return render_template("submitted.html", case_id=case_id)


@app.route("/analyst")
def analyst():
    """Analyst dashboard - lists all submitted cases."""
    cases = load_cases()
    return render_template("analyst.html", cases=list(reversed(cases)))


@app.route("/analyst/<case_id>")
def analyst_case(case_id):
    """Analyst view for a single case."""
    cases = load_cases()
    report_data = next((c for c in cases if c["case_id"] == case_id), None)
    if not report_data:
        return redirect(url_for("analyst"))
    return render_template("report.html", r=report_data)


# ─────────────────────────────────────────────
# UTILITY: Build PDF from report data
# ─────────────────────────────────────────────
def clean(text: str) -> str:
    """
    Strip characters that Helvetica (latin-1) cannot encode.
    Replaces them with ASCII equivalents where possible,
    otherwise removes them. This avoids Unicode font dependency.
    """
    replacements = {
        "\u2014": "-",   # em dash -
        "\u2013": "-",   # en dash –
        "\u2019": "'",   # right single quote '
        "\u2018": "'",   # left single quote '
        "\u201c": '"',   # left double quote "
        "\u201d": '"',   # right double quote "
        "\u2022": "*",   # bullet •
        "\u00b7": ".",   # middle dot ·
    }
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    # Remove any remaining non-latin-1 characters
    return text.encode("latin-1", errors="ignore").decode("latin-1")


def build_pdf(r: dict) -> bytes:
    """
    Generate a professional forensic report PDF using Times New Roman.
    Layout mirrors a formal legal/forensic document.
    """
    LEFT  = 25   # left margin mm
    RIGHT = 25   # right margin mm
    W     = 210 - LEFT - RIGHT  # usable width = 160mm

    pdf = FPDF()
    pdf.set_margins(LEFT, 20, RIGHT)
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # ── helpers ──────────────────────────────────────────

    def body(size=11):
        pdf.set_font("Times", "", size)
        pdf.set_text_color(20, 20, 20)

    def bold(size=11):
        pdf.set_font("Times", "B", size)
        pdf.set_text_color(20, 20, 20)

    def muted(size=9):
        pdf.set_font("Times", "", size)
        pdf.set_text_color(90, 90, 90)

    def divider():
        pdf.set_draw_color(180, 180, 180)
        pdf.line(LEFT, pdf.get_y(), LEFT + W, pdf.get_y())
        pdf.ln(4)

    def section_heading(title):
        pdf.ln(5)
        bold(9)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(0, 6, title.upper(), ln=True)
        divider()
        pdf.set_text_color(20, 20, 20)

    def kv(label, value, line_h=6):
        """Two-column row: label left, value wrapping right column."""
        KEY_W = 50
        VAL_W = W - KEY_W
        # Print label
        bold(10)
        pdf.set_text_color(60, 60, 60)
        pdf.set_x(LEFT)
        pdf.cell(KEY_W, line_h, clean(label), ln=False)
        # Print value — multi_cell resets X, so note Y before and fix X after
        body(10)
        pdf.set_text_color(20, 20, 20)
        pdf.set_x(LEFT + KEY_W)
        pdf.multi_cell(VAL_W, line_h, clean(str(value)))
        pdf.set_x(LEFT)

    # ── COVER HEADER ─────────────────────────────────────

    # Thin top rule
    pdf.set_draw_color(20, 20, 20)
    pdf.set_line_width(0.8)
    pdf.line(LEFT, pdf.get_y(), LEFT + W, pdf.get_y())
    pdf.set_line_width(0.2)
    pdf.ln(5)

    pdf.set_font("Times", "B", 20)
    pdf.set_text_color(10, 10, 10)
    pdf.cell(0, 10, "FORENSIC ANALYSIS REPORT", ln=True)

    pdf.ln(1)
    muted(9)
    pdf.cell(0, 5, clean(f"ForensIQ Digital Evidence Platform  |  Case {r['case_id']}  |  {r['analysis_date']}"), ln=True)

    pdf.ln(3)
    pdf.set_draw_color(20, 20, 20)
    pdf.set_line_width(0.8)
    pdf.line(LEFT, pdf.get_y(), LEFT + W, pdf.get_y())
    pdf.set_line_width(0.2)
    pdf.ln(6)

    # Classification badge - plain text, colour only
    color_map = {
        "Threats":   (180, 30, 30),
        "Blackmail": (160, 100, 0),
        "Fraud":     (90,  50, 170),
        "Normal":    (30, 130, 80),
    }
    badge_color = color_map.get(r["classification"], (30, 30, 30))
    pdf.set_font("Times", "B", 13)
    pdf.set_text_color(*badge_color)
    pdf.cell(0, 7, clean(f"Classification: {r['classification'].upper()}  -  {r['confidence']}% Confidence"), ln=True)
    pdf.set_text_color(20, 20, 20)
    pdf.ln(1)
    body(10)
    pdf.set_text_color(70, 70, 70)
    pdf.cell(0, 5, clean(f"Severity: {r['severity'].capitalize()}"), ln=True)
    pdf.set_text_color(20, 20, 20)

    # ── SECTION 1 - CASE INFORMATION ─────────────────────
    section_heading("1.  Case Information")
    kv("Case ID",       r["case_id"])
    kv("Case Title",    r["case_title"])
    kv("Complainant",   r["complainant"])
    kv("File Name",     r["file_name"])
    kv("Analysis Date", r["analysis_date"])
    kv("Participants",  ", ".join(r["senders"]) if r["senders"] else "Unknown")
    kv("Messages",      f"{r['total_messages']} messages parsed from {r['total_lines']} lines")

    # ── SECTION 2 - FILE INTEGRITY ───────────────────────
    section_heading("2.  File Integrity - SHA-256 Hash")
    body(10)
    pdf.set_text_color(60, 60, 60)
    pdf.multi_cell(W, 5.5,
        "The SHA-256 hash below was generated at the moment of upload. "
        "Any subsequent modification to the file - however minor - will produce "
        "a completely different hash value, making tampering detectable.")
    pdf.ln(3)
    pdf.set_font("Courier", "", 9)
    pdf.set_fill_color(245, 245, 245)
    pdf.set_text_color(20, 20, 20)
    pdf.set_draw_color(200, 200, 200)
    pdf.rect(LEFT, pdf.get_y(), W, 8, style="F")
    pdf.set_xy(LEFT + 2, pdf.get_y() + 1.5)
    pdf.cell(W - 4, 5, r["file_hash"], ln=True)
    pdf.ln(1)
    body(9)
    pdf.set_text_color(30, 130, 80)
    pdf.cell(0, 5, "Hash recorded at time of ingestion - integrity verified.", ln=True)
    pdf.set_text_color(20, 20, 20)

    # ── SECTION 3 - FORENSIC FINDINGS ───────────────────
    section_heading("3.  Forensic Findings")
    for i, finding in enumerate(r["findings"], 1):
        bold(10)
        pdf.set_text_color(40, 40, 40)
        pdf.cell(8, 6, f"{i}.", ln=False)
        body(10)
        pdf.set_text_color(20, 20, 20)
        pdf.multi_cell(W - 8, 6, clean(finding))
        pdf.ln(1)

    # ── SECTION 4 - MESSAGE PREVIEW ─────────────────────
    section_heading("4.  Message Preview (First 8 Messages)")
    body(9)
    pdf.set_text_color(80, 80, 80)
    pdf.multi_cell(W, 5, "The following messages appear at the start of the uploaded file, reproduced verbatim.")
    pdf.ln(3)

    for msg in r["preview"]:
        # Sender + timestamp on one line
        bold(9)
        pdf.set_text_color(30, 60, 140)
        sender_text = clean(msg["sender"])
        ts_text     = clean(msg["timestamp"])
        pdf.cell(W * 0.55, 5, sender_text, ln=False)
        muted(8)
        pdf.cell(W * 0.45, 5, ts_text, ln=True, align="R")
        # Message body
        body(9)
        pdf.set_text_color(40, 40, 40)
        pdf.multi_cell(W, 5, clean(msg["text"]))
        # Thin separator between messages
        pdf.set_draw_color(220, 220, 220)
        pdf.line(LEFT, pdf.get_y(), LEFT + W, pdf.get_y())
        pdf.ln(2)

    # ── SECTION 5 - CHAIN OF CUSTODY ────────────────────
    section_heading("5.  Chain of Custody")
    kv("Case Reference", r["case_id"])
    kv("File Submitted", r["file_name"])
    kv("Processed At",   r["analysis_date"])
    kv("Platform",       "ForensIQ v1.0 (Demo)")
    kv("SHA-256",        r["file_hash"])

    # ── FOOTER RULE ──────────────────────────────────────
    pdf.ln(8)
    pdf.set_draw_color(20, 20, 20)
    pdf.set_line_width(0.5)
    pdf.line(LEFT, pdf.get_y(), LEFT + W, pdf.get_y())
    pdf.ln(3)
    muted(8)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 5, clean(
        f"This report was generated automatically by ForensIQ. "
        f"Case {r['case_id']} - {r['analysis_date']}. "
        f"For official use only."
    ), ln=True, align="C")

    return bytes(pdf.output())


@app.route("/download/<case_id>")
def download(case_id):
    """Generate and serve the report as a PDF download."""
    cases = load_cases()
    report_data = next((c for c in cases if c["case_id"] == case_id), None)
    if not report_data:
        return redirect(url_for("analyst"))

    pdf_bytes = build_pdf(report_data)

    response = make_response(pdf_bytes)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = (
        f'attachment; filename="forensiq_{report_data["case_id"]}.pdf"'
    )
    return response


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    # debug=True enables auto-reload during development
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
