# Phishing Email Detection Script

 🐍 Phishing Email Detection Script (Python/Bash)

This Python script analyzes email content for potential phishing indicators by examining:
- Email headers for mismatches or spoofing attempts
- Links for suspicious patterns (IP addresses, URL shorteners, subdomain tricks)
- Content for common phishing keywords

## Features

1. **Header Analysis**:
   - Checks for mismatched "From" and "Reply-To" domains
   - Looks for missing important headers that might indicate spoofing

2. **Link Analysis**:
   - Detects URLs containing IP addresses instead of domains
   - Identifies URL shortening services
   - Flags suspicious subdomain structures (e.g., paypal.com.security-check.com)

3. **Content Analysis**:
   - Scans for common phishing keywords that create urgency or request action

## Usage

1. Save the email you want to analyze as a text file (including headers if possible)
2. Run the script: `python phish_detect.py email.txt`

## Limitations

This is a basic detector and may produce:
- False positives (legitimate emails flagged as suspicious)
- False negatives (sophisticated phishing emails not detected)

Always combine automated detection with manual inspection for important emails.


# 🛡️ Phishing Email and URL Detection Tool

A command-line tool built using the **Model-View-Controller (MVC)** design pattern to help detect phishing indicators in email content and URLs. Developed in Python by **Sasekani Maluleke**, Cybersecurity Analyst.

---

## 📁 Project Structure (MVC)

Phishing-Email-Detection-Script-Python-Bash/
├── app/
│ ├── controllers/
│ │ └── main_controller.py # Controls flow of the application
│ ├── models/
│ │ └── analyzer.py # Core logic for phishing detection
│ └── views/
│ └── console_view.py # Handles console input/output
├── main.py # Entry point of the application
├── README.md # Project documentation



---

## ⚙️ Features

- ✅ Detects **phishing keywords** in email content.
- ✅ Analyzes **email headers** for spoofing and inconsistencies.
- ✅ Identifies **malicious or suspicious URLs**, shorteners, IP-based links, and insecure protocols.
- ✅ Presents clear, color-coded analysis results.
- ✅ Follows **MVC architecture** for clean code separation.

---

## 🚀 Getting Started

### 🔧 Prerequisites



### 📦 Setup Instructions

```bash
# Clone the repo
git clone https://github.com/yourusername/Phishing-Email-Detection-Script-Python-Bash.git

cd Phishing-Email-Detection-Script-Python-Bash

# Set up virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Run the tool
export PYTHONPATH=$(pwd)
python main.py
🖥️ Usage
Once you run main.py, the tool will:

Display a banner and present options:

Analyze Email Content

Analyze a URL

Exit

Prompt for email or URL input.

Output a detailed phishing analysis report.

🧠 How It Works
Model (analyzer.py)
analyze_headers(headers): Checks for missing/mismatched headers like From and Reply-To.

analyze_links(text): Detects unsafe domains, IP addresses, shorteners, and HTTP links.

analyze_content(text): Scans for phishing-related keywords.

View (console_view.py)
Handles all user input and output.

Displays banners, prompts, and colored analysis results.

Controller (main_controller.py)
Drives application logic.

Manages flow based on user choices.

Integrates model and view components.

🧩 Example
vbnet
Copy
Edit
Choose an option:
1. Analyze Email Content
2. Analyze a URL
3. Exit
Enter 1, 2, or 3: 1

Paste the full email content below. Press Enter twice to finish:
From: "Bank Support" <support@fakebank.com>
Reply-To: <scammer@evil.com>
...
Output:

Suspicious Headers: Mismatched domains

Suspicious Links: Insecure HTTP URL

Phishing Keywords: "verify", "account", "urgent"

👨‍💻 Author
Sasekani Maluleke
Cybersecurity Analyst | Full Stack Developer