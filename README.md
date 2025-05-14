# Phishing Email Detection Script

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