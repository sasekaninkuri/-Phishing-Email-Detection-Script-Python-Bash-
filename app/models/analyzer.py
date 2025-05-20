import re
from urllib.parse import urlparse
import tldextract
import ipaddress
import hashlib
import requests
from datetime import datetime
import whois
from bs4 import BeautifulSoup

class PhishingAnalyzer:
    def __init__(self):
        self.phishing_keywords = self._load_keywords()
        self.known_phishing_domains = set()
        self.suspicious_tlds = {'.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.gq'}
        self.load_known_phishing_domains()

    def _load_keywords(self):
        return [
            "verify your account", "update your information", "suspended account",
            "click here to login", "password expires", "urgent action required",
            "you've won", "reset your password", "confirm your identity",
            "account verification", "security alert", "immediate action required",
            "unauthorized login attempt", "limited time offer", "account suspension",
            "verify your identity", "billing problem", "payment failed",
            "invoice attached", "urgent payment required", "action required: your account",
            "account locked", "unusual login activity", "important security notice"
        ]

    def load_known_phishing_domains(self):
        try:
            response = requests.get("https://openphish.com/feed.txt")
            if response.status_code == 200:
                self.known_phishing_domains.update(response.text.splitlines())
        except:
            pass

    def extract_headers(self, email_content):
        header_part = email_content.split('\n\n')[0]
        headers = {}
        for line in header_part.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        return headers

    def analyze_headers(self, headers):
        flags = []
        score = 0

        if 'received-spf' not in headers:
            flags.append("Missing SPF record - possible spoofing")
            score += 1
        if 'authentication-results' not in headers:
            flags.append("Missing authentication results header")
            score += 1
        else:
            auth_results = headers['authentication-results'].lower()
            if 'dkim=pass' not in auth_results:
                flags.append("DKIM verification failed")
                score += 2
            if 'dmarc=pass' not in auth_results:
                flags.append("DMARC verification failed")
                score += 2

        if 'from' in headers and 'reply-to' in headers and headers['from'].lower() != headers['reply-to'].lower():
            flags.append("'From' and 'Reply-To' mismatch")
            score += 2

        if 'return-path' in headers and 'from' in headers and headers['return-path'].lower() != headers['from'].lower():
            flags.append("'Return-Path' differs from 'From' header")
            score += 1

        if 'from' in headers:
            domain = self.extract_domain(headers['from'])
            if domain and self.is_suspicious_domain(domain):
                flags.append(f"Suspicious sender domain: {domain}")
                score += 3

        return {'flags': flags, 'score': score}

    def extract_domain(self, email_or_url):
        if '@' in email_or_url:
            return email_or_url.split('@')[-1].lower()
        try:
            extracted = tldextract.extract(email_or_url)
            return f"{extracted.domain}.{extracted.suffix}".lower()
        except:
            return None

    def is_suspicious_domain(self, domain):
        if domain in self.known_phishing_domains:
            return True
        return any(domain.endswith(tld) for tld in self.suspicious_tlds)

    def analyze_email(self, email_content):
        headers = self.extract_headers(email_content)
        header_result = self.analyze_headers(headers)

        content_score = 0
        content_flags = []
        for keyword in self.phishing_keywords:
            if keyword in email_content.lower():
                content_flags.append(f"Keyword detected: {keyword}")
                content_score += 1

        total_score = header_result['score'] + content_score
        verdict = "Likely Phishing" if total_score >= 5 else "Possibly Safe"

        return {
            'headers': header_result['flags'],
            'links': [],  # Optional: extract and analyze links from content
            'content': content_flags,
            'score': total_score,
            'verdict': verdict
        }
