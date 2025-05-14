#!/usr/bin/env python3
import re
import sys
from urllib.parse import urlparse

# Common phishing keywords
PHISHING_KEYWORDS = [
    'verify', 'account', 'login', 'update', 'urgent', 'security',
    'alert', 'important', 'action required', 'suspended', 'bank',
    'paypal', 'irs', 'password', 'credentials', 'click here'
]

def analyze_headers(headers):
    """Analyze email headers for suspicious patterns"""
    suspicious_flags = []
    
    # Check for mismatched From and Reply-To headers
    from_header = re.search(r'From:.*?<([^>]+)>', headers, re.IGNORECASE)
    reply_to_header = re.search(r'Reply-To:.*?<([^>]+)>', headers, re.IGNORECASE)
    
    if from_header and reply_to_header:
        from_domain = from_header.group(1).split('@')[-1]
        reply_to_domain = reply_to_header.group(1).split('@')[-1]
        if from_domain.lower() != reply_to_domain.lower():
            suspicious_flags.append(f"Mismatched From/Reply-To domains: {from_domain} vs {reply_to_domain}")
    
    # Check for spoofed headers
    if 'X-Mailer' not in headers and 'X-Originating-IP' not in headers:
        suspicious_flags.append("Missing important headers (possible spoofing)")
    
    return suspicious_flags

def analyze_links(text):
    """Analyze text for suspicious links"""
    suspicious_links = []
    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    
    # Find all URLs in the text
    urls = url_pattern.findall(text)
    
    for url in urls:
        # Parse the URL
        try:
            parsed = urlparse(url if url.startswith('http') else f'http://{url}')
            domain = parsed.netloc
            
            # Check for IP address in URL
            if ip_pattern.search(domain):
                suspicious_links.append(f"URL contains IP address: {url}")
                continue
                
            # Check for URL shorteners
            shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 't.co']
            if any(s in domain for s in shorteners):
                suspicious_links.append(f"URL shortener detected: {url}")
                
            # Check for subdomain trickery (e.g., paypal.com.security-check.com)
            parts = domain.split('.')
            if len(parts) > 2 and parts[-2] != 'com' and parts[-2] != 'net' and parts[-2] != 'org':
                suspicious_links.append(f"Suspicious subdomain structure: {url}")
                
        except Exception as e:
            print(f"Error parsing URL {url}: {e}")
    
    return suspicious_links

def analyze_content(text):
    """Analyze email content for phishing keywords"""
    suspicious_content = []
    text_lower = text.lower()
    
    for keyword in PHISHING_KEYWORDS:
        if keyword in text_lower:
            suspicious_content.append(f"Phishing keyword detected: {keyword}")
    
    return suspicious_content

def main():
    if len(sys.argv) < 2:
        print("Usage: python phish_detect.py <email_file>")
        sys.exit(1)
    
    with open(sys.argv[1], 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    print("\n=== Phishing Email Analysis Report ===\n")
    
    # Analyze headers (if present)
    headers_end = content.find('\n\n')
    if headers_end != -1:
        headers = content[:headers_end]
        header_flags = analyze_headers(headers)
        if header_flags:
            print("Suspicious Headers Detected:")
            for flag in header_flags:
                print(f" - {flag}")
        else:
            print("No suspicious headers detected.")
    else:
        print("No email headers found in the file.")
    
    # Analyze links
    link_flags = analyze_links(content)
    if link_flags:
        print("\nSuspicious Links Detected:")
        for flag in link_flags:
            print(f" - {flag}")
    else:
        print("\nNo suspicious links detected.")
    
    # Analyze content
    content_flags = analyze_content(content)
    if content_flags:
        print("\nSuspicious Content Detected:")
        for flag in content_flags:
            print(f" - {flag}")
    else:
        print("\nNo suspicious content detected.")
    
    print("\n=== Analysis Complete ===\n")

if __name__ == "__main__":
    main()