import re
from urllib.parse import urlparse

PHISHING_KEYWORDS = [
    'verify', 'account', 'login', 'update', 'urgent', 'security',
    'alert', 'important', 'action required', 'suspended', 'bank',
    'paypal', 'irs', 'password', 'credentials', 'click here'
]

def analyze_headers(headers):
    suspicious_flags = []

    from_header = re.search(r'From:.*?<([^>]+)>', headers, re.IGNORECASE)
    reply_to_header = re.search(r'Reply-To:.*?<([^>]+)>', headers, re.IGNORECASE)

    from_email = from_header.group(1) if from_header else None
    reply_email = reply_to_header.group(1) if reply_to_header else None

    if from_email:
        if '@' not in from_email or len(from_email.split('@')) != 2:
            suspicious_flags.append(f"Invalid From address: {from_email}")
    else:
        suspicious_flags.append("Missing 'From' header.")

    if reply_email:
        if '@' not in reply_email or len(reply_email.split('@')) != 2:
            suspicious_flags.append(f"Invalid Reply-To address: {reply_email}")
    else:
        suspicious_flags.append("Missing 'Reply-To' header.")

    if from_email and reply_email:
        from_domain = from_email.split('@')[-1].lower()
        reply_domain = reply_email.split('@')[-1].lower()
        if from_domain != reply_domain:
            suspicious_flags.append(f"Mismatched domains: {from_domain} vs {reply_domain}")

    if 'X-Mailer' not in headers and 'X-Originating-IP' not in headers:
        suspicious_flags.append("Missing important headers (possible spoofing)")

    return suspicious_flags

def analyze_links(text):
    suspicious_links = []

    url_pattern = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+")
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    trusted_domains = ['paypal.com', 'google.com', 'microsoft.com', 'apple.com', 'github.com']
    phishing_indicators = ['paypal-update', 'secure-paypal', 'login', 'account', 'verify']
    url_shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co']

    urls = url_pattern.findall(text)

    for url in urls:
        try:
            parsed = urlparse(url if url.startswith('http') else f'http://{url}')
            domain = parsed.netloc.lower()

            if any(ind in domain for ind in phishing_indicators):
                suspicious_links.append(f"Suspicious domain: {url}")
                continue

            if not any(domain.endswith(td) for td in trusted_domains):
                if parsed.scheme != 'https':
                    suspicious_links.append(f"Insecure (non-HTTPS) URL: {url}")
                if ip_pattern.search(domain):
                    suspicious_links.append(f"IP address in URL: {url}")
                    continue
                if any(short in domain for short in url_shorteners):
                    suspicious_links.append(f"URL shortener: {url}")
                    continue
                parts = domain.split('.')
                if len(parts) > 2 and parts[-2] not in ['com', 'net', 'org']:
                    suspicious_links.append(f"Suspicious subdomain: {url}")
        except Exception as e:
            suspicious_links.append(f"Error parsing URL {url}: {e}")

    return suspicious_links

def analyze_content(text):
    suspicious_content = []
    text_lower = text.lower()

    for keyword in PHISHING_KEYWORDS:
        if re.search(rf'\b{re.escape(keyword)}\b', text_lower):
            suspicious_content.append(f"Phishing keyword detected: {keyword}")

    return suspicious_content


