import requests
import whois
from datetime import datetime
from urllib.parse import urlparse
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# ===== SUSPICIOUS KEYWORDS IN URL =====
SUSPICIOUS_KEYWORDS = [
    'verify', 'login', 'secure', 'account', 'update', 'confirm',
    'bank', 'paypal', 'password', 'reset', 'urgent', 'click',
    'free', 'winner', 'lucky', 'claim', 'prize', 'suspend'
]
 
MALICIOUS_DOMAINS = [
    'malicious-site.com', 'fakebank.net', 'phish.xyz',
    'suspicious-link.net', 'paypa1.com', 'fakecorp.biz'
]
 
 
def get_domain_age_days(domain):
    """Returns domain age in days using multiple methods."""
    # Method 1 — WHOIS
    try:
        import socket
        socket.setdefaulttimeout(3)
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date and isinstance(creation_date, datetime):
            return (datetime.now() - creation_date).days
    except Exception:
        pass

    # Method 2 — Check via RDAP (faster than WHOIS)
    try:
        rdap_url = f"https://rdap.org/domain/{domain}"
        resp = requests.get(rdap_url, timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            for event in data.get('events', []):
                if event.get('eventAction') == 'registration':
                    date_str = event.get('eventDate', '')
                    creation = datetime.fromisoformat(date_str[:10])
                    return (datetime.now() - creation).days
    except Exception:
        pass

    # Method 3 — Suspicious TLD fallback
    suspicious_tlds = ['.xyz', '.top', '.click', '.loan', '.gq', '.ml', '.cf', '.tk']
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        return 3  # treat as very new

    # Known old safe domains
    safe_domains = ['google.com', 'amazon.com', 'microsoft.com', 
                    'github.com', 'youtube.com', 'linkedin.com']
    if any(domain.endswith(d) for d in safe_domains):
        return 5000  # very old trusted domain

    return -1  # truly unknown
 
 
def check_redirects(url):
    """Follow redirects and return count + final URL."""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(
            url, 
            timeout=6, 
            allow_redirects=True,
            headers=headers,
            verify=False  # skip SSL errors
        )
        redirect_count = len(response.history)
        return redirect_count, response.url
    except requests.exceptions.SSLError:
        return 0, url
    except requests.exceptions.ConnectionError:
        return 0, url   # treat as 0 redirects — don't penalize
    except requests.exceptions.Timeout:
        return 0, url
    except Exception:
        return 0, url
 
 
def check_suspicious_keywords(url):
    """Check if URL contains suspicious keywords."""
    url_lower = url.lower()
    found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    return found
 
 
def check_https(url):
    """Check if URL uses HTTPS."""
    return url.startswith('https://')
 
 
def analyze_url(url):
    """
    Main sandbox function.
    Returns a dict with verdict, score, and details.
    """
    result = {
        'url': url,
        'verdict': 'safe',
        'threat_score': 0,
        'details': {},
        'reasons': []
    }
 
    parsed = urlparse(url)
    domain = parsed.netloc.replace('www.', '')
 
    # --- Check 1: Known malicious domain ---
    if domain in MALICIOUS_DOMAINS:
        result['threat_score'] += 60
        result['reasons'].append('Known malicious domain')
        result['details']['known_malicious'] = True
    else:
        result['details']['known_malicious'] = False
 
    # --- Check 2: Domain age ---
    age_days = get_domain_age_days(domain)
    result['details']['domain_age_days'] = age_days if age_days != -1 else 'Unknown'
    if age_days != -1 and age_days < 30:
        result['threat_score'] += 30
        result['reasons'].append(f'Very new domain ({age_days} days old)')
    elif age_days == -1:
        result['threat_score'] += 10
        result['reasons'].append('Domain age unknown')
 
    # --- Check 3: Redirects ---
    redirect_count, final_url = check_redirects(url)
    result['details']['redirect_count'] = redirect_count if redirect_count != -1 else 'Unreachable'
    result['details']['final_url'] = final_url
    if redirect_count > 2:
        result['threat_score'] += 20
        result['reasons'].append(f'Excessive redirects ({redirect_count})')
    elif redirect_count == -1:
        result['threat_score'] += 15
        result['reasons'].append('URL unreachable or timed out')
 
    # --- Check 4: Suspicious keywords ---
    keywords_found = check_suspicious_keywords(url)
    result['details']['suspicious_keywords'] = keywords_found
    if keywords_found:
        result['threat_score'] += len(keywords_found) * 5
        result['reasons'].append(f'Suspicious keywords: {", ".join(keywords_found)}')
 
    # --- Check 5: HTTPS check ---
    is_https = check_https(url)
    result['details']['https'] = is_https
    if not is_https:
        result['threat_score'] += 10
        result['reasons'].append('No HTTPS — insecure connection')
 
    # --- Final Verdict ---
    score = result['threat_score']
    if score >= 60:
        result['verdict'] = 'malicious'
    elif score >= 25:
        result['verdict'] = 'suspicious'
    else:
        result['verdict'] = 'safe'
 
    return result
 
 
# ===== TEST =====
if __name__ == '__main__':
    test_urls = [
        'http://malicious-site.com/verify',
        'http://amazon.com/orders',
        'http://suspicious-link.net/sale'
    ]
    for url in test_urls:
        r = analyze_url(url)
        print(f"\nURL: {r['url']}")
        print(f"Verdict: {r['verdict'].upper()}")
        print(f"Threat Score: {r['threat_score']}")
        print(f"Reasons: {r['reasons']}")
        print(f"Details: {r['details']}")