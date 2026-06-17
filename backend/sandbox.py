import requests
import whois
from datetime import datetime
from urllib.parse import urlparse, urljoin
import re
import urllib3
import socket
import ipaddress
import concurrent.futures

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===== SSRF PROTECTION HELPER =====
def is_private_ip(hostname):
    """Resolve hostname and check if it belongs to private or loopback ranges."""
    try:
        # If it's already an IP address, check directly
        try:
            ip = ipaddress.ip_address(hostname)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            pass

        # Resolve hostname to IPs
        addr_info = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return True
        return False
    except Exception:
        # Treat unresolved hostnames as unsafe
        return True


# ===== SAFE WHOIS QUERY WITH TIMEOUT =====
def get_whois_data(domain):
    """Execute whois query in a thread pool with a timeout to prevent hanging."""
    if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(whois.whois, domain)
        try:
            return future.result(timeout=4)
        except Exception:
            return None


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
    # Sanitize domain
    if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
        return -1

    # Method 1 — Check via RDAP (faster than WHOIS, try first)
    try:
        rdap_url = f"https://rdap.org/domain/{domain}"
        resp = requests.get(rdap_url, timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            for event in data.get('events', []):
                if event.get('eventAction') == 'registration':
                    date_str = event.get('eventDate', '')
                    creation = datetime.fromisoformat(date_str[:10])
                    age = (datetime.now() - creation).days
                    return max(0, age)
    except Exception:
        pass

    # Method 2 — WHOIS with timeout wrapper (slower fallback)
    try:
        w = get_whois_data(domain)
        if w:
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date and isinstance(creation_date, datetime):
                if creation_date.tzinfo is not None:
                    creation_date = creation_date.replace(tzinfo=None)
                age = (datetime.now() - creation_date).days
                return max(0, age)
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
    """Follow redirects and return count + final URL, with SSRF protection."""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        curr_url = url
        redirect_count = 0
        max_redirects = 5

        while redirect_count <= max_redirects:
            parsed = urlparse(curr_url)
            domain = parsed.netloc.split(':')[0]
            if not domain or is_private_ip(domain):
                return -1, url

            response = requests.get(
                curr_url, 
                timeout=4, 
                allow_redirects=False,
                headers=headers,
                verify=False
            )
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get('Location')
                if not location:
                    break
                if not location.startswith('http'):
                    curr_url = urljoin(curr_url, location)
                else:
                    curr_url = location
                redirect_count += 1
            else:
                break
        
        return redirect_count, curr_url
    except Exception:
        return -1, url
 
 
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