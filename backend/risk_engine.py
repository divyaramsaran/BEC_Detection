from email_analysis import analyze_email
from sandbox import analyze_url
from login_behavior import analyze_login
 
# ===== WEIGHT CONFIGURATION =====
WEIGHTS = {
    'email_keywords' : 0.35,   # 35% weight
    'sandbox_result' : 0.40,   # 40% weight (highest — direct threat)
    'login_behavior' : 0.25    # 25% weight
}
 
# ===== RISK THRESHOLDS =====
THRESHOLD_HIGH   = 60
THRESHOLD_MEDIUM = 30
 
 
def normalize_score(score, max_val=100):
    """Clamp score between 0 and 100."""
    return max(0, min(int(score), 100))
 
 
def compute_risk_score(email_score=0, sandbox_score=0, login_score=0):
    """
    Weighted combination of all 3 module scores.
    Returns final risk score (0-100).
    """
    weighted = (
        email_score   * WEIGHTS['email_keywords'] +
        sandbox_score * WEIGHTS['sandbox_result'] +
        login_score   * WEIGHTS['login_behavior']
    )
    return normalize_score(weighted)
 
 
def determine_verdict(score):
    """Map score to verdict."""
    if score >= THRESHOLD_HIGH:
        return 'high'
    elif score >= THRESHOLD_MEDIUM:
        return 'medium'
    else:
        return 'safe'
 
 
def determine_action(verdict):
    """Map verdict to system action."""
    actions = {
        'high'  : 'Email quarantined — Receiver & Admin notified immediately',
        'medium': 'Warning sent to receiver — Email accessible with caution',
        'safe'  : 'Email delivered to inbox normally'
    }
    return actions[verdict]
 
 
# ===== MAIN RISK ENGINE =====
def run_risk_engine(email_data, login_data=None):
    """
    Full pipeline:
    1. Analyze email (keywords + ML)
    2. Analyze link via sandbox (if has_link)
    3. Analyze login behavior (if login_data provided)
    4. Combine into final risk score
    5. Return verdict + action + breakdown
 
    email_data : dict — sender, subject, body, has_link, link_url
    login_data : dict — log_entry, previous_entry (optional)
    """
 
    breakdown = {}
    all_reasons = []
 
    # ===== STEP 1: Email Analysis =====
    email_result = analyze_email(email_data)
    email_score  = email_result.get('risk_score', 0)
    breakdown['email'] = {
        'score'      : email_score,
        'verdict'    : email_result.get('verdict'),
        'keywords'   : email_result.get('keywords_found', []),
        'ml_predict' : email_result.get('ml_prediction'),
        'confidence' : email_result.get('ml_confidence')
    }
    all_reasons.extend(email_result.get('reasons', []))
 
    # ===== STEP 2: Sandbox Analysis (if link present) =====
    sandbox_score  = 0
    sandbox_result = None
    if email_data.get('has_link') and email_data.get('link_url'):
        sandbox_result = analyze_url(email_data['link_url'])
        raw_sandbox    = sandbox_result.get('threat_score', 0)
        sandbox_score  = normalize_score(raw_sandbox)
        breakdown['sandbox'] = {
            'score'          : sandbox_score,
            'verdict'        : sandbox_result.get('verdict'),
            'redirect_count' : sandbox_result.get('details', {}).get('redirect_count'),
            'domain_age'     : sandbox_result.get('details', {}).get('domain_age_days'),
            'https'          : sandbox_result.get('details', {}).get('https'),
            'known_malicious': sandbox_result.get('details', {}).get('known_malicious')
        }
        all_reasons.extend(sandbox_result.get('reasons', []))
    else:
        breakdown['sandbox'] = {'score': 0, 'verdict': 'not_checked'}
 
    # ===== STEP 3: Login Behavior Analysis =====
    login_score  = 0
    login_result = None
    if login_data:
        login_result = analyze_login(
            login_data.get('log_entry'),
            login_data.get('previous_entry')
        )
        login_score  = login_result.get('risk_score', 0)
        breakdown['login'] = {
            'score'  : login_score,
            'verdict': login_result.get('verdict'),
            'reasons': login_result.get('reasons', [])
        }
        all_reasons.extend(login_result.get('reasons', []))
    else:
        breakdown['login'] = {'score': 0, 'verdict': 'not_checked'}
 
    # ===== STEP 4: Compute Final Score =====
    final_score  = compute_risk_score(email_score, sandbox_score, login_score)
 
    # If any single module is critical — escalate
    if sandbox_score >= 80 or login_score >= 70:
        final_score = max(final_score, 65)
        all_reasons.append("Critical threat escalation from sandbox or login module")
 
    verdict = determine_verdict(final_score)
    action  = determine_action(verdict)
 
    return {
        'final_score' : final_score,
        'verdict'     : verdict,
        'action'      : action,
        'reasons'     : list(set(all_reasons)),   # deduplicate
        'breakdown'   : breakdown,
        'weights_used': WEIGHTS
    }
 
 
# ===== TEST =====
if __name__ == '__main__':
    print("=" * 50)
    print("TEST 1: High Risk Email with Malicious Link")
    print("=" * 50)
    result1 = run_risk_engine(
        email_data={
            'sender'  : 'ceo@fakebank.net',
            'subject' : 'Urgent Wire Transfer Required',
            'body'    : 'Please transfer funds immediately. Verify your account now or it will be suspended.',
            'has_link': True,
            'link_url': 'http://malicious-site.com/verify'
        },
        login_data={
            'log_entry': {
                'user_email' : 'john@company.com',
                'login_time' : '2024-01-15 11:00:00',
                'location'   : 'Russia',
                'device'     : 'Unknown-Device',
                'ip_address' : '185.220.101.5'
            },
            'previous_entry': {
                'user_email' : 'john@company.com',
                'login_time' : '2024-01-15 09:00:00',
                'location'   : 'Mumbai',
                'device'     : 'Windows-PC',
                'ip_address' : '192.168.1.1'
            }
        }
    )
    print(f"Final Score : {result1['final_score']}")
    print(f"Verdict     : {result1['verdict'].upper()}")
    print(f"Action      : {result1['action']}")
    print(f"Breakdown   : Email={result1['breakdown']['email']['score']} | "
          f"Sandbox={result1['breakdown']['sandbox']['score']} | "
          f"Login={result1['breakdown']['login']['score']}")
    print(f"Reasons     : {result1['reasons']}")
 
    print("\n" + "=" * 50)
    print("TEST 2: Safe Email")
    print("=" * 50)
    result2 = run_risk_engine(
        email_data={
            'sender'  : 'hr@company.com',
            'subject' : 'Team Meeting Tomorrow',
            'body'    : 'Please join us for the team meeting tomorrow at 10 AM.',
            'has_link': False,
            'link_url': None
        }
    )
    print(f"Final Score : {result2['final_score']}")
    print(f"Verdict     : {result2['verdict'].upper()}")
    print(f"Action      : {result2['action']}")
 
    print("\n" + "=" * 50)
    print("TEST 3: Medium Risk Email")
    print("=" * 50)
    result3 = run_risk_engine(
        email_data={
            'sender'  : 'deals@promosite.com',
            'subject' : 'Exclusive Weekend Offer',
            'body'    : 'Check out our exclusive deals. Limited time offer. Click now.',
            'has_link': True,
            'link_url': 'http://suspicious-link.net/sale'
        }
    )
    print(f"Final Score : {result3['final_score']}")
    print(f"Verdict     : {result3['verdict'].upper()}")
    print(f"Action      : {result3['action']}")
 