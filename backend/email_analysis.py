import pandas as pd
import numpy as np
import re
import joblib
import os
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sandbox import analyze_url
 
# ===== SUSPICIOUS KEYWORDS =====
SUSPICIOUS_KEYWORDS = [
    'urgent', 'verify', 'account', 'suspended', 'click here', 'confirm',
    'password', 'reset', 'wire transfer', 'immediate', 'bank', 'paypal',
    'login', 'secure', 'update', 'free', 'winner', 'prize', 'claim',
    'act now', 'limited time', 'invoice', 'payment', 'credential',
    'unusual activity', 'compromise', 'suspended', 'unusual', 'access'
]
 
# ===== PREPROCESS TEXT =====
def preprocess_text(text):
    """Clean and normalize email text."""
    text = str(text).lower()
    text = re.sub(r'http\S+', ' url_token ', text)   # replace URLs
    text = re.sub(r'\S+@\S+', ' email_token ', text)  # replace emails
    text = re.sub(r'[^a-z\s]', ' ', text)             # remove special chars
    text = re.sub(r'\s+', ' ', text).strip()
    return text
 
 
def count_suspicious_keywords(text):
    """Count how many suspicious keywords appear in text."""
    text_lower = text.lower()
    found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text_lower]
    return len(found), found
 
 
def keyword_score(count):
    """Convert keyword count to risk score contribution."""
    if count == 0:
        return 0
    elif count <= 2:
        return 20
    elif count <= 4:
        return 35
    else:
        return 50
 
 
# ===== TRAIN MODEL =====
import os
def train_email_model(csv_path=None):
    if csv_path is None:
        base = os.path.dirname(os.path.abspath(__file__))
        csv_path = os.path.join(base, '..', 'data', 'emails.csv')
    """Train TF-IDF + Logistic Regression on email dataset."""
    df = pd.read_csv(csv_path)
 
    # Combine subject + body for NLP
    df['text'] = df['subject'].fillna('') + ' ' + df['body'].fillna('')
    df['text'] = df['text'].apply(preprocess_text)
 
    X = df['text']
    y = df['label']  # safe / medium / high
 
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
 
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=5000,
            stop_words='english'
        )),
        ('clf', LogisticRegression(
            max_iter=1000,
            class_weight='balanced',
            random_state=42
        ))
    ])
 
    model = pipeline.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("=== Email Model Evaluation ===")
    print(classification_report(y_test, y_pred, zero_division=0))
 
    base = os.path.dirname(os.path.abspath(__file__))
    models_dir = os.path.join(base, '..', 'models')
    os.makedirs(models_dir, exist_ok=True)
    joblib.dump(pipeline, os.path.join(models_dir, 'email_model.pkl'))

    print("Email model saved to models/email_model.pkl")
    return pipeline
 
 
# ===== ANALYZE EMAIL =====
def analyze_email(email_data):
    """
    Main function — analyze a single email.
 
    email_data: dict with keys:
        sender, subject, body, has_link (bool), link_url (str or None)
 
    Returns: dict with verdict, risk_score, reasons, action
    """
    subject = email_data.get('subject', '')
    body    = email_data.get('body', '')
    sender  = email_data.get('sender', '')
    has_link = email_data.get('has_link', False)
    link_url = email_data.get('link_url', None)
 
    combined_text = subject + ' ' + body
    risk_score = 0
    reasons = []
 
    # --- Factor 1: Suspicious Keywords ---
    kw_count, kw_found = count_suspicious_keywords(combined_text)
    kw_contribution = keyword_score(kw_count)
    risk_score += kw_contribution
    if kw_found:
        reasons.append(f"Suspicious keywords found: {', '.join(kw_found[:5])}")
 
    # --- Factor 2: Sandbox Link Analysis ---
    sandbox_verdict = None
    sandbox_score   = 0
    if has_link and link_url:
        try:
            sandbox_result  = analyze_url(link_url)
            sandbox_verdict = sandbox_result.get('verdict', 'safe')
            sandbox_threat  = sandbox_result.get('threat_score', 0)
 
            if sandbox_verdict == 'malicious':
                sandbox_score = 50
                reasons.append(f"Sandbox: Malicious link detected ({link_url})")
            elif sandbox_verdict == 'suspicious':
                sandbox_score = 25
                reasons.append(f"Sandbox: Suspicious link detected ({link_url})")
            else:
                reasons.append(f"Sandbox: Link is safe ({link_url})")
 
            risk_score += sandbox_score
        except Exception as e:
            reasons.append(f"Sandbox analysis failed: {str(e)}")
 
    # --- ML Model Prediction ---
    base = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(base, '..', 'models', 'email_model.pkl')
    if os.path.exists(model_path):
        model = joblib.load(model_path)
    else:
        model = train_email_model()
 
    clean_text = preprocess_text(combined_text)
    ml_prediction = model.predict([clean_text])[0]
    ml_proba = model.predict_proba([clean_text])[0]
    ml_confidence = round(max(ml_proba) * 100, 1)
 
    # --- Combine ML + Rule-based ---
    # ML boosts score if it predicts high
    if ml_prediction == 'high':
        risk_score = max(risk_score, 60)
        reasons.append(f"ML model classified as HIGH (confidence: {ml_confidence}%)")
    elif ml_prediction == 'medium' and risk_score < 40:
        risk_score = max(risk_score, 35)
        reasons.append(f"ML model classified as MEDIUM (confidence: {ml_confidence}%)")
 
    risk_score = min(risk_score, 100)
 
    # --- Final Verdict ---
    if risk_score >= 60:
        verdict = 'high'
        action  = 'Email quarantined — Receiver & Admin notified'
    elif risk_score >= 30:
        verdict = 'medium'
        action  = 'Warning sent to receiver — Proceed with caution'
    else:
        verdict = 'safe'
        action  = 'Email delivered to inbox normally'
 
    return {
        'verdict'          : verdict,
        'risk_score'       : risk_score,
        'action'           : action,
        'reasons'          : reasons,
        'ml_prediction'    : ml_prediction,
        'ml_confidence'    : ml_confidence,
        'sandbox_verdict'  : sandbox_verdict,
        'keyword_count'    : kw_count,
        'keywords_found'   : kw_found,
        'sender'           : sender,
        'subject'          : subject,
        'has_link'         : has_link
    }
 
 
# ===== TEST =====
if __name__ == '__main__':
    test_emails = [
        {
            'sender'  : 'ceo@fakebank.net',
            'subject' : 'Urgent Wire Transfer Required',
            'body'    : 'Please transfer $50000 immediately to the following account. Act now.',
            'has_link': False,
            'link_url': None
        },
        {
            'sender'  : 'support@paypa1.com',
            'subject' : 'Password Reset Required',
            'body'    : 'Click here to reset your password or your account will be suspended.',
            'has_link': True,
            'link_url': 'http://malicious-site.com/verify'
        },
        {
            'sender'  : 'hr@company.com',
            'subject' : 'Team Meeting Tomorrow',
            'body'    : 'Please join us for the team meeting tomorrow at 10 AM.',
            'has_link': False,
            'link_url': None
        }
    ]
 
    for email in test_emails:
        result = analyze_email(email)
        print(f"\nSubject : {result['subject']}")
        print(f"Verdict : {result['verdict'].upper()}")
        print(f"Score   : {result['risk_score']}")
        print(f"Action  : {result['action']}")
        print(f"Reasons : {result['reasons']}")
 