import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from datetime import datetime
import joblib
import os
 
# ===== KNOWN SAFE LOCATIONS PER USER =====
USER_HOME_LOCATIONS = {
    'john@company.com': 'Mumbai',
    'jane@company.com': 'Delhi',
    'bob@company.com': 'Mumbai',
    'alice@company.com': 'Chennai',
    'mark@company.com': 'Bangalore',
    'sara@company.com': 'Hyderabad',
    'raj@company.com': 'Mumbai'
}
 
# ===== HIGH RISK COUNTRIES =====
HIGH_RISK_LOCATIONS = ['Russia', 'China', 'North Korea', 'Iran', 'Unknown']
 
# ===== FEATURE ENGINEERING =====
def extract_features(log_entry, previous_entry=None):
    """
    Extract numerical features from a login log entry.
    log_entry: dict with keys:
        user_email, login_time, location, device, ip_address (optional)
    previous_entry: previous login dict for comparison
    """
    features = {}
 
    # --- Feature 1: Login hour (0-23) ---
    login_time = log_entry.get('login_time')
    if isinstance(login_time, str):
        login_time = datetime.strptime(login_time, '%Y-%m-%d %H:%M:%S')
    features['login_hour'] = login_time.hour
 
    # --- Feature 2: Is odd hour (11PM - 5AM = 1) ---
    features['is_odd_hour'] = 1 if login_time.hour >= 23 or login_time.hour <= 5 else 0
 
    # --- Feature 3: Location change from home ---
    user_email = log_entry.get('user_email', '')
    current_location = log_entry.get('location', 'Unknown')
    home_location = USER_HOME_LOCATIONS.get(user_email, 'Unknown')
    features['location_changed'] = 0 if current_location == home_location else 1
 
    # --- Feature 4: High risk location ---
    features['high_risk_location'] = 1 if current_location in HIGH_RISK_LOCATIONS else 0
 
    # --- Feature 5: Time gap from previous login (hours) ---
    if previous_entry:
        prev_time = previous_entry.get('login_time')
        if isinstance(prev_time, str):
            prev_time = datetime.strptime(prev_time, '%Y-%m-%d %H:%M:%S')
        time_gap = abs((login_time - prev_time).total_seconds() / 3600)
        features['time_gap_hours'] = round(time_gap, 2)
    else:
        features['time_gap_hours'] = 8.0  # default normal gap
 
    # --- Feature 6: Impossible travel (location changed + time gap < 3 hrs) ---
    features['impossible_travel'] = 1 if (
        features['location_changed'] == 1 and features['time_gap_hours'] < 3
    ) else 0
 
    # --- Feature 7: Device change ---
    if previous_entry:
        prev_device = previous_entry.get('device', '')
        curr_device = log_entry.get('device', '')
        features['device_changed'] = 0 if prev_device == curr_device else 1
    else:
        features['device_changed'] = 0
 
    # --- Feature 8: Unknown device ---
    device = log_entry.get('device', '').lower()
    features['unknown_device'] = 1 if 'unknown' in device else 0
 
    # --- Feature 9: IP change (optional) ---
    if previous_entry and log_entry.get('ip_address') and previous_entry.get('ip_address'):
        features['ip_changed'] = 0 if log_entry['ip_address'] == previous_entry['ip_address'] else 1
    else:
        features['ip_changed'] = 0
 
    return features
 
 
def calculate_risk_score(features):
    """
    Rule-based risk score calculation (0-100).
    Used alongside Isolation Forest.
    """
    score = 0
 
    if features.get('impossible_travel') == 1:
        score += 40
    if features.get('high_risk_location') == 1:
        score += 30
    if features.get('is_odd_hour') == 1:
        score += 15
    if features.get('unknown_device') == 1:
        score += 20
    if features.get('device_changed') == 1:
        score += 10
    if features.get('ip_changed') == 1:
        score += 10
    if features.get('location_changed') == 1:
        score += 10
 
    return min(score, 100)
 
 
def train_model(csv_path=None):
    if csv_path is None:
        base = os.path.dirname(os.path.abspath(__file__))
        csv_path = os.path.join(base, '..', 'data', 'login_logs.csv')
    """Train Isolation Forest on login logs dataset."""
    df = pd.read_csv(csv_path)
 
    feature_rows = []
    for i, row in df.iterrows():
        prev_row = df.iloc[i - 1].to_dict() if i > 0 else None
        curr = row.to_dict()
        feats = extract_features(curr, prev_row)
        feature_rows.append(feats)
 
    feature_df = pd.DataFrame(feature_rows)
 
    model = IsolationForest(
        n_estimators=100,
        contamination=0.2,
        random_state=42
    )
    model.fit(feature_df)
 
    base = os.path.dirname(os.path.abspath(__file__))
    models_dir = os.path.join(base, '..', 'models')
    os.makedirs(models_dir, exist_ok=True)
    joblib.dump(model, os.path.join(models_dir, 'login_model.pkl'))

    print("Login behavior model trained and saved.")
    return model
 
 
def analyze_login(log_entry, previous_entry=None):
    """
    Main function — analyze a login attempt.
    Returns verdict, risk score, reasons.
    """
    features = extract_features(log_entry, previous_entry)
    risk_score = calculate_risk_score(features)
 
    # Load or train model
    base = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(base, '..', 'models', 'login_model.pkl')
    if os.path.exists(model_path):
        model = joblib.load(model_path)
    else:
        model = train_model()
 
    feature_df = pd.DataFrame([features])
    prediction = model.predict(feature_df)
    is_anomaly_ml = prediction[0] == -1  # -1 = anomaly in Isolation Forest
 
    # Combine ML + rule-based
    is_anomaly = is_anomaly_ml or risk_score >= 40
 
    # Build reasons
    reasons = []
    if features['impossible_travel']:
        reasons.append(f"Impossible travel detected — location changed in {features['time_gap_hours']} hrs")
    if features['high_risk_location']:
        reasons.append(f"Login from high-risk location: {log_entry.get('location')}")
    if features['is_odd_hour']:
        reasons.append(f"Login at odd hour: {log_entry.get('login_time')}")
    if features['unknown_device']:
        reasons.append("Unknown device used")
    if features['device_changed']:
        reasons.append("Device changed from previous login")
    if features['ip_changed']:
        reasons.append("IP address changed")
    if features['location_changed'] and not features['impossible_travel']:
        reasons.append(f"Location changed from home base")
 
    # Verdict
    if risk_score >= 60:
        verdict = 'anomaly'
        action = 'Session blocked — Admin & Receiver alerted'
    elif risk_score >= 30:
        verdict = 'suspicious'
        action = 'Flagged for review — User notified'
    else:
        verdict = 'normal'
        action = 'Login allowed'
 
    return {
        'verdict': verdict,
        'risk_score': risk_score,
        'is_anomaly': is_anomaly,
        'action': action,
        'reasons': reasons,
        'features': features,
        'user': log_entry.get('user_email'),
        'location': log_entry.get('location'),
        'device': log_entry.get('device'),
        'login_time': str(log_entry.get('login_time')),
        'ip_address': log_entry.get('ip_address', 'N/A')
    }
 
 
# ===== TEST =====
if __name__ == '__main__':
    normal_login = {
        'user_email': 'john@company.com',
        'login_time': '2024-01-15 09:00:00',
        'location': 'Mumbai',
        'device': 'Windows-PC',
        'ip_address': '192.168.1.1'
    }
 
    anomaly_login = {
        'user_email': 'john@company.com',
        'login_time': '2024-01-15 11:00:00',
        'location': 'Russia',
        'device': 'Unknown-Device',
        'ip_address': '185.220.101.5'
    }
 
    print("=== Normal Login ===")
    r1 = analyze_login(normal_login)
    print(f"Verdict: {r1['verdict']} | Score: {r1['risk_score']} | Action: {r1['action']}")
 
    print("\n=== Anomaly Login ===")
    r2 = analyze_login(anomaly_login, previous_entry=normal_login)
    print(f"Verdict: {r2['verdict']} | Score: {r2['risk_score']} | Action: {r2['action']}")
    print(f"Reasons: {r2['reasons']}")
 