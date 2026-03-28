from flask import Flask, request, jsonify
from flask_cors import CORS
from sandbox import analyze_url
from login_behavior import analyze_login, train_model
from email_analysis import analyze_email, train_email_model
from risk_engine import run_risk_engine
import os
 
app = Flask(__name__)
CORS(app)
 
# ===== TRAIN MODELS ON STARTUP =====
if not os.path.exists('models/login_model.pkl'):
    try:
        train_model()
    except Exception as e:
        print(f"Login model training skipped: {e}")
 
if not os.path.exists('models/email_model.pkl'):
    try:
        train_email_model()
    except Exception as e:
        print(f"Email model training skipped: {e}")
 
 
@app.route('/')
def home():
    return jsonify({'status': 'BEC Shield API is running'})
 
 
# ===== SANDBOX ENDPOINT =====
@app.route('/api/sandbox', methods=['POST'])
def sandbox():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'No URL provided'}), 400
    url = data['url'].strip()
    if not url.startswith('http'):
        url = 'http://' + url
    try:
        result = analyze_url(url)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
 
 
# ===== LOGIN BEHAVIOR ENDPOINT =====
@app.route('/api/login', methods=['POST'])
def login_analysis():
    data = request.get_json()
    if not data or 'log_entry' not in data:
        return jsonify({'error': 'No login data provided'}), 400
    log_entry = data['log_entry']
    previous_entry = data.get('previous_entry', None)
    required_fields = ['user_email', 'login_time', 'location', 'device']
    for field in required_fields:
        if field not in log_entry:
            return jsonify({'error': f'Missing field: {field}'}), 400
    try:
        result = analyze_login(log_entry, previous_entry)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
 
 
# ===== EMAIL ANALYSIS ENDPOINT =====
@app.route('/api/email', methods=['POST'])
def email_analysis():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    required_fields = ['sender', 'subject', 'body']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing field: {field}'}), 400
    email_data = {
        'sender'  : data['sender'],
        'subject' : data['subject'],
        'body'    : data['body'],
        'has_link': data.get('has_link', False),
        'link_url': data.get('link_url', None)
    }
    try:
        result = analyze_email(email_data)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
 
 
# ===== RISK ENGINE ENDPOINT (MAIN) =====
@app.route('/api/analyze', methods=['POST'])
def full_analysis():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
 
    required_fields = ['sender', 'subject', 'body']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing field: {field}'}), 400
 
    email_data = {
        'sender'  : data['sender'],
        'subject' : data['subject'],
        'body'    : data['body'],
        'has_link': data.get('has_link', False),
        'link_url': data.get('link_url', None)
    }
 
    login_data = data.get('login_data', None)
 
    try:
        result = run_risk_engine(email_data, login_data)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
 
 
if __name__ == '__main__':
    app.run(debug=True, port=5000)
 
