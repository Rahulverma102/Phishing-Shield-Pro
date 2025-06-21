from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import urllib.parse
import hashlib
import json
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Enable CORS for browser extension

# Simulated blacklist database
BLACKLIST_DOMAINS = {
    'phishing-site.com',
    'fake-bank.net',
    'malicious-login.org',
    'scam-website.info',
    'suspicious-domain.biz'
}

# Suspicious patterns for URL analysis
SUSPICIOUS_PATTERNS = [
    r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
    r'[a-z]+-[a-z]+-[a-z]+\.(tk|ml|ga|cf)',  # Suspicious TLDs
    r'(paypal|amazon|google|microsoft|apple)[0-9]+',  # Brand impersonation
    r'[a-z]{20,}',  # Very long subdomains
    r'(secure|login|verify|update|confirm)-[a-z]+',  # Phishing keywords
]

def extract_features(url):
    """Extract features from URL for analysis"""
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    
    features = {
        'domain_length': len(domain),
        'path_length': len(path),
        'subdomain_count': domain.count('.') - 1,
        'has_ip': bool(re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', domain)),
        'suspicious_tld': domain.endswith(('.tk', '.ml', '.ga', '.cf', '.pw')),
        'has_hyphen': '-' in domain,
        'url_length': len(url),
        'has_suspicious_keywords': any(keyword in url.lower() for keyword in 
                                     ['secure', 'login', 'verify', 'update', 'confirm', 'account']),
        'https': parsed.scheme == 'https'
    }
    
    return features

def calculate_risk_score(url, features):
    """Calculate risk score based on URL features"""
    score = 0
    
    # Check blacklist
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    
    if domain in BLACKLIST_DOMAINS:
        return 95  # High risk for blacklisted domains
    
    # Feature-based scoring
    if features['has_ip']:
        score += 30
    
    if features['suspicious_tld']:
        score += 25
    
    if features['domain_length'] > 30:
        score += 15
    
    if features['subdomain_count'] > 3:
        score += 20
    
    if features['has_suspicious_keywords']:
        score += 20
    
    if not features['https']:
        score += 10
    
    if features['url_length'] > 100:
        score += 10
    
    # Check suspicious patterns
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, url.lower()):
            score += 15
            break
    
    return min(score, 100)  # Cap at 100

@app.route('/api/analyze', methods=['POST'])
def analyze_url():
    """Analyze URL for phishing indicators"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Extract features
        features = extract_features(url)
        
        # Calculate risk score
        risk_score = calculate_risk_score(url, features)
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = 'HIGH'
            recommendation = 'BLOCK'
        elif risk_score >= 40:
            risk_level = 'MEDIUM'
            recommendation = 'CAUTION'
        else:
            risk_level = 'LOW'
            recommendation = 'SAFE'
        
        response = {
            'url': url,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'recommendation': recommendation,
            'features': features,
            'timestamp': datetime.now().isoformat(),
            'analysis_details': {
                'blacklisted': urllib.parse.urlparse(url).netloc.lower() in BLACKLIST_DOMAINS,
                'suspicious_patterns': [pattern for pattern in SUSPICIOUS_PATTERNS 
                                      if re.search(pattern, url.lower())],
                'security_indicators': {
                    'https': features['https'],
                    'ip_address': features['has_ip'],
                    'suspicious_tld': features['suspicious_tld']
                }
            }
        }
        
        return jsonify(response)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/report', methods=['POST'])
def report_phishing():
    """Report a phishing URL"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        user_report = data.get('report_type', 'phishing')
        
        # In a real implementation, this would save to a database
        print(f"Phishing report received: {url} - Type: {user_report}")
        
        return jsonify({
            'status': 'success',
            'message': 'Thank you for reporting this URL. It will be reviewed by our security team.'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Phishing Detection API',
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    print("Starting Phishing Detection API...")
    print("API will be available at: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
