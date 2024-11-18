from flask import Flask, request, jsonify
import joblib
import socket
from urllib.parse import urlparse
import tldextract
import pandas as pd
import pickle

# Load the model and encoders using pickle
with open(r"D:\PyHack-PyAITM-PyHack04-main\PyHack-PyAITM-PyHack04-main\Final Project\LogisticReg_model.pkl", 'rb') as f:
    model = pickle.load(f)

with open(r"D:\PyHack-PyAITM-PyHack04-main\PyHack-PyAITM-PyHack04-main\Final Project\url_encoder.pkl", 'rb') as f:
    url_encoder = pickle.load(f)

with open(r"D:\PyHack-PyAITM-PyHack04-main\PyHack-PyAITM-PyHack04-main\Final Project\domain_encoder.pkl", 'rb') as f:
    domain_encoder = pickle.load(f)

with open(r"D:\PyHack-PyAITM-PyHack04-main\PyHack-PyAITM-PyHack04-main\Final Project\tld_encoder.pkl", 'rb') as f:
    tld_encoder = pickle.load(f)

app = Flask(__name__)

def is_domain_ip(domain):
    try:
        socket.inet_aton(domain)
        return 1
    except socket.error:
        return 0

def char_continuation_rate(url):
    from itertools import groupby
    return sum(1 for _ in groupby(url)) / len(url) if url else 0

def url_char_prob(url):
    suspicious_chars = ['%', '$', '&', '@']
    count = sum(url.count(char) for char in suspicious_chars)
    return count / len(url) if url else 0

def obfuscation_ratio(url):
    obfuscated = url.count('%')
    return obfuscated / len(url) if url else 0

def is_valid_url(url):
    parsed = urlparse(url)
    return bool(parsed.scheme) and bool(parsed.netloc)

def extract_features_from_url(url):
    extracted = tldextract.extract(url)
    domain = extracted.domain + '.' + extracted.suffix if extracted.suffix else extracted.domain
    subdomain = extracted.subdomain
    url_length = len(url)
    domain_length = len(domain)
    tld_length = len(extracted.suffix)
    no_of_subdomain = subdomain.count('.') + 1 if subdomain else 0
    is_https = 1 if url.startswith('https') else 0

    # Use the encoders to transform data
    try:
        encoded_url = url_encoder.transform([url])[0]
        encoded_domain = domain_encoder.transform([domain])[0]
        encoded_tld = tld_encoder.transform([extracted.suffix])[0]
    except ValueError as e:
        print("Encoding error:", e)
        return None  # Return None if encoding fails

    features = {
        'EncodedURL': encoded_url,
        'EncodedDomain': encoded_domain,
        'EncodedTLD': encoded_tld,
        'URLLength': url_length,
        'DomainLength': domain_length,
        'IsDomainIP': is_domain_ip(domain),
        'URLSimilarityIndex': 100.0,
        'CharContinuationRate': char_continuation_rate(url),
        'TLDLegitimateProb': 0.5229071,
        'URLCharProb': url_char_prob(url),
        'TLDLength': tld_length,
        'NoOfSubDomain': no_of_subdomain,
        'NoOfObfuscatedChar': url.count('%'),
        'ObfuscationRatio': obfuscation_ratio(url),
        'NoOfLettersInURL': sum(c.isalpha() for c in url),
        'LetterRatioInURL': sum(c.isalpha() for c in url) / url_length if url_length > 0 else 0,
        'NoOfDegitsInURL': sum(c.isdigit() for c in url),
        'DegitRatioInURL': sum(c.isdigit() for c in url) / url_length if url_length > 0 else 0,
        'NoOfEqualsInURL': url.count('='),
        'NoOfQMarkInURL': url.count('?'),
        'NoOfAmpersandInURL': url.count('&'),
        'NoOfOtherSpecialCharsInURL': sum(not c.isalnum() and not c.isspace() for c in url),
        'SpacialCharRatioInURL': sum(not c.isalnum() and not c.isspace() for c in url) / url_length if url_length > 0 else 0,
        'IsHTTPS': is_https
    }

    feature_order = ['EncodedURL', 'EncodedDomain', 'EncodedTLD', 'URLLength', 'DomainLength', 'IsDomainIP',
                     'URLSimilarityIndex', 'CharContinuationRate', 'TLDLegitimateProb', 'URLCharProb', 
                     'TLDLength', 'NoOfSubDomain', 'NoOfObfuscatedChar', 'ObfuscationRatio', 'NoOfLettersInURL', 
                     'LetterRatioInURL', 'NoOfDegitsInURL', 'DegitRatioInURL', 'NoOfEqualsInURL', 
                     'NoOfQMarkInURL', 'NoOfAmpersandInURL', 'NoOfOtherSpecialCharsInURL', 
                     'SpacialCharRatioInURL', 'IsHTTPS']
    return pd.DataFrame([features], columns=feature_order)

@app.route('/predict', methods=['POST'])
def predict_phishing():
    data = request.json.get('url') if request.is_json else request.form.get('url')
    if not data:
        return jsonify({"error": "Please provide a URL."}), 400

    if not is_valid_url(data):
        return jsonify({"error": "Invalid URL format."}), 400

    features = extract_features_from_url(data)
    if features is None:
        result = 0 if data.startswith('https') else 1
        return jsonify({"prediction": result})

    prediction = model.predict(features)
    result = 0 if prediction[0] == 1 else 1
    return jsonify({"prediction": result})

if __name__ == '__main__':
    app.run(debug=True)
