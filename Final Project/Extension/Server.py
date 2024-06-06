from flask import Flask, request, jsonify
import joblib
import pandas as pd
import tldextract

app = Flask(__name__)

# Load your model and encoders
model = joblib.load("C:\\Users\\vishw\\Desktop\\Final Project\\Data\\final_decision_tree_model.joblib")
url_encoder = joblib.load("C:\\Users\\vishw\\Desktop\\Final Project\\Data\\url_encoder.joblib")
domain_encoder = joblib.load("C:\\Users\\vishw\\Desktop\\Final Project\\Data\\domain_encoder.joblib")
tld_encoder = joblib.load("C:\\Users\\vishw\\Desktop\\Final Project\\Data\\tld_encoder.joblib")


def extract_features_from_url(url):
    extracted = tldextract.extract(url)
    domain = extracted.domain + '.' + extracted.suffix if extracted.suffix else extracted.domain
    subdomain = extracted.subdomain
    url_length = len(url)
    domain_length = len(domain)
    tld_length = len(extracted.suffix)
    no_of_subdomain = subdomain.count('.') + 1 if subdomain else 0
    is_https = 1 if url.startswith('https') else 0

    encoded_url = url_encoder.transform([url])[0] if url in url_encoder.classes_ else -1
    encoded_domain = domain_encoder.transform([domain])[0] if domain in domain_encoder.classes_ else -1
    encoded_tld = tld_encoder.transform([extracted.suffix])[0] if extracted.suffix in tld_encoder.classes_ else -1

    features = {
        'EncodedURL': encoded_url,
        'EncodedDomain': encoded_domain,
        'EncodedTLD': encoded_tld,
        'URLLength': url_length,
        'DomainLength': domain_length,
        'IsDomainIP': 1 if subdomain else 0,
        'TLD': extracted.suffix,
        'URLSimilarityIndex': 100.0,
        'CharContinuationRate': 0.5,
        'TLDLegitimateProb': 0.5229071,
        'URLCharProb': 0.1,
        'TLDLength': tld_length,
        'NoOfSubDomain': no_of_subdomain,
        'NoOfObfuscatedChar': url.count('%'),
        'ObfuscationRatio': url.count('%') / len(url) if len(url) > 0 else 0,
        'NoOfLettersInURL': sum(c.isalpha() for c in url),
        'LetterRatioInURL': sum(c.isalpha() for c in url) / len(url) if len(url) > 0 else 0,
        'NoOfDegitsInURL': sum(c.isdigit() for c in url),
        'DegitRatioInURL': sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0,
        'NoOfEqualsInURL': url.count('='),
        'NoOfQMarkInURL': url.count('?'),
        'NoOfAmpersandInURL': url.count('&'),
        'NoOfOtherSpecialCharsInURL': sum(not c.isalnum() and not c.isspace() for c in url),
        'SpacialCharRatioInURL': sum(not c.isalnum() and not c.isspace() for c in url) / len(url) if len(url) > 0 else 0,
        'IsHTTPS': is_https
    }

    return pd.DataFrame([features])

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    url = data['url']
    try:
        features = extract_features_from_url(url)
        # Check for unknown encoded features
        if features['EncodedURL'].values[0] == -1 or features['EncodedDomain'].values[0] == -1 or features['EncodedTLD'].values[0] == -1:
            result = "Not Phishing" if url.startswith('https') else "Phishing"
        else:
            prediction = model.predict(features)
            result = "Phishing" if prediction[0] == 1 else "Not Phishing"
        return jsonify({'prediction': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(port=5000, debug=True)
