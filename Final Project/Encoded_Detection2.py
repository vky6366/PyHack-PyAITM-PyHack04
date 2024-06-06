from kivy.uix.image import Image
from kivy.uix.floatlayout import FloatLayout
from kivy.lang import Builder
from kivymd.app import MDApp
import joblib
import socket
import pandas as pd
from urllib.parse import urlparse
import tldextract
from sklearn.preprocessing import LabelEncoder

# Load the pre-trained model and label encoders
model = joblib.load("C:\\Users\\vishw\\Desktop\\Final Project\\Data\\final_decision_tree_model.joblib")
url_encoder = joblib.load("C:\\Users\\vishw\\Desktop\\Final Project\\Data\\url_encoder.joblib")
domain_encoder = joblib.load("C:\\Users\\vishw\\Desktop\\Final Project\\Data\\domain_encoder.joblib")
tld_encoder = joblib.load("C:\\Users\\vishw\\Desktop\\Final Project\\Data\\tld_encoder.joblib")

# Define your KV layout string here with proper integration of the background
KV = '''
Screen:
    FloatLayout:
        md_bg_color: 0.8784313725490196, 1.0, 1.0, 1
        MDCard:
            size_hint: None, None
            size: "600dp", "220dp"
            pos_hint: {'center_x': 0.5, 'center_y': 0.3}
            elevation: 1
            padding: "10dp"
            spacing: "10dp"
            orientation: 'vertical'

            MDTextField:
                id: url_entry
                hint_text: "Enter URL"
                size_hint_x: None
                width: "250dp"
                pos_hint: {'center_x': 0.5}

            MDRaisedButton:
                text: "Detect"
                size_hint: None, None
                size: "140dp", "48dp"
                pos_hint: {'center_x': 0.5}
                on_release: app.predict_phishing()

            MDLabel:
                id: result_label
                text: ""
                halign: 'center'
                size_hint: None, None
                size: "250dp", "20dp"
                pos_hint: {'center_x': 0.5}
'''

class PhishingApp(MDApp):
    def build(self):
        self.theme_cls.primary_palette = "Blue"
        return Builder.load_string(KV)

    @staticmethod
    def is_domain_ip(domain):
        try:
            socket.inet_aton(domain)
            return 1
        except socket.error:
            return 0

    @staticmethod
    def char_continuation_rate(url):
        from itertools import groupby
        return sum(1 for _ in groupby(url)) / len(url) if url else 0

    @staticmethod
    def url_char_prob(url):
        suspicious_chars = ['%', '$', '&', '@']
        count = sum(url.count(char) for char in suspicious_chars)
        return count / len(url) if url else 0

    @staticmethod
    def obfuscation_ratio(url):
        obfuscated = url.count('%')  # Simple count of URL-encoded characters
        return obfuscated / len(url) if url else 0

    @staticmethod
    def is_valid_url(url):
        parsed = urlparse(url)
        return bool(parsed.scheme) and bool(parsed.netloc)

    def extract_features_from_url(self, url):
        extracted = tldextract.extract(url)
        domain = extracted.domain + '.' + extracted.suffix if extracted.suffix else extracted.domain
        subdomain = extracted.subdomain
        url_length = len(url)
        domain_length = len(domain)
        tld_length = len(extracted.suffix)
        no_of_subdomain = subdomain.count('.') + 1 if subdomain else 0
        is_https = 1 if url.startswith('https') else 0

        # Use the encoders to transform data if possible
        try:
            encoded_url = url_encoder.transform([url])[0]
        except ValueError:
            encoded_url = -1  # Indicator for unknown URL

        try:
            encoded_domain = domain_encoder.transform([domain])[0]
        except ValueError:
            encoded_domain = -1  # Indicator for unknown domain

        try:
            encoded_tld = tld_encoder.transform([extracted.suffix])[0]
        except ValueError:
            encoded_tld = -1  # Indicator for unknown TLD

        features = {
            'EncodedURL': encoded_url,
            'EncodedDomain': encoded_domain,
            'EncodedTLD': encoded_tld,
            'URLLength': url_length,
            'DomainLength': domain_length,
            'IsDomainIP': self.is_domain_ip(domain),
            'URLSimilarityIndex': 100.0,  # Placeholder
            'CharContinuationRate': self.char_continuation_rate(url),
            'TLDLegitimateProb': 0.5229071,  # Example static value
            'URLCharProb': self.url_char_prob(url),
            'TLDLength': tld_length,
            'NoOfSubDomain': no_of_subdomain,
            'NoOfObfuscatedChar': url.count('%'),
            'ObfuscationRatio': self.obfuscation_ratio(url),
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

        # Ensure all features used during model training are generated here
        feature_order = ['EncodedURL', 'EncodedDomain', 'EncodedTLD', 'URLLength', 'DomainLength', 'IsDomainIP', 
                         'URLSimilarityIndex', 'CharContinuationRate', 'TLDLegitimateProb', 'URLCharProb', 
                         'TLDLength', 'NoOfSubDomain', 'NoOfObfuscatedChar', 'ObfuscationRatio', 'NoOfLettersInURL', 
                         'LetterRatioInURL', 'NoOfDegitsInURL', 'DegitRatioInURL', 'NoOfEqualsInURL', 
                         'NoOfQMarkInURL', 'NoOfAmpersandInURL', 'NoOfOtherSpecialCharsInURL', 
                         'SpacialCharRatioInURL', 'IsHTTPS']

        return pd.DataFrame([features], columns=feature_order)

    def predict_phishing(self):
        url = self.root.ids.url_entry.text.strip()
        if not url:
            self.root.ids.result_label.text = "Please enter a URL."
            return

        if not self.is_valid_url(url):
            self.root.ids.result_label.text = "Invalid URL format. Please enter a correct URL."
            return

        features = self.extract_features_from_url(url)

        # Check for missing features
        expected_features = ['EncodedURL', 'EncodedDomain', 'EncodedTLD', 'URLLength', 'DomainLength', 'IsDomainIP', 
                             'URLSimilarityIndex', 'CharContinuationRate', 'TLDLegitimateProb', 'URLCharProb', 
                             'TLDLength', 'NoOfSubDomain', 'NoOfObfuscatedChar', 'ObfuscationRatio', 'NoOfLettersInURL', 
                             'LetterRatioInURL', 'NoOfDegitsInURL', 'DegitRatioInURL', 'NoOfEqualsInURL', 
                             'NoOfQMarkInURL', 'NoOfAmpersandInURL', 'NoOfOtherSpecialCharsInURL', 
                             'SpacialCharRatioInURL', 'IsHTTPS']
        missing_features = set(expected_features) - set(features.columns)
        if missing_features:
            self.root.ids.result_label.text = f"Missing features: {missing_features}"
            return

        # Check for unknown encoded features
        if features['EncodedURL'].values[0] == -1 or features['EncodedDomain'].values[0] == -1 or features['EncodedTLD'].values[0] == -1:
            result = "Not Phishing" if url.startswith('https') else "Phishing"
        else:
            prediction = model.predict(features)
            result = "Phishing" if prediction[0] == 1 else "Not Phishing"

        self.root.ids.result_label.text = f"Prediction: {result}"

if __name__ == '__main__':
    PhishingApp().run()