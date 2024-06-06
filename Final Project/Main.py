from kivy.uix.image import Image
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.floatlayout import FloatLayout
from kivy.lang import Builder
from kivymd.app import MDApp
import joblib
import socket
import pandas as pd
from urllib.parse import urlparse
import tldextract
from sklearn.preprocessing import LabelEncoder
from kivy.core.window import Window
from kivy.uix.textinput import TextInput
from kivy.utils import get_color_from_hex
from kivy.uix.relativelayout import RelativeLayout
from kivy.graphics import Color, RoundedRectangle
from kivymd.uix.textfield import MDTextField

# Load the pre-trained model and label encoders
model = joblib.load("C:\\Users\\vishw\\Desktop\\Final Project\\Data\\final_decision_tree_model.joblib")
url_encoder = joblib.load("C:\\Users\\vishw\\Desktop\\Final Project\\Data\\url_encoder.joblib")
domain_encoder = joblib.load("C:\\Users\\vishw\\Desktop\\Final Project\\Data\\domain_encoder.joblib")
tld_encoder = joblib.load("C:\\Users\\vishw\\Desktop\\Final Project\\Data\\tld_encoder.joblib")

# Define your KV layout string here with proper integration of the background
KV = '''
<FeedbackPopup@Popup>:
    title: 'Feedback Form'
    size_hint: None, None
    size: 400, 300
    auto_dismiss: False
    background: ''
    
    canvas.before:
        Color:
            rgba: 0.94, 0.97, 1, 1  # Alice Blue
        RoundedRectangle:
            size: self.size
            pos: self.pos
            radius: [15]

    BoxLayout:
        orientation: 'vertical'
        padding: [20, 20]
        spacing: 10
        
        Label:
            text: 'Feedback'
            size_hint_y: None
            height: 30
            font_size: '20sp'

        MDTextField:
            id: name_input
            hint_text: 'Enter your name'
            size_hint_y: None
            height: 40
            multiline: False
            height: 50
            color: 0, 0, 0, 1

        TextInput:
            id: feedback_input
            hint_text: 'Enter your feedback here'
            size_hint_y: None
            height: 100
            multiline: True

        Button:
            text: 'Submit'
            size_hint_y: None
            height: 50
            on_release: root.dismiss()

        Label:
            text: 'We value your feedback!'
            size_hint_y: None
            height: 40
            font_size: '18sp'
            color: 0, 0, 0, 1

        TextInput:
            id: name_input
            hint_text: 'Enter your name'
            size_hint_y: None
            height: 40
            padding: [10, 5]
            background_color: 0, 0, 0, 1
            foreground_color: 0, 0, 0, 1
            multiline: False

        TextInput:
            id: feedback_input
            hint_text: 'Enter your feedback here'
            size_hint_y: None
            height: 100
            padding: [10, 10]
            background_normal: ''
            background_color: 0.95, 0.95, 0.95, 1
            foreground_color: 0, 0, 0, 1
            multiline: True

        Button:
            text: 'Submit'
            size_hint_y: None
            height: 50
            background_normal: ''
            background_color: 0.13, 0.55, 0.13, 1
            color: 1, 1, 1, 1
            on_release:
                root.dismiss()
                app.submit_feedback(name_input.text, feedback_input.text)

Screen:
    FloatLayout:
        canvas.before:
            Color:
                rgba: 224/255, 255/255, 255/255, 1
            Rectangle:
                size: self.size
                pos: self.pos
        MDRaisedButton:
            text: "Feedback"
            size_hint: None, None
            size: "140dp", "48dp"
            pos_hint: {'right': 0.98, 'top': 0.95}
            on_release: app.open_feedback_form()
        Image:
            source: "C:/Users/vishw/Desktop/Final Project/Title.png"
            size_hint: (1, None)
            height: 200
            pos_hint: {'center_x': 0.5, 'top': 0.85}

        MDCard:
            background_normal: ''
            background_color: 0, 0, 0, 0
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

        # Use the encoders to transform data
        encoded_url = url_encoder.transform([url])[0]
        encoded_domain = domain_encoder.transform([domain])[0]
        encoded_tld = tld_encoder.transform([extracted.suffix])[0]

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
            self.show_popup("Please enter a URL.", "error", "C:/Users/vishw/Desktop/Final Project/Exclamation.png")
            return

        if not self.is_valid_url(url):
            self.show_popup("Invalid URL format. Please enter a correct URL.", "error", "C:/Users/vishw/Desktop/Final Project/Exclamation.png")
            return
        
        try:
            features = self.extract_features_from_url(url)
        except ValueError:
            result = "Not Phishing" if url.startswith('https') else "Phishing"
            img_path = "C:/Users/vishw/Desktop/Final Project/Safe.png" if result == "Not Phishing" else "C:/Users/vishw/Desktop/Final Project/Unsafe.jpg"
            self.show_popup(result, "safe" if result == "Not Phishing" else "phishing", img_path)
            return

        prediction = model.predict(features)
        result = "Phishing" if prediction[0] == 1 else "Not Phishing"
        img_path = "C:/Users/vishw/Desktop/Final Project/Safe.jpg" if result == "Not Phishing" else "C:/Users/vishw/Desktop/Final Project/Unsafe.jpg"
        self.show_popup(f"Prediction: {result}", "safe" if result == "Not Phishing" else "phishing", img_path)

    def show_popup(self, message, status, image_path):
        # Main layout for content
        box = BoxLayout(orientation='vertical', padding=(10))
        img = Image(source=image_path, size_hint=(1, 0.5))
        box.add_widget(img)
        label = Label(text=message, size_hint=(1, 0.2), font_size='20sp', color=[0, 0, 0, 1])
        box.add_widget(label)

        # Container for the popup which allows for absolute positioning
        layout = RelativeLayout()
        layout.add_widget(box)

        # Add close button at the very top right corner of the popup, aligning it with the edge
        close_btn = Button(
            text='X', 
            font_size='24sp',  # Larger font size
            size_hint=(None, None), 
            size=(50, 50),
            pos_hint={'right': 1, 'top': 1},
            on_release=lambda x: popup.dismiss(),
            background_normal='',  # Removes the default background for the normal state
            background_down='',  # Removes the default background for the pressed state
            background_color=[0, 0, 0, 0],  # Transparent background
            color=[0, 0, 0, 1],  # Black color for the text
            bold=True
            )

        layout.add_widget(close_btn)

        # Determine the background color based on the status
        if status == "safe":
            background_color = get_color_from_hex('#FFFFFF')  # Alice Blue
        else:
            background_color = get_color_from_hex('#FFFFFF')  # Misty Rose

        # Create and configure popup with no title bar
        popup = Popup(title='', content=layout, size_hint=(None, None), size=(400, 300),  # Width x Height in pixels or density-independent pixels
              background_color=background_color, separator_color=self.theme_cls.primary_color)


        # Set the default background image to fully transparent
        popup.background = ""

        popup.open()

    def open_feedback_form(self):
        # Open a popup with fields for name and feedback
        box = BoxLayout(orientation='vertical', padding=(10), spacing=10)
        feedback_label = Label(
        text='Your Feedback is \nImportant to us',
        size_hint_y=None,
        height=20,
        font_size='20sp',
        color = [0, 0, 0, 1]
        )
        box.add_widget(feedback_label)
        name_input = MDTextField(
            hint_text='Enter your name',
            size_hint_y=None,
            height=30,
            background_color=(0.1, 0.5, 0.6, 1),  # RGB with alpha
            foreground_color=(1, 1, 1, 1),        # Text color
            font_size=18,
            padding_y=(5, 5),
            multiline=False
        )
        feedback_input = MDTextField(
            hint_text='Enter your feedback here',
            size_hint_y=None,
            height=90,
            background_color=(0.2, 0.2, 0.2, 1),
            foreground_color=(0.8, 0.8, 0.8, 1),
            font_size=16,
            padding_y=(10, 10),
            multiline=True
        )
        submit_button = Button(text='Submit', size_hint_y=None, height=30,
                               on_release=lambda x: self.submit_feedback(name_input.text, feedback_input.text))
        
        box.add_widget(name_input)
        box.add_widget(feedback_input)
        box.add_widget(submit_button)

        # Create a popup with a specific background color
        self.feedback_popup = Popup(title='Feedback Form',
                                    content=box,
                                    size_hint=(0.4, 0.5),
                                    background='Alice Blue',
                                    separator_color=self.theme_cls.primary_color)
        self.feedback_popup.open()

    def submit_feedback(self, name, feedback):
        # Implement the feedback saving mechanism here
        if name.strip() and feedback.strip():  # Ensure non-empty submissions
            import csv
            with open('Feedback.csv', 'a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([name, feedback])
            if self.feedback_popup:  # Check if the popup is defined and then dismiss it
                self.feedback_popup.dismiss()
            print("Feedback submitted:", name, feedback)
        else:
            print("Name and feedback must not be empty")


if __name__ == '__main__':
    PhishingApp().run()
