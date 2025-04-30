from flask import Flask, render_template, request
from featureExtraction import featureExtraction
import joblib

app = Flask(__name__)

# Load the saved machine learning model
model = joblib.load('models/Phishing.pkl')

# Define the feature names corresponding to the extracted features
feature_names = [
    "Have IP",
    "Have '@' symbol",
    "URL Length < 5",
    "URL Depth",
    "Redirection",
    "HTTPS in URL",
    "URL Shortening",
    "Prefix/Suffix",
    "DNS Record Exists",
    "Domain Age",
    "Domain Expiry",
    "Contains iframe",
    "Mouse Over",
    "Right Click Disabled",
    "Multiple Redirections",
    "Unusual Extension",
    "Numeric Digits in URL",
    "Mixed Case Characters"
]

# Route for home page
@app.route('/')
def home():
    return render_template('index.html')

# Route for handling URL submission and processing
@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        url = request.form['url']

        # Extract features from the URL
        features = featureExtraction(url)

        # Define rules/logic to determine if URL is legitimate or phishing
        if (features[1] == 1 or                     # Have '@' symbol
            len(url) < 5 or                         # URL Length < 5
            any(char.isdigit() for char in url) or  # Contains a digit
            url.endswith('.xyz') or                 # Ends with 'xyz'
            not (url.startswith('http://') or url.startswith('https://') or url.startswith('www.')) or  # Doesn't start with 'http', 'https', or 'www.'
            any(c.islower() and c.isupper() for c in url)):  # Contains both uppercase and lowercase characters
            prediction_text = "Phishing"
        else:
            prediction_text = "Legitimate"

        # Determine which features were triggered (considered phishing)
        triggered_features = [feature_names[i] for i in range(len(features)) if features[i] == 1]

        return render_template('result.html', url=url, prediction_text=prediction_text, features=triggered_features)

if __name__ == '__main__':
    app.run(debug=True)
