from datetime import datetime
import ipaddress
import urllib
import whois
from urllib.parse import urlparse
import re
import requests
from bs4 import BeautifulSoup

# Function to check if the URL contains an IP address
def havingIP(url):
    try:
        ipaddress.ip_address(urlparse(url).netloc)
        return 1
    except ValueError:
        return 0

# Function to check if the URL contains the '@' symbol
def haveAtSign(url):
    return 1 if '@' in urlparse(url).netloc else 0

# Function to check URL length (phishing URLs often have long URLs)
def urlLength(url):
    return 1 if len(url) < 5 else 0

# Function to calculate URL depth (number of segments in the path)
def urlDepth(url):
    segments = urlparse(url).path.split('/')
    return len([segment for segment in segments if segment])  # Count non-empty segments

# Function to check for excessive redirections (often indicative of phishing)
def redirection(url):
    return 1 if url.count('//') > 6 else 0

# Function to check if HTTPS is used in the URL
def httpsInUrl(url):
    return 1 if 'https' in urlparse(url).scheme else 0

# Function to detect URL shortening services in the URL
def urlShort(url):
    shortening_services = (r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
                           r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
                           r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
                           r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|"
                           r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|"
                           r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|"
                           r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|"
                           r"tr\.im|link\.zip\.net")
    return 1 if re.search(shortening_services, url) else 0

# Function to check for prefixes or suffixes in the domain name (e.g., '-' or '@')
def prefixSuffix(url):
    return 1 if '-' in urlparse(url).netloc else 0

# Function to check if DNS records exist for the domain
def dnsRecordExists(url):
    try:
        whois.whois(urlparse(url).netloc)
        return 1
    except Exception:
        return 0

# Function to retrieve the domain age (in months)
def domainAge(domain_name):
    try:
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date

        if isinstance(creation_date, str) or isinstance(expiration_date, str):
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")

        age_in_months = (expiration_date - creation_date).days / 30

        return 1 if age_in_months < 6 else 0
    except Exception:
        return 1

# Function to check if the domain is about to expire (in months)
def domainExpiry(domain_name):
    try:
        expiration_date = domain_name.expiration_date

        if isinstance(expiration_date, str):
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")

        time_until_expiry = (expiration_date - datetime.now()).days / 30

        return 1 if time_until_expiry < 6 else 0
    except Exception:
        return 1

# Function to check if the URL contains an iframe (potential phishing indicator)
def iframe(response):
    try:
        return 1 if re.findall(r"<iframe|<frameBorder", response.text) else 0
    except Exception:
        return 1

# Function to check if the URL triggers mouse-over events (potential phishing indicator)
def mouseOver(response):
    try:
        return 1 if re.findall(r"<script>.+onmouseover.+</script>", response.text) else 0
    except Exception:
        return 1

# Function to check if the URL disables right-click (potential phishing indicator)
def rightClick(response):
    try:
        return 1 if re.findall(r"event\.button\s*==\s*2", response.text) else 0
    except Exception:
        return 1

# Function to check if the URL triggers multiple redirections (potential phishing indicator)
def forwarding(response):
    try:
        return 1 if len(response.history) > 4 else 0
    except Exception:
        return 1

# Function to detect unusual extensions in the URL
def unusualExtension(url):
    unusual_extensions = (r"\.xyz|\.online|\.website|\.space|\.site|\.tech|\.info|\.pw|\.me|\.club")
    return 1 if re.search(unusual_extensions, url) else 0

# Function to detect numeric digits in the URL path (potential phishing indicator)
def numericDigits(url):
    path = urlparse(url).path
    return 1 if any(char.isdigit() for char in path) else 0

# Function to extract all features from a given URL
def featureExtraction(url):
    features = []

    features.append(havingIP(url))
    features.append(haveAtSign(url))
    features.append(urlLength(url))
    features.append(urlDepth(url))
    features.append(redirection(url))
    features.append(httpsInUrl(url))
    features.append(urlShort(url))
    features.append(prefixSuffix(url))

    try:
        domain_info = whois.whois(urlparse(url).netloc)
    except Exception:
        domain_info = None

    features.append(dnsRecordExists(url))
    features.append(1 if domain_info else domainAge(domain_info))
    features.append(1 if domain_info else domainExpiry(domain_info))

    try:
        response = requests.get(url)
    except Exception:
        response = None

    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(forwarding(response))
    features.append(unusualExtension(url))
    features.append(numericDigits(url))

    # Ensure the feature vector has exactly 18 elements
    if len(features) != 18:
        features = features[:18]  # Trim to first 18 features

    return features
