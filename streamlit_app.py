"""streamlit app trial"""

import streamlit as st
from urllib.parse import urlparse
from sklearn.preprocessing import MinMaxScaler
import pickle

# Load the model
file = open("phishing_rf_model.saved", "rb")
rf_model = pickle.load(file)
file.close()

# Load the MinMaxScaler
min_scaler = MinMaxScaler()

# Function to extract features from URL
def extract_features_from_url(url):
    parsed_url = urlparse(url)
    num_dots = url.count('.')
    subdomain_level = len(parsed_url.netloc.split('.')) - 1
    path_level = len(parsed_url.path.split('/')) - 1
    url_length = len(url)
    num_dash = url.count('-')
    num_dash_in_hostname = parsed_url.netloc.count('-')
    at_symbol = '@' in parsed_url.netloc
    tilde_symbol = '~' in parsed_url.netloc
    num_underscore = url.count('_')
    num_percent = url.count('%')
    num_query_components = len(parsed_url.query.split('&'))
    num_ampersand = url.count('&')
    num_hash = url.count('#')
    num_numeric_chars = sum(c.isdigit() for c in url)
    no_https = not url.startswith('https://')
    random_string = '?' in parsed_url.query
    ip_address = parsed_url.netloc.count('.')
    domain_in_subdomains = '.' in parsed_url.netloc[:-1]
    domain_in_paths = '.' in parsed_url.path
    https_in_hostname = 'https' in parsed_url.netloc
    hostname_length = len(parsed_url.netloc)
    path_length = len(parsed_url.path)
    query_length = len(parsed_url.query)
    double_slash_in_path = '//' in parsed_url.path
    num_sensitive_words = 0  # You need to define how to extract this feature
    return [num_dots, subdomain_level, path_level, url_length, num_dash,
            num_dash_in_hostname, at_symbol, tilde_symbol, num_underscore, num_percent,
            num_query_components, num_ampersand, num_hash, num_numeric_chars, no_https,
            random_string, ip_address, domain_in_subdomains, domain_in_paths, https_in_hostname,
            hostname_length, path_length, query_length, double_slash_in_path, num_sensitive_words]

# Function to predict using the model
def predict_phishing(url):
    features = extract_features_from_url(url)
    scaled_features = min_scaler.transform([features])
    prediction = rf_model.predict(scaled_features)
    return prediction

# Streamlit UI
def main():
    st.title("Phishing URL Detector")

    url_input = st.text_input("Enter the URL:")
    if st.button("Check Phishing"):
        if url_input:
            prediction = predict_phishing(url_input)
            if prediction[0] == 1:
                st.error("Phishing URL Detected!")
            else:
                st.success("Safe URL")
        else:
            st.warning("Please enter a URL")

if __name__ == "__main__":
    main()
