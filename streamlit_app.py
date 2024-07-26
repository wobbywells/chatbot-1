import streamlit as st
from openai import OpenAI
from urllib.parse import urlparse
from streamlit_javascript import st_javascript
import hashlib
import base64
import os
import requests

# Functions to get URL and hostname
def get_url():
    return st_javascript("await fetch('').then(r => window.parent.location.href)")

def url_to_hostname(url):
    uri = urlparse(url)
    return f"{uri.scheme}://{uri.netloc}/"

# Step 1: Generate code_verifier and code_challenge
def generate_code_challenge():
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode('utf-8')).digest()).decode('utf-8').rstrip('=')
    return code_verifier, code_challenge

code_verifier, code_challenge = generate_code_challenge()

# Get the site URL
site_url = get_url()
callback_url = url_to_hostname(site_url)

# Constants
CALLBACK_URL = callback_url  # Use the grabbed site URL

# Step 2: Send user to OpenRouter for authentication
auth_url = "https://openrouter.ai/auth?" + urlencode({
    "callback_url": CALLBACK_URL,
    "code_challenge": code_challenge,
    "code_challenge_method": "S256"
})

if "auth_code" not in st.session_state:
    st.markdown(f"[Login with OpenRouter]({auth_url})")

# Step 3: Handle the callback and extract the code
callback_params = st.experimental_get_query_params()
if "code" in callback_params:
    st.session_state.auth_code = callback_params["code"][0]

# Step 4: Exchange the code for an API key
if "auth_code" in st.session_state and "api_key" not in st.session_state:
    response = requests.post(
        'https://openrouter.ai/api/v1/auth/keys',
        json={
            'code': st.session_state.auth_code,
            'code_verifier': code_verifier,
            'code_challenge_method': "S256"
        }
    )
    if response.status_code == 200:
        st.session_state.api_key = response.json().get('api_key')
    else:
        st.error("Failed to retrieve API key.")

# Step 5: Use the API key in your application
if "api_key" in st.session_state:
    # Create an OpenAI client.
    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=st.session_state.api_key
    )

    # Create a session state variable to store the chat messages. This ensures that the
    # messages persist across reruns.
    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Display the existing chat messages via `st.chat_message`.
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Create a chat input field to allow the user to enter a message. This will display
    # automatically at the bottom of the page.
    if prompt := st.chat_input("What is up?"):

        # Store and display the current prompt.
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        # Generate a response using the OpenAI API.
        stream = client.chat.completions.create(
            extra_headers={
                "HTTP-Referer": CALLBACK_URL,  # Use the grabbed site URL
                "X-Title": "Your App Name",  # Replace with your app name
            },
            model="openai/gpt-3.5-turbo",
            messages=[
                {"role": m["role"], "content": m["content"]}
                for m in st.session_state.messages
            ],
            stream=True,
        )

        # Stream the response to the chat using `st.write_stream`, then store it in 
        # session state.
        with st.chat_message("assistant"):
            response = st.write_stream(stream)
        st.session_state.messages.append({"role": "assistant", "content": response})
