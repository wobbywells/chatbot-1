import streamlit as st
import secrets
import hashlib
import base64
import requests
from openai import OpenAI

# Function to generate code verifier and code challenge
def generate_pkce_pair():
    code_verifier = secrets.token_urlsafe(128)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b'=').decode('utf-8')
    return code_verifier, code_challenge

# Function to get the current URL of the Streamlit app
def get_current_url():
    if 'externalUrl' not in st.session_state:
        # Simulate obtaining the URL from a public deployment setting
        st.session_state.externalUrl = "http://localhost:8501"
    return st.session_state.externalUrl

# Show title and description.
st.title("💬 Chatbot")
st.write(
    "This is a simple chatbot that uses OpenAI's GPT-3.5 model to generate responses via OpenRouter."
)

# Step 1: Add connect and disconnect buttons
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if st.session_state.authenticated:
    if st.button("Disconnect"):
        st.session_state.authenticated = False
        st.session_state.api_key = None
        st.session_state.messages = []
else:
    if st.button("Connect"):
        # Generate PKCE pair
        code_verifier, code_challenge = generate_pkce_pair()

        # Store the code verifier in session state
        st.session_state.code_verifier = code_verifier

        # Get the current URL to use as the callback URL
        callback_url = get_current_url()

        # Redirect user to OpenRouter for authentication
        auth_url = (
            f"https://openrouter.ai/auth?callback_url={callback_url}&code_challenge={code_challenge}&code_challenge_method=S256"
        )
        st.write(f"[Click here to authenticate]({auth_url})")

# Step 2: Handle the authentication process manually
code = st.experimental_get_query_params().get("code")

if code and not st.session_state.authenticated:
    # Exchange the code for a user-controlled API key
    response = requests.post(
        'https://openrouter.ai/api/v1/auth/keys',
        json={
            'code': code[0],
            'code_verifier': st.session_state.code_verifier,
            'code_challenge_method': 'S256',
        }
    )
    api_key = response.json().get('key')
    st.session_state.api_key = api_key
    st.session_state.authenticated = True

if st.session_state.authenticated:
    # Step 3: Use the API key for making OpenAI-style requests
    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=st.session_state.api_key,
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

        # Generate a response using the OpenRouter API.
        response = client.chat.completions.create(
            extra_headers={
                "HTTP-Referer": get_current_url(),  # Optional, replace with your site URL
                "X-Title": "Chatbot App",  # Optional, replace with your app name
            },
            model="openai/gpt-3.5-turbo",
            messages=[
                {"role": m["role"], "content": m["content"]}
                for m in st.session_state.messages
            ]
        )

        # Extract the response content and store it in session state.
        response_content = response.choices[0].message.content
        with st.chat_message("assistant"):
            st.markdown(response_content)
        st.session_state.messages.append({"role": "assistant", "content": response_content})
else:
    st.info("Please connect to use the chatbot.", icon="🗝️")
