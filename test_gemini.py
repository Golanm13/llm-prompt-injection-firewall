import os
from dotenv import load_dotenv
from google import genai

load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")
model_name = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")

print(f"Testing model: {model_name}")
try:
    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model=model_name,
        contents="Hello, this is a connection test."
    )
    print("Success! Response:")
    print(response.text)
except Exception as e:
    print(f"Error during API call: {e}")