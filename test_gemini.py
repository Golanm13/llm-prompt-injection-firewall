import os
from google.genai import Client

api_key = os.getenv("GEMINI_API_KEY")
print(f"Found API Key in environment: {api_key[:10] if api_key else 'None'}...")

try:
    client = Client(api_key=api_key)
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents="Hello, this is a diagnostic test.",
    )
    print("\n--- Success! Response from Gemini ---")
    print(response.text)
except Exception as e:
    print("\n--- Error details from Google API ---")
    print(str(e))