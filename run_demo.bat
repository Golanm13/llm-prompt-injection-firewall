@echo off
pushd %~dp0
echo Starting LLM-Firewall Demo Environment...

:: Start the FastAPI Backend
start cmd /k "title Backend Proxy && uvicorn src.main:app --reload --port 8000"

:: Start the Streamlit Dashboard
start cmd /k "title Security Dashboard && streamlit run dashboard.py"

:: Start the Streamlit Frontend Chat App
start cmd /k "title User Chat Interface && streamlit run src/frontend/app.py"

echo All services started!
popd