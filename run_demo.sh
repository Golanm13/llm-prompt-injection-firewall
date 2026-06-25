#!/bin/bash

# 1. Activate the virtual environment
source venv/bin/activate

# 2. Run the Backend (FastAPI) in the background on port 8000
echo "Starting Backend (FastAPI)..."
uvicorn src.main:app --host 127.0.0.1 --port 8000 --reload &

# Short delay to ensure the backend is up
sleep 2

# 3. Run the Frontend Chat App in the background
echo "Starting Frontend (Prompt Interface) on port 8501..."
streamlit run src/frontend/app.py &

# Short delay
sleep 2

# 4. Run the Security Dashboard in the background
echo "Starting Dashboard on port 8502..."
streamlit run dashboard.py &

# Keep terminal active and kill all background processes together on Ctrl+C
trap "kill 0" EXIT
wait
