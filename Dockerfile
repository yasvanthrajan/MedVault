FROM python:3.10

WORKDIR /app

# Copy backend requirements and install
COPY backend/requirements.txt .
RUN pip install -r requirements.txt

# Copy backend and frontend
COPY backend/ ./backend
COPY frontend/ ./frontend

# Set Flask environment
ENV FLASK_APP=backend/app.py
ENV FLASK_RUN_HOST=0.0.0.0

# Expose port
EXPOSE 5000

# Start Flask
CMD ["python", "backend/app.py"]
