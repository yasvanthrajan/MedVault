FROM python:3.10

# Set working directory inside the container
WORKDIR /app

# Copy backend requirements and install dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend and frontend code
COPY backend/ ./backend
COPY frontend/ ./frontend

# Set environment variables
ENV FLASK_APP=backend/app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV PYTHONUNBUFFERED=1

# Expose Flask port
EXPOSE 5000

# Run Flask app
CMD ["python", "backend/app.py"]
