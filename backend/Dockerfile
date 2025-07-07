# ✅ Use official Python image
FROM python:3.10

# ✅ Set working directory
WORKDIR /app

# ✅ Copy all backend code
COPY . .

# ✅ Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# ✅ Expose the Flask port
EXPOSE 5000

# ✅ Start the app
CMD ["python", "app.py"]
