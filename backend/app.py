from flask import Flask, request, jsonify, session, render_template, redirect
import boto3
import hashlib
import os
import threading
import time
import logging
import traceback
import mysql.connector
from twilio.rest import Client
from dotenv import load_dotenv
from datetime import datetime
from flask_cors import CORS
import random
import requests

app = Flask(__name__)

# ✅ Load environment
load_dotenv()

# ✅ Secret key for session
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecretkey")

# ✅ CORS setup
CORS(app, supports_credentials=True)

# ✅ Logging
logging.basicConfig(level=logging.DEBUG)

# ✅ AWS & Twilio Config
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_KEY")
AWS_REGION = os.getenv("AWS_REGION")
BUCKET = os.getenv("S3_BUCKET_NAME")

TWILIO_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE = os.getenv("TWILIO_PHONE")
DOCTOR_PHONE = os.getenv("DOCTOR_PHONE")
PATIENT_PHONE = os.getenv("PATIENT_PHONE")

# ✅ MySQL Config
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")

# ✅ AWS S3 Setup
s3 = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=AWS_REGION
)

@app.route('/')
def home():
    return "MedVault Backend Running 🚀"

@app.route('/check-login')
def check_login():
    if session.get("doctor_logged_in"):
        return jsonify({"logged_in": True})
    return jsonify({"logged_in": False})

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return "❌ Missing username or password", 400

    try:
        conn = mysql.connector.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM doctors 
            WHERE username = %s AND password = SHA2(%s, 256)
        """, (username, password))

        doctor = cursor.fetchone()
        cursor.close()
        conn.close()

        if doctor:
            session['doctor_logged_in'] = True
            session['doctor_name'] = doctor['full_name']
            return jsonify({"message": "✅ Login successful"})
        else:
            return "❌ Invalid credentials", 401

    except Exception as e:
        print("❌ Login error:", e)
        return "❌ Internal Server Error", 500

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('doctor_logged_in', None)
    session.pop('doctor_name', None)
    return jsonify({"message": "✅ Logged out successfully"})

@app.route('/upload-report', methods=['POST'])
def upload_report():
    file = request.files.get('report_file')
    patient_name = request.form.get('patient_name')
    phone = request.form.get('phone')  # ✅ NEW
    report_type = request.form.get('report_type')

    if file and file.filename:
        s3_key = f"{patient_name}_{report_type}_{file.filename}"
        s3.upload_fileobj(file, BUCKET, s3_key)
        url = f"https://{BUCKET}.s3.{AWS_REGION}.amazonaws.com/{s3_key}"

        try:
            conn = mysql.connector.connect(
                host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME
            )
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO reports (patient_name, phone, report_type, s3_url)
                VALUES (%s, %s, %s, %s)
            """, (patient_name, phone, report_type, url))
            conn.commit()
            cursor.close()
            conn.close()
            return "✅ Report uploaded and saved successfully!"
        except Exception as e:
            print("❌ DB error while saving report:", e)
            return "❌ Failed to save to DB", 500
    else:
        return "❌ No file received!", 400


@app.route('/trigger-emergency', methods=['POST'])
def trigger_emergency():
    patient_name = request.form.get('patient_name')
    if not patient_name:
        return "❌ Patient name required!", 400

    client = Client(TWILIO_SID, TWILIO_TOKEN)
    sms_body = f"🚨 Emergency Alert!\nPatient '{patient_name}' needs help.\nCheck MedVault dashboard immediately."

    try:
        message = client.messages.create(
            body=sms_body,
            from_=TWILIO_PHONE,
            to=DOCTOR_PHONE
        )
    except Exception as e:
        return "❌ SMS Failed", 500

    def delayed_call():
        time.sleep(60)
        twiml_msg = f"""<Response>
            <Say voice=\"Polly.Joanna\" language=\"en-US\">
                Emergency alert from MedVault!
                Patient needs your urgent attention.
                Please check the SMS and MedVault dashboard now.
            </Say>
        </Response>"""
        try:
            client.calls.create(
                twiml=twiml_msg,
                from_=TWILIO_PHONE,
                to=DOCTOR_PHONE
            )
        except:
            pass

    threading.Thread(target=delayed_call).start()

    return "🚨 Emergency alert sent via SMS. Voice call will follow in 60 seconds."

@app.route('/get-latest-report/<patient_name>', methods=['GET'])
def get_latest_report(patient_name):
    response = s3.list_objects_v2(Bucket=BUCKET)
    if 'Contents' not in response:
        return jsonify({'error': 'No reports found in bucket'}), 404

    reports = [obj['Key'] for obj in response['Contents'] if obj['Key'].lower().startswith(patient_name.lower())]
    if not reports:
        return jsonify({'error': f'No reports found for {patient_name}'}), 404

    reports.sort(reverse=True)
    latest_key = reports[0]

    url = s3.generate_presigned_url('get_object', Params={'Bucket': BUCKET, 'Key': latest_key}, ExpiresIn=3600)

    return jsonify({'report_url': url})

@app.route('/send-prescription', methods=['POST'])
def send_prescription():
    data = request.form
    patient_name = data.get('patient_name')
    phone = data.get('phone')
    medicine = data.get('medicine')
    instruction = data.get('instruction')
    quote = data.get('quote')
    notes = data.get('notes', '')

    if not all([patient_name, medicine, instruction, phone]):
        return "❌ Missing required fields", 400

    # ✅ Auto-fetch a quote if not provided
    if not quote:
        try:
            response = requests.get("https://type.fit/api/quotes")
            if response.status_code == 200:
                quotes = response.json()
                quote = random.choice(quotes)['text']
            else:
                quote = "Stay strong and get well soon!"
        except:
            quote = "Stay strong and get well soon!"

    # ✅ Generate medicine link (1mg.com)
    medicine_clean = medicine.replace(' ', '+')
    buy_link = f"https://www.1mg.com/search/all?name={medicine_clean}"

    message_body = f"""
💊 *Prescription from MedVault*
*Patient:* {patient_name}
*Medicine:* {medicine}
*Instruction:* {instruction}
🔗 *Buy Online:* {buy_link}
🧠 {quote}
"""

    try:
        client = Client(TWILIO_SID, TWILIO_TOKEN)
        from_whatsapp = 'whatsapp:+14155238886'
        to_whatsapp = f'whatsapp:{phone}'

        message = client.messages.create(
            body=message_body,
            from_=from_whatsapp,
            to=to_whatsapp
        )
        print("✅ WhatsApp prescription sent:", message.sid)

        # ✅ Save to MySQL
        save_prescription_to_db(patient_name, medicine, instruction, quote, phone, notes)

    except Exception as e:
        print("❌ WhatsApp error:", e)
        return "❌ Failed to send WhatsApp message", 500

    return "✅ Prescription sent to patient via WhatsApp!"

def save_prescription_to_db(patient_name, medicine, instruction, quote, phone, notes=""):
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = conn.cursor()
        query = """
            INSERT INTO prescriptions (patient_name, phone, medicine, instruction, quote, notes)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (patient_name, phone, medicine, instruction, quote, notes))
        conn.commit()
        cursor.close()
        conn.close()
        print("✅ Prescription saved to MySQL")
    except Exception as e:
        print("❌ Failed to save prescription to DB:", e)


@app.route('/get-patient-appointments', methods=['GET'])
def get_patient_appointments():
    phone = request.args.get('phone')
    appointments = []
    try:
        conn = mysql.connector.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM appointments
            WHERE phone = %s AND is_confirmed = TRUE
            ORDER BY confirmed_datetime DESC
        """, (phone,))
        for row in cursor.fetchall():
            appointments.append({
                "confirmed_datetime": row["confirmed_datetime"].strftime("%d %B %Y at %I:%M %p"),
                "reason": row["reason"]
            })
        cursor.close()
        conn.close()
        return jsonify({"appointments": appointments})
    except Exception as e:
        return jsonify({"error": "Failed to fetch"}), 500

@app.route('/get-patient-prescriptions', methods=['GET'])
def get_patient_prescriptions():
    phone = request.args.get('phone')
    prescriptions = []
    try:
        conn = mysql.connector.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM prescriptions WHERE phone = %s ORDER BY created_at DESC
        """, (phone,))
        for row in cursor.fetchall():
            prescriptions.append({
                "medicine": row["medicine"],
                "instruction": row["instruction"],
                "quote": row["quote"],
                "date": row["created_at"].strftime("%d %B %Y"),
                "notes": row.get("notes", "")
            })
        cursor.close()
        conn.close()
        return jsonify({"prescriptions": prescriptions})
    except Exception as e:
        return jsonify({"error": "Failed to fetch"}), 500

@app.route('/get-patient-reports', methods=['GET'])
def get_patient_reports():
    phone = request.args.get('phone')
    reports = []
    try:
        conn = mysql.connector.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM reports WHERE phone = %s ORDER BY uploaded_at DESC
        """, (phone,))
        for row in cursor.fetchall():
            reports.append({
                "url": row["s3_url"],
                "date_time": row["uploaded_at"].strftime("%d %B %Y at %I:%M %p"),
                "type": row["report_type"]
            })
        cursor.close()
        conn.close()
        return jsonify({"reports": reports})
    except Exception as e:
        return jsonify({"error": "Failed to fetch"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
