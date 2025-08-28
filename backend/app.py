from flask import Flask, request, jsonify, session, render_template, redirect, url_for
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
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from flask import send_file
import io
from auth import get_cognito
from flask import send_from_directory
from auth import get_secret_hash
from botocore.exceptions import ClientError
import hmac
import base64
from flask import Flask, session
from flask_session import Session

app = Flask(__name__, template_folder="../frontend", static_folder="../frontend")

# Enhanced Session Configuration
app.secret_key = "supersecretkey"
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_NAME'] = 'medvault_session'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # ✅ Add this
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour session lifetime
Session(app)



client = boto3.client('cognito-idp', region_name='eu-north-1')
sns = boto3.client('sns', region_name='ap-south-1')

# Load environment
load_dotenv()

CORS(app, supports_credentials=True, resources={
    r"/*": {
        "origins": ["http://localhost:5000", "http://127.0.0.1:5000"],
        "supports_credentials": True
    }
})


# Logging
logging.basicConfig(level=logging.DEBUG)

# AWS & Twilio Config
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_KEY")
AWS_REGION = os.getenv("AWS_REGION")
BUCKET = os.getenv("S3_BUCKET_NAME")

TWILIO_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE = os.getenv("TWILIO_PHONE")
DOCTOR_PHONE = os.getenv("DOCTOR_PHONE")
PATIENT_PHONE = os.getenv("PATIENT_PHONE")

# MySQL Config
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")

COGNITO_APP_CLIENT_ID = os.getenv("COGNITO_APP_CLIENT_ID")
COGNITO_CLIENT_SECRET = os.getenv("COGNITO_CLIENT_SECRET")
COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")

# AWS S3 Setup
s3 = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=AWS_REGION
)

def get_secret_hash(username, client_id, client_secret):
    message = username + client_id
    dig = hmac.new(
        key=client_secret.encode('utf-8'),
        msg=message.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()

def log_notification(type, message):
    try:
        conn = mysql.connector.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME
        )
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO notifications (type, message) VALUES (%s, %s)",
            (type, message)
        )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print("❌ Notification log error:", e)


@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route("/cognito-check-login")
def cognito_check_login():
    if session.get("doctor_logged_in"):
        return jsonify({ "logged_in": True, "role": "doctor" })
    elif session.get("patient_logged_in"):
        return jsonify({ "logged_in": True, "role": "patient" })
    else:
        # If neither flag is set, the user is not logged in
        return jsonify({ "logged_in": False })




@app.route("/cognito-signup", methods=["POST"])
def cognito_signup():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    role = data.get("role")

    try:
        secret_hash = get_secret_hash(email, COGNITO_APP_CLIENT_ID, COGNITO_CLIENT_SECRET)
        client.sign_up(
            ClientId=COGNITO_APP_CLIENT_ID,
            SecretHash=secret_hash,
            Username=email,
            Password=password,
            UserAttributes=[{ "Name": "email", "Value": email }]
        )

        connection = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        result = cursor.fetchone()

        if not result:
            cursor.execute("INSERT INTO users (email, role) VALUES (%s, %s)", (email, role))
            connection.commit()

        cursor.close()
        connection.close()

        return jsonify({ "message": "Signup successful" })

    except client.exceptions.UsernameExistsException:
        return jsonify({ "message": "Already registered. Check your email for code." })

    except Exception as e:
        print("Signup error:", e)
        return jsonify({ "error": "Signup failed: " + str(e) }), 400
from twilio.rest import Client

@app.route('/confirm-appointment', methods=['POST'])
def confirm_appointment():
    appointment_id = request.form.get("appointment_id")
    patient_name = request.form.get("patient_name")
    patient_phone = request.form.get("patient_phone")
    confirmed_time = request.form.get("confirmed_time")

    if not all([appointment_id, patient_name, patient_phone, confirmed_time]):
        return jsonify({"error": "Missing required fields"}), 400

    try:
        # ✅ Update DB
        conn = mysql.connector.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME
        )
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE appointments
            SET is_confirmed = TRUE,
                status = 'confirmed',
                confirmed_datetime = %s
            WHERE id = %s
        """, (confirmed_time, appointment_id))
        conn.commit()
        cursor.close()
        conn.close()

        # ✅ Send SMS using Twilio
        try:
            client = Client(TWILIO_SID, TWILIO_TOKEN)
            message = f"✅ Appointment Confirmed!\nHi {patient_name}, your appointment is scheduled for {confirmed_time}."

            client.messages.create(
                body=message,
                from_=TWILIO_PHONE,
                to=patient_phone
            )
        except Exception as sms_error:
            print("❗ Twilio SMS failed:", sms_error)

        # ✅ Log Notification
        log_notification("📅 Appointment Confirmed", f"{patient_name}'s appointment confirmed for {confirmed_time}.")

        return jsonify({"message": "Appointment confirmed successfully!"})

    except Exception as e:
        print("❌ DB update failed:", e)
        return jsonify({"error": "Database update failed"}), 500




@app.route('/confirm-signup', methods=['POST'])
def confirm_signup():
    data = request.get_json()
    email = data.get("email")
    code = data.get("code")
    role = data.get("role", "patient")

    try:
        secret_hash = get_secret_hash(email, COGNITO_APP_CLIENT_ID, COGNITO_CLIENT_SECRET)

        client.confirm_sign_up(
            ClientId=COGNITO_APP_CLIENT_ID,
            Username=email,
            ConfirmationCode=code,
            SecretHash=secret_hash
        )

        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        if not cursor.fetchone():
            cursor.execute("INSERT INTO users (email, role) VALUES (%s, %s)", (email, role))
            conn.commit()

        cursor.close()
        conn.close()

        return jsonify({"message": "✅ Email verified successfully. You can now login."})

    except Exception as e:
        print("Verification error:", e)
        return jsonify({"error": str(e)}), 500

def get_user_role_from_db(email):
    connection = mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )
    cursor = connection.cursor()
    cursor.execute("SELECT role FROM users WHERE email = %s", (email,))
    result = cursor.fetchone()
    cursor.close()
    connection.close()
    return result[0] if result else None


@app.route("/cognito-login", methods=["POST"])
def cognito_login():
    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        print("🧪 Received:", username, password)

        if not username or not password:
            return jsonify({"error": "Missing username or password"}), 400

        secret_hash = get_secret_hash(username)

        # Step 1: Authenticate the user
        response = client.initiate_auth(
            ClientId=COGNITO_APP_CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": password,
                "SECRET_HASH": secret_hash
            }
        )

        # Step 2: Fetch user attributes from Cognito
        user_data = client.admin_get_user(
            UserPoolId=COGNITO_USER_POOL_ID,
            Username=username
        )

        # Extract attributes
        role = None
        full_name = None
        phone_number = None

        for attr in user_data["UserAttributes"]:
            if attr["Name"] == "custom:role":
                role = attr["Value"]
            elif attr["Name"] == "name":
                full_name = attr["Value"]
            elif attr["Name"] == "phone_number":
                phone_number = attr["Value"]

        print("🎯 Role:", role)
        print("🙋 Full Name:", full_name)
        print("📱 Phone Number:", phone_number)

        if not role:
            return jsonify({"error": "Role not found in Cognito attributes"}), 403

        # ✅ Set session variables
        session.permanent = True
        session["username"] = username
        session["role"] = role
        session["name"] = full_name or "Unknown"
        session["phone"] = phone_number or username  # fallback if no phone_number in Cognito
        print("🔐 Session just after login:", dict(session))


        if role == "doctor":
            session["doctor_logged_in"] = True
            session["patient_logged_in"] = False
        elif role == "patient":
            session["patient_logged_in"] = True
            session["doctor_logged_in"] = False

        # ✅ Respond with redirect and user info
        return jsonify({
            "success": True,
            "redirect": "/frontend/doctor/doctor_main_dashboard.html" if role == "doctor" else "/frontend/patient/patient-dashboard.html",
            "role": role,
            "name": full_name or "Unknown",
            "phone": phone_number or username
        })

    except Exception as e:
        print("❌ Cognito login error:", str(e))
        return jsonify({"error": "Login failed. Check logs."}), 500

@app.route("/whoami")
def whoami():
    print("📦 Session at /whoami:", dict(session))
    return jsonify(dict(session))





@app.route('/cognito-logout', methods=['POST'])
def cognito_logout():
    session.clear()
    return jsonify({"message": "✅ Logged out successfully!"})

@app.route('/resend-code', methods=['POST'])
def resend_code():
    data = request.get_json()
    email = data.get("email")

    try:
        client.resend_confirmation_code(
            ClientId=COGNITO_APP_CLIENT_ID,
            Username=email
        )
        return jsonify({"message": "📩 Verification code resent successfully."})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/cognito-forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json()
    email = data.get("email")
    secret_hash = get_secret_hash(email, COGNITO_APP_CLIENT_ID, COGNITO_CLIENT_SECRET)
    try:
        client.forgot_password(
            ClientId=COGNITO_APP_CLIENT_ID,
            Username=email,
            SecretHash=secret_hash
        )
        return jsonify({"message": "📩 Code sent to email. Please check your inbox."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/cognito-reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()
    email = data.get("email")
    code = data.get("code")
    new_password = data.get("new_password")
    secret_hash = get_secret_hash(email, COGNITO_APP_CLIENT_ID, COGNITO_CLIENT_SECRET)
    try:
        client.confirm_forgot_password(
            ClientId=COGNITO_APP_CLIENT_ID,
            Username=email,
            ConfirmationCode=code,
            Password=new_password,
            SecretHash=secret_hash 
        )
        return jsonify({"message": "✅ Password reset successfully!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/check-login')
def check_login():
    if session.get("doctor_logged_in"):
        return jsonify({"logged_in": True})
    return jsonify({"logged_in": False})


from auth import client, get_secret_hash  # ✅ Reuse authenticated client

@app.route("/login", methods=["POST"])
def login():
    try:
        username = request.form.get("username") or request.json.get("username")
        password = request.form.get("password") or request.json.get("password")

        print("🧪 Received username:", username)
        print("🧪 Received password:", password)

        if not username or not password:
            return jsonify({ "success": False, "message": "Missing username or password." }), 400

        secret_hash = get_secret_hash(username, COGNITO_APP_CLIENT_ID, COGNITO_CLIENT_SECRET)

        # Step 1: Verify login credentials
        response = client.initiate_auth(
            ClientId=COGNITO_APP_CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": password,
                "SECRET_HASH": secret_hash
            }
        )

        # Step 2: Get user attributes (especially role)
        user_data = client.admin_get_user(
            UserPoolId=COGNITO_USER_POOL_ID,
            Username=username
        )

        role = None
        for attr in user_data["UserAttributes"]:
            if attr["Name"] == "custom:role":
                role = attr["Value"]
                break

        if not role:
            return jsonify({ "success": False, "message": "Role not found." }), 401

        session.permanent = True
        session["username"] = username
        session["role"] = role
        session["access_token"] = response["AuthenticationResult"]["AccessToken"]

        # ✅ Return redirect in JSON response
        return jsonify({
            "success": True,
            "role": role,
            "redirect": f"/frontend/{role}/{role}_main_dashboard.html",
            "message": "Login successful."
        })

    except ClientError as e:
        print("❌ Login error:", str(e))
        return jsonify({ "success": False, "message": "Invalid credentials." }), 401

    except Exception as e:
        print("❌ Server error:", str(e))
        return jsonify({ "success": False, "message": "Server error." }), 500


@app.route('/logout', methods=['GET'])
def logout():
    session.pop('doctor_logged_in', None)
    session.pop('doctor_username', None)
    session.pop('email', None)
    session.pop('role', None)
    return redirect('/doctor/login.html')

@app.route('/upload-report', methods=['POST'])
def upload_report():
    print("🔐 Session contents at upload:", dict(session))
    if not session.get("username"):
        print("❌ No session found!")
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    else:
        print("✅ Session found:", session.get("username"))

    file = request.files.get('report')
    report_type = request.form.get('report_type') or "Medical Report"
    phone = session.get("username")
    patient_name = session.get("name") or "Unknown"

    if file and file.filename:
        try:
            # ✅ Step 1: Upload to S3
            s3_key = f"{phone}_{report_type}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
            s3.upload_fileobj(file, BUCKET, s3_key)
            url = f"https://{BUCKET}.s3.{AWS_REGION}.amazonaws.com/{s3_key}"
            print("✅ S3 Upload Successful:", url)

            # ✅ Step 2: Save Metadata to MySQL
            conn = mysql.connector.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME
            )
            cursor = conn.cursor()
            insert_query = """
                INSERT INTO reports (patient_name, phone, report_type, s3_url, uploaded_at)
                VALUES (%s, %s, %s, %s, NOW())
            """
            insert_values = (patient_name, phone, report_type, url)
            cursor.execute(insert_query, insert_values)
            conn.commit()
            print("✅ DB Insert Successful")
            cursor.close()
            conn.close()

            # ✅ Log Notification
            log_notification("📄 Report Uploaded", f"Patient *{patient_name}* uploaded a {report_type}.")

            return jsonify({'success': True})
        except Exception as err:
            print("❌ Upload or DB Error:", err)
            return jsonify({'success': False, 'message': str(err)}), 500
    else:
        return jsonify({'success': False, 'message': 'No file received'}), 400





@app.route('/trigger-emergency', methods=['POST'])
def trigger_emergency():
    if not session.get("username"):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    patient_name = session.get("name", "Unknown")
    phone = session.get("phone", "N/A")

    sms_body = f"🚨 Emergency Alert!\nPatient '{patient_name}' ({phone}) needs help.\nCheck MedVault dashboard immediately."

    try:
        client = Client(TWILIO_SID, TWILIO_TOKEN)

        # Send SMS to doctor
        client.messages.create(
            body=sms_body,
            from_=TWILIO_PHONE,
            to=DOCTOR_PHONE
        )

        # Log notification
        log_notification("🚨 Emergency Alert", f"Patient *{patient_name}* triggered an emergency.")

        def delayed_call():
            time.sleep(60)
            twiml_msg = f"""<Response>
                <Say voice="Polly.Joanna" language="en-US">
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
            except Exception as e:
                print("❌ Voice Call Error:", e)

        threading.Thread(target=delayed_call).start()

        return jsonify({'success': True})
    except Exception as e:
        print("❌ SMS Error:", e)
        return jsonify({'success': False, 'message': 'SMS Failed'}), 500



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

    # Clean medicine name for URL
    medicine_clean = medicine.replace(' ', '+')
    buy_link = f"https://www.1mg.com/search/all?name={medicine_clean}"

    # ✅ Clean phone number
    phone_clean = phone.replace(" ", "").replace("+91", "").strip()
    to_whatsapp = f"whatsapp:+91{phone_clean}"
    from_whatsapp = 'whatsapp:+14155238886'

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

        message = client.messages.create(
            body=message_body,
            from_=from_whatsapp,
            to=to_whatsapp
        )
        print("✅ WhatsApp prescription sent:", message.sid)

        # Save to DB
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

@app.route('/get-appointments', methods=['GET'])
def get_pending_appointments():
    try:
        conn = mysql.connector.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM appointments 
            WHERE is_confirmed = FALSE 
            ORDER BY created_at DESC
        """)
        appointments = []
        for row in cursor.fetchall():
            appointments.append({
                "id": row["id"],
                "name": row["patient_name"],
                "phone": row["phone"],
                "date": row["date"].strftime("%Y-%m-%d"),
                "reason": row["reason"]
            })
        cursor.close()
        conn.close()
        return jsonify({"appointments": appointments})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get-confirmed-appointments', methods=['GET'])
def get_confirmed_appointments():
    try:
        conn = mysql.connector.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM appointments 
            WHERE is_confirmed = TRUE 
            ORDER BY confirmed_datetime DESC
        """)
        history = []
        for row in cursor.fetchall():
            history.append({
                "name": row["patient_name"],
                "phone": row["phone"],
                "reason": row["reason"],
                "confirmed_at": row["confirmed_datetime"].strftime("%Y-%m-%d %H:%M")
            })
        cursor.close()
        conn.close()
        return jsonify({"history": history})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/get-patient-reports', methods=['GET'])
def get_patient_reports():
    username = session.get("username")
    role = session.get("role")
    print("📦 Session at /get-patient-reports:", dict(session))

    # Safety check: Only allow logged-in patients
    if not username or role != "patient":
        return jsonify({"error": "Unauthorized"}), 403

    print("🔍 Comparing username:", repr(username))

    try:
        conn = mysql.connector.connect(
            host=DB_HOST, user=DB_USER,
            password=DB_PASSWORD, database=DB_NAME
        )
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM reports WHERE phone = %s ORDER BY uploaded_at DESC
        """, (username,))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        print("🧾 Reports found:", rows)

        reports = []
        for row in rows:
            # extract just the key from the stored full URL
            s3_key = row["s3_url"].split(f"{BUCKET}.s3.{AWS_REGION}.amazonaws.com/")[-1]

            # generate a pre-signed URL for secure access
            presigned_url = s3.generate_presigned_url(
                'get_object',
                Params={'Bucket': BUCKET, 'Key': s3_key},
                ExpiresIn=3600
            )

            reports.append({
                "url": presigned_url,
                "date_time": row["uploaded_at"].strftime("%d %B %Y at %I:%M %p"),
                "type": row["report_type"]
            })

        return jsonify({"reports": reports})

    except Exception as e:
        print("❌ DB Fetch Error:", e)
        return jsonify({"error": "DB error"}), 500




    
@app.route('/patient_login', methods=['POST'])
def patient_login():
    username = request.form.get("username")
    password = request.form.get("password")

    try:
        secret_hash = get_secret_hash(username, COGNITO_APP_CLIENT_ID, COGNITO_CLIENT_SECRET)
        response = client.initiate_auth(
            ClientId=COGNITO_APP_CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": password,
                "SECRET_HASH": secret_hash
            }
        )

        session.permanent = True
        session['patient_logged_in'] = True
        session['doctor_logged_in'] = False
        session['patient_username'] = username
        session['email'] = username
        session['role'] = "patient"
        session['access_token'] = response["AuthenticationResult"]["AccessToken"]

        return jsonify({
            "success": True,
            "redirect": "/patient/patient-dashboard.html"
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 401

@app.route('/patient_logout', methods=['GET'])
def patient_logout():
    session.pop('patient_logged_in', None)
    session.pop('patient_username', None)
    session.pop('email', None)
    session.pop('role', None)
    return redirect('/patient/patient_login.html')

@app.route('/patient-dashboard')
def patient_dashboard():
    if not session.get('patient_logged_in'):
        return redirect('/patient/patient_login.html')
    return send_from_directory(os.path.join(app.static_folder, 'patient'), 'patient-dashboard.html')

@app.route('/book-appointment', methods=['POST'])
def book_appointment():
    patient_name = request.form.get('patient_name')
    phone = request.form.get('phone')
    date = request.form.get('date')
    reason = request.form.get('reason')

    if not (patient_name and phone and date and reason):
        return jsonify({"error": "All fields are required"}), 400

    try:
        conn = mysql.connector.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO appointments (patient_name, phone, date, reason)
            VALUES (%s, %s, %s, %s)
        """, (patient_name, phone, date, reason))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        print("❌ DB Error:", e)
        return jsonify({"error": "❌ Failed to book appointment"}), 500



import boto3

def generate_presigned_url(bucket_name, object_key, expiration=3600):
    try:
        s3_client = boto3.client(
            "s3",
            region_name=AWS_REGION,
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY
        )
        url = s3_client.generate_presigned_url(
            ClientMethod='get_object',
            Params={
                'Bucket': bucket_name,
                'Key': object_key
            },
            ExpiresIn=expiration
        )
        return url
    except Exception as e:
        print("❌ Error generating pre-signed URL:", e)
        return None



@app.route('/search-patient', methods=['POST'])
def search_patient():
    query = request.form.get('query')
    if not query:
        return jsonify({'error': 'Missing patient name'}), 400

    try:
        conn = mysql.connector.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME
        )
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT s3_url FROM reports
            WHERE patient_name LIKE %s
            ORDER BY uploaded_at DESC
        """, (f"%{query}%",))
        s3_urls = [row['s3_url'] for row in cursor.fetchall()]

        # 🔁 Convert s3_url to object key and generate pre-signed URL
        report_links = []
        for url in s3_urls:
            if ".s3." in url:
                object_key = url.split(".amazonaws.com/")[-1]
                signed_url = generate_presigned_url(BUCKET, object_key)
                if signed_url:
                    report_links.append(signed_url)

        cursor.execute("""
            SELECT patient_name, medicine, instruction, quote, notes, created_at
            FROM prescriptions
            WHERE patient_name LIKE %s
            ORDER BY created_at DESC
        """, (f"%{query}%",))
        prescriptions = []
        for row in cursor.fetchall():
            prescriptions.append({
                "patient": row["patient_name"],
                "medicine": row["medicine"],
                "instruction": row["instruction"],
                "quote": row["quote"],
                "notes": row["notes"],
                "date": row["created_at"].strftime("%d %B %Y")
            })

        cursor.close()
        conn.close()

        return jsonify({
            "reports": report_links,
            "prescriptions": prescriptions
        })

    except Exception as e:
        print("❌ Error in /search-patient:", e)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/get-notifications', methods=['GET'])
def get_notifications():
    try:
        conn = mysql.connector.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME
        )
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT type, message, timestamp FROM notifications ORDER BY timestamp DESC LIMIT 20")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        # Format the timestamp as a readable string
        notifications = []
        for row in rows:
            formatted_time = row['timestamp'].strftime("%d %B %Y at %I:%M %p")
            notifications.append({
                "type": row['type'],
                "message": row['message'],
                "timestamp": formatted_time
            })

        return jsonify({"notifications": notifications})
    except Exception as e:
        print("❌ Notification fetch error:", e)
        return jsonify({"error": "Failed to load notifications"}), 500


@app.route('/generate-prescription-pdf', methods=['POST'])
def generate_prescription_pdf():
    data = request.form
    patient = data.get("patient_name")
    medicine = data.get("medicine")
    instruction = data.get("instruction")
    quote = data.get("quote", "Stay strong and get well soon!")

    if not all([patient, medicine, instruction]):
        return "❌ Missing fields", 400

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    pdf.setTitle("MedVault Prescription")

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, 750, "🩺 MedVault Prescription")

    pdf.setFont("Helvetica", 12)
    pdf.drawString(50, 710, f"👤 Patient Name: {patient}")
    pdf.drawString(50, 690, f"💊 Medicine: {medicine}")
    pdf.drawString(50, 670, f"📝 Instructions: {instruction}")
    pdf.drawString(50, 650, f"💬 Quote: {quote}")

    pdf.drawString(50, 620, f"📅 Generated on: {datetime.now().strftime('%d %B %Y at %I:%M %p')}")
    pdf.showPage()
    pdf.save()

    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name=f"{patient}_prescription.pdf", mimetype='application/pdf')

@app.route('/doctor_main_dashboard')
def doctor_dashboard():
    if not session.get("doctor_logged_in"):
        return redirect('/doctor/login.html')
    return send_from_directory(os.path.join(app.static_folder, 'doctor'), 'doctor_main_dashboard.html')

@app.route('/doctor_login', methods=['POST'])
def doctor_login():
    email = request.form['email']
    password = request.form['password']

    # Step 1: Try Cognito Login
    try:
        response = client.initiate_auth(
            ClientId=COGNITO_APP_CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': email,
                'PASSWORD': password
            }
        )
    except Exception as e:
        return f"Login failed: {str(e)}"

    # Step 2: Get the role from MySQL DB
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE email = %s", (email,))
        result = cursor.fetchone()
        conn.close()
    except Exception as e:
        return f"DB error: {str(e)}"

    # Step 3: Check if role is 'doctor'
    if result is None:
        return "User not found in DB.", 403

    role = result[0]

    if role != 'doctor':
        return "❌ Access Denied. You are not authorized to log in as a Doctor.", 403

    # Step 4: Login success
    session['email'] = email
    session['role'] = 'doctor'
    session['doctor_logged_in'] = True
    session['patient_logged_in'] = False
    session.permanent = True    # <--- ADD THIS LINE

    return redirect('/doctor_main_dashboard')

@app.route('/patient/report-upload')
def patient_report_upload():
    return send_from_directory('frontend/patient', 'Report-upload.html')

@app.route("/patient/<path:filename>")
def serve_patient_page(filename):
    return send_from_directory(os.path.join("frontend", "patient"), filename)

@app.route('/patient/patient_login.html')
def serve_patient_login():
    return send_from_directory(os.path.join(app.static_folder, 'patient'), 'patient_login.html')

@app.route('/<path:filename>')
def serve_frontend_files(filename):
    return send_from_directory(app.static_folder, filename)

@app.route('/doctor/<path:filename>')
def serve_doctor_files(filename):
    return send_from_directory(os.path.join(app.static_folder, 'doctor'), filename)

@app.route('/patient/<path:filename>')
def serve_patient_files(filename):
    return send_from_directory(os.path.join(app.static_folder, 'patient'), filename)

@app.route('/frontend/<path:filename>')
def serve_static_file(filename):
    return send_from_directory('../frontend', filename)

@app.route('/frontend/<path:path>')
def serve_frontend(path):
    return send_from_directory('frontend', path)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)