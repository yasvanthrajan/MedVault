# 🏥 MedVault – Cloud-Based Medical Record & Prescription Management System

> **A Secure, Cloud-Integrated Healthcare Platform**  
> Built with Flask, AWS Services, and CI/CD DevOps Deployment

---

## 🌟 Overview

**MedVault** is a cloud-based medical record and prescription management system designed to simplify doctor-patient communication and medical data handling.  
It enables **patients** to upload reports, trigger emergencies, and book appointments, while **doctors** can view reports, send prescriptions, and track patient history — all securely hosted on AWS.

---

## 🚀 Key Features

### 👨‍⚕️ Doctor Side
- Secure doctor login via **AWS Cognito**
- Dashboard to **view uploaded patient reports** (from S3)
- Send **prescriptions via WhatsApp/SMS** using Twilio
- Auto-attach **medicine purchase links** (e.g., MedPlus Chennai)
- Save all prescription data in **AWS RDS MySQL**
- Search patients and view complete medical history (reports + prescriptions)
- Track appointments booked by patients

### 🧑‍💻 Patient Side
- Secure patient login via **AWS Cognito**
- Upload medical reports (PDFs sent to AWS S3)
- Trigger **emergency alert** → sends SMS & voice call via Twilio
- View prescriptions from doctors (from RDS)
- Book appointments and view confirmations
- Receive real-time notifications through AWS SNS

---

## 🏗️ System Architecture

Below is the complete MedVault architecture connecting frontend, backend, and AWS cloud services:

![WhatsApp Image 2025-07-19 at 19 00 04_b4798aad](https://github.com/user-attachments/assets/96dc09fc-e595-4faf-99ec-810ed796a35e)


---

## 🧩 Tech Stack

| Category | Technology Used |
|-----------|-----------------|
| **Frontend** | HTML, CSS, JavaScript |
| **Backend** | Flask (Python) |
| **Authentication** | AWS Cognito |
| **Database** | AWS RDS (MySQL) |
| **File Storage** | AWS S3 |
| **Notifications** | Twilio API, AWS SNS |
| **Deployment** | Docker, AWS EC2, GitHub Actions (CI/CD) |
| **Version Control** | Git, GitHub |
| **Monitoring** | AWS CloudWatch (optional for logs) |

---

## 🧠 Project Workflow

1. **User Authentication**  
   - Users (Doctor/Patient) log in securely using AWS Cognito.  
   - Flask sessions manage authenticated routes.  

2. **Patient Workflow**  
   - Upload report (stored in S3, linked with Cognito user).  
   - View prescriptions (fetched from RDS).  
   - Book appointments.  
   - Trigger emergencies (Twilio SMS & call).  

3. **Doctor Workflow**  
   - Access dashboard → view patient reports from S3.  
   - Send prescriptions via Twilio (SMS/WhatsApp).  
   - Store prescription in RDS for record tracking.  
   - View appointments and patient history.  

4. **Backend Integration**  
   - Flask API routes handle data exchange between frontend and AWS.  
   - MySQL RDS stores structured prescription and appointment data.  

5. **CI/CD Deployment Pipeline**  
   - GitHub Actions builds and Dockerizes the Flask backend.  
   - Automatically SSH-deploys to **AWS EC2** instance.  
   - Containers restart with updated image on every commit.  

---

## ⚙️ AWS Services Breakdown

| Service | Purpose |
|----------|----------|
| **Amazon S3** | Store patient reports (PDFs) |
| **Amazon RDS (MySQL)** | Store prescription, appointment, and patient metadata |
| **Amazon Cognito** | Handle user authentication and session tokens |
| **Amazon SNS** | Push notifications for patient updates |
| **Amazon EC2** | Host backend using Docker |
| **Twilio API** | Send emergency SMS, voice calls, and prescription messages |
| **GitHub Actions** | Automate CI/CD pipeline for deployment |

---

## 🖥️ Screenshots
📷 Landing Page (Doctor/Patient Login):
![MixCollage-25-Oct-2025-08-39-AM-1995](https://github.com/user-attachments/assets/7780485a-1d33-4139-b3eb-08bda14a364a)
📷 Patient Dashboard (Upload + Emergency + Appointments):
<img width="957" height="413" alt="patient" src="https://github.com/user-attachments/assets/017f2244-22d8-42ab-9ce8-36873275fbd1" />
📷 Doctor Dashboard (View Reports + Send Prescription):
<img width="959" height="415" alt="doctor" src="https://github.com/user-attachments/assets/05fcf9d7-6d55-4a16-b6fa-48075fa06cbe" />
📷 Database:
<img width="730" height="326" alt="db" src="https://github.com/user-attachments/assets/3aac43ce-3405-40f7-a64a-5f3f88b22de6" />
📷 AWS Console (EC2, RDS, S3 setup):
![MixCollage-25-Oct-2025-08-42-AM-8235](https://github.com/user-attachments/assets/887cdf3e-96a6-46ca-afd4-0497491b8553)
📷  CI/CD GitHub Actions pipeline success:
<img width="959" height="463" alt="cicd" src="https://github.com/user-attachments/assets/ecf09c0d-a786-474a-98dd-f03349d860af" />
📷 Messages:
![Messages](https://github.com/user-attachments/assets/62cc2c3d-5632-4704-9770-731cfe1ee3cd)



---

## 🧩 Folder Structure (Simplified)
MedVault/
│
├── backend/
│ ├── app.py
│ ├── routes/
│ │ ├── patient_routes.py
│ │ ├── doctor_routes.py
│ └── templates/
│
├── frontend/
│ ├── index.html
│ ├── doctor_login.html
│ ├── patient_login.html
│ ├── doctor_dashboard.html
│ ├── patient_dashboard.html
│ ├── upload_report.html
│ ├── book_appointment.html
│
│ ├── css/
│ 
│
├── Dockerfile
├── requirements.txt
├── README.md
└── .github/
└── workflows/
└── deploy.yml


---

## 🧪 Deployment Notes

- Backend containerized using **Docker**
- Hosted on **AWS EC2 (Ubuntu)**  
- RDS and S3 configured in **eu-north-1 region**
- Domain secured via **NGINX + Certbot (optional HTTPS)**
- CI/CD pipeline automates:
  - Build → Push → SSH → Restart container
- Environment variables stored securely in EC2 or GitHub Secrets

---

## 💬 Challenges Faced & Learnings

- Integrating **AWS Cognito sessions** with Flask for dual-role login (Doctor/Patient)
- Handling **Twilio WhatsApp + SMS** automation
- Managing **RDS connection pooling** and error handling
- Optimizing **CI/CD pipeline** for seamless Docker deployment
- Structuring **frontend dashboards** for clarity and functionality

---

## 🏁 Final Outcome

✅ Fully functional **end-to-end cloud healthcare system**  
✅ Secure multi-role authentication with **AWS Cognito**  
✅ Automated **DevOps pipeline** using **GitHub Actions & Docker**  
✅ Deployed and hosted on **AWS EC2**  
✅ Integrated **S3, RDS, SNS, and Twilio** successfully

---

## 🔗 Live Demo / Repo

🌐 **Live Project:** _[http://13.51.162.84/](http://13.51.162.84/)_  
💻 **GitHub Repository:** _[https://github.com/yasvanthrajan/MedVault](https://github.com/yasvanthrajan/MedVault)_
---

## 🧑‍💻 Developed By

**👨‍💻 Yasvanth Rajan E**  
B.Tech – St. Joseph’s College of Engineering  
AWS Certified Cloud Practitioner | DevOps Enthusiast  
📩 [LinkedIn Profile](https://www.linkedin.com/in/yasvanth-rajan-e-6714bb295)  

---

⭐ *If you liked this project, don’t forget to star the repository and share feedback!*


