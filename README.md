# 🛡️ Digital Guardian

## Hybrid AI-Powered Cybersecurity & Fraud Detection System

**Digital Guardian** is a Hybrid AI-powered cybersecurity web application designed to detect and analyze spam, phishing, scams, financial fraud, suspicious URLs, and social-engineering threats.

The system combines **Machine Learning, Natural Language Processing (NLP), and rule-based cybersecurity intelligence** to generate explainable threat reports with risk scores, threat levels, scam categories, detected indicators, and security recommendations.

---

## 🚀 Key Features

- 🔐 User Registration & Login
- 🤖 Hybrid AI Threat Detection
- 💬 SMS / Message Analysis
- 🟢 WhatsApp Content Analysis
- 📧 Email Threat Analysis
- 📞 Call Transcript Analysis
- 🔗 Suspicious URL Detection
- 🎣 Phishing Detection
- 💳 Banking & Payment Fraud Detection
- 🔑 OTP / Credential Theft Detection
- 🎁 Lottery & Prize Scam Detection
- 💼 Fake Job Scam Detection
- 🧠 Social Engineering Detection
- 📊 Personalized Security Dashboard
- 📜 User-Specific Scan History
- 📈 Threat Analytics
- 🛡️ Guardian Mode
- 💡 Explainable Security Recommendations

---

## 🧠 Hybrid AI Architecture

Digital Guardian combines two different threat-detection mechanisms.

### 1. Machine Learning Engine

The Machine Learning engine analyzes textual content and predicts whether the content resembles legitimate or spam communication.

It uses:

- Natural Language Processing
- TF-IDF Vectorization
- Logistic Regression
- Spam Probability Estimation

### 2. Cybersecurity Rule Engine

The cybersecurity engine searches for suspicious patterns and indicators such as:

- OTP requests
- Password requests
- Banking impersonation
- Payment requests
- Suspicious URLs
- Prize/reward bait
- Fake job offers
- Urgency
- Fear manipulation
- Credential theft
- Social-engineering techniques

The results from both engines are combined to calculate the final **Guardian Risk Score**.

---

## 🏗️ System Architecture

```text
                         USER
                           │
                           ▼
                  ┌─────────────────┐
                  │ Flask Web App   │
                  └────────┬────────┘
                           │
                           ▼
                     Authentication
                           │
                           ▼
                   Multi-Channel Input
                           │
              ┌────────────┴────────────┐
              │                         │
              ▼                         ▼
      ┌───────────────┐        ┌─────────────────┐
      │ ML/NLP Engine │        │ Security Rules  │
      │               │        │     Engine      │
      │ TF-IDF        │        │                 │
      │ Logistic Reg. │        │ Fraud Patterns  │
      │ Spam Prob.    │        │ Scam Patterns   │
      └───────┬───────┘        └────────┬────────┘
              │                         │
              └────────────┬────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ Hybrid AI Engine│
                  └────────┬────────┘
                           │
                           ▼
                    Risk Score 0–100
                           │
                           ▼
                  Threat Classification
                           │
                           ▼
                   Explainable Report
                           │
                    ┌──────┴──────┐
                    ▼             ▼
                Dashboard       History
                                  │
                                  ▼
                              Analytics
```

---

## 🤖 Machine Learning Model

Digital Guardian uses an NLP-based spam classification model.

### ML Pipeline

```text
Raw Text
   ↓
Text Processing
   ↓
TF-IDF Vectorization
   ↓
Logistic Regression
   ↓
Spam Probability
   ↓
Hybrid Threat Engine
```

---

## 📚 Dataset

The Machine Learning model was trained using the **SMS Spam Collection Dataset**.

After dataset preparation and duplicate removal:

| Category | Samples |
|---|---:|
| HAM | 4,516 |
| SPAM | 642 |
| **Total** | **5,158** |

### Dataset Split

| Dataset | Samples |
|---|---:|
| Training | 4,126 |
| Testing | 1,032 |

---

## 📊 Model Performance

The trained Machine Learning model achieved:

| Metric | Score |
|---|---:|
| Accuracy | **98.06%** |
| Precision | **90.91%** |
| Recall | **93.75%** |
| F1 Score | **92.31%** |

### Confusion Matrix

```text
[[892  12]
 [  8 120]]
```

This represents:

- **892** legitimate messages correctly classified
- **120** spam messages correctly classified
- **12** legitimate messages incorrectly classified as spam
- **8** spam messages incorrectly classified as legitimate

---

## 🚨 Guardian Risk Score

Digital Guardian generates a final risk score between **0 and 100**.

The score combines the Machine Learning prediction with cybersecurity indicators detected by the rule engine.

### Example Threat Analysis

```text
ML Prediction:
SPAM

ML Spam Probability:
97.37%

Rule Score:
28/100

Final Risk Score:
70/100

Threat Level:
HIGH RISK

Threat Type:
Fraud

Scam Category:
Lottery / Prize Scam

Manipulation:
Reward / Greed
```

---

## 🔍 Explainable Threat Reports

Digital Guardian goes beyond simple spam classification by explaining **why content may be suspicious**.

Each analysis can contain:

- Guardian Risk Score
- Rule-Based Risk Score
- ML Classification
- ML Spam Probability
- Threat Level
- Threat Type
- Scam Category
- Threat Indicators
- Manipulation Techniques
- Detected URLs
- Security Recommendation

Example:

```text
Recommendation:

Avoid interacting with this content until the sender,
link, phone number, or request has been independently verified.
```

---

## 📊 Security Dashboard

Every registered user receives a personalized cybersecurity dashboard.

The dashboard provides:

- Total Scans
- Safe Scans
- Suspicious Scans
- Critical Threats
- Average Risk Score
- Guardian Score
- Most Used Channel
- Most Common Threat
- Recent Threat Activity
- Security Conclusion

---

## 📜 Scan History

Digital Guardian stores previous scan results for each authenticated user.

The history module records:

- Communication Channel
- Submitted Content
- Threat Type
- Scam Category
- Risk Score
- Threat Level
- Security Recommendation
- Date and Time

Users can also filter their history based on:

- Communication Channel
- Threat Level

---

## 📈 Security Analytics

The Analytics module summarizes previous scans and provides information such as:

- Total Content Analyzed
- Average Risk Score
- Threat-Level Distribution
- Channel Distribution
- Scam-Category Distribution
- Riskiest Communication Channel

---

## 🔐 User Authentication

Digital Guardian provides individual user accounts.

Authentication features include:

- User Registration
- User Login
- Secure Password Hashing
- Session Management
- Protected Routes
- Logout
- User-Specific Dashboard
- User-Specific Scan History
- User-Specific Analytics

Passwords are hashed before being stored in the database.

---

## 🛡️ Guardian Mode

Digital Guardian includes a **Guardian Mode** control that represents the user's protection status.

Guardian Mode can be displayed as:

```text
Guardian Mode ACTIVE
```

or:

```text
Guardian Mode PAUSED
```

In the current prototype, Guardian Mode functions as an application-level protection status.

Continuous device-level background monitoring is planned as a future enhancement.

---

## 🛠️ Technologies Used

### Programming Language

- Python

### Backend

- Flask
- Flask-SQLAlchemy
- Flask-Login
- Werkzeug

### Machine Learning & NLP

- Scikit-learn
- Pandas
- NumPy
- Joblib
- TF-IDF Vectorization
- Logistic Regression

### Frontend

- HTML5
- CSS3
- Jinja2

### Database

- SQLite

### Development Tools

- macOS Terminal
- Python Virtual Environment
- Git
- GitHub

---

## 📁 Project Structure

```text
Digital-Guardian/
│
├── app.py
├── README.md
├── requirements.txt
├── .gitignore
│
├── data/
│   └── sms_spam_dataset.csv
│
├── ml/
│   ├── download_dataset.py
│   ├── train_model.py
│   └── spam_model.pkl
│
├── services/
│   └── threat_engine.py
│
├── static/
│   └── css/
│       └── style.css
│
└── templates/
    ├── analytics.html
    ├── base.html
    ├── dashboard.html
    ├── history.html
    ├── index.html
    ├── login.html
    ├── register.html
    └── scanner.html
```

The local virtual environment and user database are intentionally excluded from the GitHub repository.

---

## ⚙️ Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/bharad1101/Digital-Guardian.git
```

Enter the project directory:

```bash
cd Digital-Guardian
```

---

### 2. Create a Virtual Environment

For macOS/Linux:

```bash
python3 -m venv venv
source venv/bin/activate
```

For Windows:

```bash
python -m venv venv
venv\Scripts\activate
```

---

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

### 4. Download the Dataset

```bash
python ml/download_dataset.py
```

The prepared dataset will be stored at:

```text
data/sms_spam_dataset.csv
```

---

### 5. Train the Machine Learning Model

Run:

```bash
python ml/train_model.py
```

The trained model will be generated at:

```text
ml/spam_model.pkl
```

---

### 6. Run Digital Guardian

Start the Flask application:

```bash
python app.py
```

The application should start locally at:

```text
http://127.0.0.1:5000
```

Open the address in your browser.

---

## 🧪 Testing the System

### Example Scam Message

```text
Congratulations! You won a free cash prize.
Click now to claim your reward.
```

Digital Guardian should detect spam/fraud indicators and generate a high-risk assessment.

### Example Safe Message

```text
Hey, are we meeting for class tomorrow morning?
```

The system should normally classify the content as legitimate with a low risk score.

---

## 🔄 Application Workflow

```text
Register
   ↓
Login
   ↓
Dashboard
   ↓
Select Scan
   ↓
Choose Communication Channel
   ↓
Enter Suspicious Content
   ↓
Hybrid AI Analysis
   ↓
Risk Score
   ↓
Threat Report
   ↓
Save Scan
   ↓
History
   ↓
Analytics
```

---

## 💡 What Makes Digital Guardian Different?

A traditional spam classifier may only provide:

```text
SPAM
```

or:

```text
NOT SPAM
```

Digital Guardian provides a more detailed and explainable result.

For example:

```text
Risk Score:
70/100

Threat Level:
HIGH RISK

Threat Type:
Fraud

Scam Category:
Lottery / Prize Scam

Manipulation:
Reward / Greed

Recommendation:
Avoid interacting with the content until
the sender or request has been independently verified.
```

Digital Guardian therefore combines **Machine Learning classification with cybersecurity intelligence and explainable risk analysis**.

---

## 🎯 Project Objective

The objective of Digital Guardian is to develop an intelligent and explainable cybersecurity platform capable of identifying potentially fraudulent digital communications using a combination of:

- Artificial Intelligence
- Machine Learning
- Natural Language Processing
- Cybersecurity Rules
- Fraud Pattern Detection

The system aims to help users make safer decisions before responding to suspicious messages, emails, calls, links, or online requests.

---

## 🔮 Future Enhancements

Digital Guardian can be expanded with:

- 🔳 QR Code Scam Detection
- 📷 Screenshot Analysis
- 🔤 OCR-Based Threat Detection
- 📄 Suspicious File Analysis
- 🎙️ Voice / Audio Scam Detection
- 🔗 Advanced URL Reputation Analysis
- 📧 Email Account Integration
- 🟢 Messaging Platform Integration
- 🔔 Real-Time Security Notifications
- 🛡️ Background Protection
- 🌐 Browser Extension
- 📱 Mobile Application
- ☁️ Cloud Deployment
- 🧠 Transformer-Based NLP Models
- 🌍 Multilingual Scam Detection
- 🔌 REST API
- 📊 Advanced Security Visualization

---

## ⚠️ Current Limitations

Digital Guardian is currently an **educational and research prototype**.

The Machine Learning model is primarily trained on SMS spam data.

Although the Hybrid AI rule engine can analyze user-submitted emails, WhatsApp content, call transcripts, messages, and URLs, the ML model itself has not been independently validated across every communication channel.

The current version does **not continuously access or monitor**:

- WhatsApp accounts
- Phone calls
- Email accounts
- SMS applications
- Operating-system activity

Real-time and background integrations are planned for future versions.

---

## 🔒 Privacy & Security

Users should avoid submitting highly sensitive information such as:

- Passwords
- Real OTPs
- Banking PINs
- Credit/Debit Card Numbers
- CVVs
- Private Keys
- Authentication Tokens

Digital Guardian is intended for cybersecurity education, experimentation, and research.

## ⭐ Digital Guardian

### Detect. Analyze. Explain. Protect.

**Hybrid AI for safer digital communication.**
