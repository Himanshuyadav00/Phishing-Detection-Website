# 🎣 Phishing Detection Website

## 📌 Overview

The **Phishing Detection Website** is a cybersecurity-focused web application that analyzes URLs to determine whether they are **safe or potentially malicious (phishing)**.

This project demonstrates how common phishing techniques can be detected using rule-based analysis and helps users understand online threats in a practical way.

---

## 🚀 Features

* 🔍 URL analysis for phishing detection
* 🔐 HTTPS security verification
* 📏 URL length and structure analysis
* ⚠️ Detection of suspicious characters and patterns
* 💡 Simple and user-friendly interface
* ⚡ Real-time results

---

## 🧠 Detection Techniques

The system uses rule-based heuristics to evaluate URLs:

### 1. Suspicious Domain Detection

* Identifies IP-based URLs instead of domain names
* Detects unusual or misleading domain patterns
* Checks for excessive subdomains

### 2. HTTPS Verification

* Verifies whether the URL uses secure HTTPS protocol
* Flags non-secure HTTP websites

### 3. URL Length Analysis

* Long URLs are often used to hide malicious intent

### 4. Special Characters Check

* Detects symbols like:

  * `@`
  * `-`
  * `//` (multiple redirects)

### 5. Redirection Behavior

* Identifies multiple or hidden redirects

---

## 🛠️ Tech Stack

| Layer    | Technology                  |
| -------- | --------------------------- |
| Frontend | HTML, CSS, JavaScript       |
| Backend  | Python (Flask)              |
| Logic    | Python (Regex, URL parsing) |

---

## 📂 Project Structure

```
phishing-detector/
│
├── app.py
├── utils/
│   └── detector.py
├── templates/
│   └── index.html
├── static/
│   ├── style.css
│   └── script.js
└── README.md
```

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/your-username/phishing-detector.git
cd phishing-detector
```

### 2️⃣ Install Dependencies

```bash
pip install flask
```

### 3️⃣ Run the Application

```bash
python app.py
```

### 4️⃣ Open in Browser

```
http://127.0.0.1:5000
```

---

## 💻 Usage

1. Enter a URL into the input field
2. Click on **Check**
3. View the result:

   * ✅ Safe
   * ⚠️ Phishing

---

## 🧪 Example

| Input URL                   | Result   |
| --------------------------- | -------- |
| https://google.com          | Safe     |
| http://192.168.0.1/login    | Phishing |
| http://free-money-offer.xyz | Phishing |

---

## 🔐 Security Note

This tool uses basic rule-based detection and is intended for **educational purposes only**.
It may not detect all advanced phishing techniques.

---

## 🚀 Future Enhancements

* 🤖 Machine Learning integration for better accuracy
* 🌐 API integration (Google Safe Browsing)
* 🧩 Browser extension version
* 🗄️ Database for storing phishing URLs

---

## 📚 Learning Outcomes

* Understanding phishing attacks
* Web development using Flask
* Secure coding practices
* Basic threat detection techniques

---

## 👨‍💻 Author

**Himanshu Yadav**
Cybersecurity Student

---

## 📜 License

This project is licensed under the MIT License.
