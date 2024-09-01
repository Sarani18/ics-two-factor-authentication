# Two-Factor Authentication with Python

This project demonstrates a Two-Factor Authentication (2FA) system using Python with Flask, MySQL, and Google Authenticator. It provides an example of how to integrate 2FA for enhanced security during user login.

## Project Overview

The application allows users to register and log in with 2FA using a QR code scanned by the Google Authenticator app. The 2FA setup generates a time-based OTP (One-Time Password) that the user must enter to complete the login process.

## Prerequisites

- **Python 3.11** or higher
- **MySQL** server
- **Google Authenticator app** (Available on iOS and Android)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Sarani18/ics-two-factor-authentication.git
cd two-factor-authentication
```

### 2. Set Up a Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
```

### 3. Install Required Python Packages
```bash
pip install -r requirements.txt
```

### 4. Set Up MySQL Database
#### 4.1 Create a MySQL Database
Log in to your MySQL server and create a new database:
```bash
CREATE DATABASE ics2fa;
```

#### 4.2 Create the users Table
Use the following SQL commands to create the necessary table:
```bash
USE ics2fa;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    otp_secret VARCHAR(255) NOT NULL
);
```

### 5. Configure Flask Application
Edit the app.py file to include your MySQL configuration details:
```bash
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'your_mysql_password'
app.config['MYSQL_DB'] = 'ics2fa'
```

### 6. Run the Flask Application
```bash
python app.py
```
The Flask development server will start and you can access the application at http://127.0.0.1:5000.
