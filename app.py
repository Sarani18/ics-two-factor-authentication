# app.py

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
import pyotp
import qrcode
import io
import base64

app = Flask(__name__)
app.secret_key = 'ics2fa'  # Replace with a secure key

# MySQL configurations
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '121418'
app.config['MYSQL_DB'] = 'ics2fa'

mysql = MySQL(app)
bcrypt = Bcrypt(app)

def generate_secret_key():
    return pyotp.random_base32()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Generate OTP secret
        otp_secret = generate_secret_key()

        # try:
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (username, password, otp_secret) VALUES (%s, %s, %s)", 
                    (username, hashed_password, otp_secret))
        mysql.connection.commit()
        cur.close()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
        # except Exception as e:
        #     flash('Username already exists', 'danger')
        #     return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", [username])
        user = cur.fetchone()

        if user:
            password = user[2]

            if bcrypt.check_password_hash(password, password_candidate):
                session['logged_in'] = True
                session['username'] = username
                session['user_id'] = user[0]
                session['otp_secret'] = user[3]
                return redirect(url_for('two_factor'))
            else:
                flash('Invalid login', 'danger')
                return redirect(url_for('login'))
        else:
            flash('User not found', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/two_factor', methods=['GET', 'POST'])
def two_factor():
    if 'logged_in' not in session:
        flash('Please log in first', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp = request.form['otp']
        otp_secret = session['otp_secret']
        totp = pyotp.TOTP(otp_secret)

        if totp.verify(otp):
            session['authenticated'] = True
            session.pop('otp_verification_failed', None)  # Clear the failure flag if successful
            flash('Logged in successfully', 'success')
            return redirect(url_for('dashboard'))
        else:
            session['otp_verification_failed'] = True  # Set the failure flag
            flash('Invalid OTP, please try again.', 'danger')
            return redirect(url_for('two_factor'))

    # Generate QR Code for the first-time setup
    if 'authenticated' not in session:
        otp_secret = session['otp_secret']
        username = session['username']
        issuer_name = "MyFlaskApp"
        totp = pyotp.TOTP(otp_secret)
        uri = totp.provisioning_uri(name=username, issuer_name=issuer_name)

        # Generate QR Code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf)
        image_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')

        return render_template('two_factor.html', qr_code=image_base64)

    return render_template('two_factor.html')

@app.route('/dashboard')
def dashboard():
    if 'logged_in' in session and 'authenticated' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        flash('Please complete login', 'danger')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
