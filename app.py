from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mail import Mail, Message
from stegano import lsb
from PIL import Image
import sqlite3
import requests
import json
import os
import secrets
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()
print(f"Email configuration: {os.getenv('EMAIL_USER')}")
print(f"Email password length: {len(os.getenv('EMAIL_PASSWORD', '')) if os.getenv('EMAIL_PASSWORD') else 0}")

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('EMAIL_USER')
mail = Mail(app)

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (email TEXT PRIMARY KEY, user_hash TEXT, image_path TEXT, 
                  created_at TIMESTAMP, last_reset TIMESTAMP)''')
    conn.commit()
    conn.close()

def get_user_info():
    try:
        ip = request.remote_addr
        print(f"Fetching geo data for IP: {ip}")
        
        if ip in ('127.0.0.1', 'localhost', '::1'):
            print("Local IP detected, using default values")
            geo_data = {
                'city': 'Local',
                'country_name': 'Local',
            }
        else:
            try:
                response = requests.get(f'https://ipapi.co/{ip}/json/')
                if response.status_code == 200:
                    geo_data = response.json()
                    print(f"Geo data received: {geo_data}")
                else:
                    print(f"Error response from ipapi.co: {response.status_code}")
                    geo_data = {
                        'city': 'Unknown',
                        'country_name': 'Unknown',
                    }
            except Exception as e:
                print(f"Error fetching geo data: {str(e)}")
                geo_data = {
                    'city': 'Unknown',
                    'country_name': 'Unknown',
                }
        
        user_agent = request.user_agent
        user_info = {
            'ip': ip,
            'city': geo_data.get('city', 'Unknown'),
            'country': geo_data.get('country_name', 'Unknown'),
            'os': user_agent.platform,
            'browser': user_agent.browser,
            'timestamp': datetime.now().isoformat()
        }
        print(f"Generated user info: {user_info}")
        return user_info
    except Exception as e:
        print(f"Error in get_user_info: {str(e)}")
        return {
            'ip': request.remote_addr,
            'city': 'Unknown',
            'country': 'Unknown',
            'os': request.user_agent.platform,
            'browser': request.user_agent.browser,
            'timestamp': datetime.now().isoformat()
        }

def generate_auth_image(email):
    try:
        user_hash = secrets.token_hex(32)
        print(f"Generated user hash: {user_hash}")
        
        user_info = get_user_info()
        print(f"User info before adding hash: {user_info}")
        
        user_info['user_hash'] = user_hash
        print(f"User info after adding hash: {user_info}")
        
        required_fields = ['ip', 'city', 'country', 'os', 'browser', 'timestamp', 'user_hash']
        for field in required_fields:
            if field not in user_info:
                raise ValueError(f"Missing required field: {field}")
        
        data = json.dumps(user_info, ensure_ascii=False)
        print(f"Serialized JSON data: {data}")
        
        base_image = Image.new('RGB', (800, 600), color='white')
        image_path = f'static/auth_images/{user_hash}.png'
        os.makedirs('static/auth_images', exist_ok=True)
        
        print("Attempting to hide data in image...")
        secret = lsb.hide(base_image, data)
        secret.save(image_path)
        print(f"Image saved to: {image_path}")
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('''INSERT OR REPLACE INTO users 
                     (email, user_hash, image_path, created_at, last_reset)
                     VALUES (?, ?, ?, ?, ?)''',
                  (email, user_hash, image_path, datetime.now(), datetime.now()))
        conn.commit()
        conn.close()
        print("Database entry created")
        
        msg = Message('Your ImageAuthAI Authentication Image',
                      recipients=[email])
        msg.body = f'''Your authentication image is attached.
        Please keep this image safe as it will be required for login.
        If you lose this image, you can request a new one through the reset system.'''
        
        with app.open_resource(image_path) as fp:
            msg.attach(image_path, 'image/png', fp.read())
        
        mail.send(msg)
        print("Email sent successfully")
        return user_hash
    except Exception as e:
        print(f"Error in generate_auth_image: {str(e)}")
        print(f"Error type: {type(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        raise

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        try:
            generate_auth_image(email)
            flash('Registration successful! Please check your email for the authentication image.')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error during registration: {str(e)}')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if 'auth_image' not in request.files:
            flash('No image uploaded')
            return redirect(request.url)
        
        file = request.files['auth_image']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        
        try:
            temp_path = 'static/temp_upload.png'
            file.save(temp_path)

            hidden_data = lsb.reveal(temp_path)
            user_data = json.loads(hidden_data)
            

            current_info = get_user_info()
            

            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE user_hash = ?', (user_data['user_hash'],))
            user = c.fetchone()
            conn.close()
            
            if not user:
                flash('Invalid authentication image')
                return redirect(request.url)

            created_at = datetime.fromisoformat(user_data['timestamp'])
            if datetime.now() - created_at > timedelta(days=7):
                flash('Authentication image has expired')
                return redirect(request.url)
            

            if user_data['country'] != current_info['country']:
                flash('Login attempt from different country')
                return redirect(request.url)
            
 
            session['user_email'] = user[0]
            flash('Login successful!')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash(f'Error during login: {str(e)}')
            return redirect(request.url)
            
    return render_template('login.html')

@app.route('/reset', methods=['GET', 'POST'])
def reset():
    if request.method == 'POST':
        email = request.form['email']
        try:
            generate_auth_image(email)
            flash('New authentication image has been sent to your email')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error during reset: {str(e)}')
    return render_template('reset.html')

@app.route('/dashboard')
def dashboard():
    if 'user_email' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', email=session['user_email'])

@app.route('/logout')
def logout():
    session.pop('user_email', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True) 