from flask import Flask, render_template, request, redirect, url_for, session, g, jsonify
import sqlite3
import os
import time
import uuid
import random
from datetime import datetime, timedelta
from security import hash_password, verify_password

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a secure secret key

DATABASE = 'members.db'
SESSION_TIMEOUT = 20  # Set the session timeout period to 20 seconds

# Configure secure cookies
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=10)
)
print("Configured secure and HTTP-only session cookies.")

# Helper function to connect to the SQLite database
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = [dict((cur.description[idx][0], value) for idx, value in enumerate(row)) for row in cur.fetchall()]
    cur.close()
    return (rv[0] if rv else None) if one else rv

# Generate a random 4-character alphanumeric string for the CAPTCHA 
def generate_captcha():
    captcha_text = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=4))
    return captcha_text


    # Compare the user's input with the generated CAPTCHA text
def validate_captcha(user_input, captcha_text):
    return user_input.lower() == captcha_text.lower()

@app.before_request
def create_tables():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS members (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    membership_status TEXT NOT NULL
                )''')
    db.execute('''CREATE TABLE IF NOT EXISTS classes (
                    id INTEGER PRIMARY KEY,
                    class_name TEXT NOT NULL,
                    class_time TEXT NOT NULL
              )''')
    db.execute('''CREATE TABLE IF NOT EXISTS member_classes (
                    member_id INTEGER,
                    class_id INTEGER,
                    FOREIGN KEY (member_id) REFERENCES members (id),
                    FOREIGN KEY (class_id) REFERENCES classes (id)
                )''')
    db.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    salt TEXT NOT NULL,
                    hashed_password TEXT NOT NULL,
                    role TEXT NOT NULL,
                    failed_attempts INTEGER DEFAULT 0,
                    lockout_time TEXT DEFAULT NULL
              )''')
    db.commit()

#session timeout
@app.before_request
def check_session_timeout():
    # Check if the user is logged in
    if 'user' in session:
        last_activity_time = session.get('last_activity_time', None)
        current_time = time.time()
        
        print(f"[DEBUG] Last activity time: {last_activity_time}, Current time: {current_time}")
        
        # If last activity time is not set, set it to the current time
        if last_activity_time is None:
            session['last_activity_time'] = current_time
            print("[DEBUG] Setting last_activity_time for the first time.")
        else:
            elapsed_time = current_time - last_activity_time
            print(f"[DEBUG] Elapsed time: {elapsed_time}")
            if elapsed_time > SESSION_TIMEOUT:
                session.pop('user', None)
                session.pop('role', None)
                session.pop('last_activity_time', None)
                print("[DEBUG] Session timed out. Logging out.")
                return redirect(url_for('login', message="Session timed out. Please log in again."))
            else:
                session['last_activity_time'] = current_time
                print("[DEBUG] Session is still active. Updating last_activity_time.")
    else:
        print("[DEBUG] No user in session.")

#cache control headers
@app.after_request
def add_header(response):
    # Disable caching for authenticated pages
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

# Refresh CAPTCHA
@app.route('/refresh_captcha')
def refresh_captcha():
    captcha_text = generate_captcha()
    session['captcha_text'] = captcha_text
    return jsonify(captcha_text=captcha_text)

# Home Route (Login)
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        captcha_input = request.form['captcha']
        captcha_text = session.get('captcha_text')

        print(f"[DEBUG] Captcha input: {captcha_input}")
        print(f"[DEBUG] Captcha text: {captcha_text}")
        
        #refresh CAPTCHA if the user input is empty
        if not validate_captcha(captcha_input, captcha_text):
            print("[DEBUG] CAPTCHA validation failed.")
            session['captcha_text'] = generate_captcha()  # Refresh CAPTCHA
            return render_template('login.html', error="Invalid CAPTCHA. Please try again.", captcha_text=session['captcha_text'])
        
        user = query_db("SELECT * FROM users WHERE username = ?", [username], one=True)
        
        if user:
            if verify_password(user['hashed_password'], user['salt'], password):
                session['user'] = username
                session['role'] = user['role']
                session['last_activity_time'] = time.time()  # Set last activity time to the current time
                session['session_id'] = str(uuid.uuid4())  # # Generate a new session ID
                session.permanent = True
                print(f"[DEBUG] User {username} logged in. Setting last_activity_time.")
                session['captcha_text'] = generate_captcha() 
                return redirect(url_for('dashboard'))
            else:
                session['captcha_text'] = generate_captcha()  
                return render_template('login.html', error="Invalid password.", captcha_text=session['captcha_text'])
        else:
            print(f"[DEBUG] User {username} does not exist")
            session['captcha_text'] = generate_captcha()  
            return render_template('login.html', error="User does not exist.", captcha_text=session['captcha_text'])
    
    captcha_text = generate_captcha()
    session['captcha_text'] = captcha_text
    return render_template('login.html', captcha_text=captcha_text)

# Dashboard (for both staff and members)
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    username = session['user']
    role = session['role']
    print(f"[DEBUG] User {username} accessed dashboard.")
    return render_template('dashboard.html', username=username, role=role)

# Member Management Routes
@app.route('/add_member', methods=['GET', 'POST'])
def add_member():
    if 'user' not in session or session['role'] != 'staff':
        print("Redirected to login page due to unauthorized access.")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?,?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))
    
    return render_template('add_member.html')

# View specific member class
@app.route('/member/<int:member_id>/classes')
def member_classes(member_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    # Get member classes
    member = query_db("SELECT * FROM members WHERE id = ?", [member_id], one=True)
    classes = query_db("SELECT c.class_name, c.class_time FROM classes c "
                       "JOIN member_classes mc ON c.id = mc.class_id "
                       "WHERE mc.member_id = ?", [member_id])
    return render_template('member_classes.html', member=member, classes=classes)

# Register class
@app.route('/register_class/<int:member_id>', methods=['GET', 'POST'])
def register_class(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    classes = query_db("SELECT * FROM classes")  # Get all available classes
    if request.method == 'POST':
        class_id = request.form['class_id']
        db = get_db()
        db.execute("INSERT INTO member_classes (member_id, class_id) VALUES (?, ?)", (member_id, class_id))
        db.commit()
        return redirect(url_for('member_classes', member_id=member_id))
    return render_template('register_class.html', member_id=member_id, classes=classes)

# View members
@app.route('/view_members')
def view_members():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
        
    members = query_db("SELECT * FROM members")
    return render_template('view_members.html', members=members)

# Register a member
@app.route('/register_member', methods=['GET', 'POST'])
def register_member():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?,?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))
    
    return render_template('register_member.html')

# Class scheduling routes
@app.route('/add_class', methods=['GET', 'POST'])
def add_class():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        class_name = request.form['class_name']
        class_time = request.form['class_time']
        db = get_db()
        db.execute("INSERT INTO classes (class_name, class_time) VALUES (?,?)", (class_name, class_time))
        db.commit()
        return redirect(url_for('view_classes'))
    
    return render_template('add_class.html')

@app.route('/view_classes')
def view_classes():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    classes = query_db("SELECT * FROM classes")
    return render_template('view_classes.html', classes=classes)

# Deleting member
@app.route('/delete_member/<int:member_id>', methods=['POST'])
def delete_member(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    db = get_db()
     
    # Delete member from the database
    db.execute("DELETE FROM members WHERE id = ?", [member_id])
    
    # Also delete any classes associated with the member in the member_classes table
    db.execute("DELETE FROM member_classes WHERE member_id = ?", [member_id])
    
    db.commit()
    
    return redirect(url_for('view_members'))

# Logout route
@app.route('/logout')
def logout():
    username = session.pop('user', None)
    session.pop('role', None)
    session.pop('last_activity_time', None)
    print(f"[DEBUG] User {username} logged out.")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)