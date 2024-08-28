from flask import Flask, request, session, redirect, url_for, render_template, flash
import psycopg2 
import psycopg2.extras
import re 
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'excel-coba-kp'

DB_HOST = "localhost"
DB_NAME = "lms"
DB_USER = "postgres"
DB_PASS = "Indonesia09"

def get_db_connection():
    return psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login/', methods=['GET', 'POST'])
def login():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        print(password)
 
        # Check if account exists using MySQL
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        # Fetch one record and return result
        account = cursor.fetchone()
 
        if account:
            password_rs = account['password']
            print(password_rs)
            # If account exists in users table in our database
            if check_password_hash(password_rs, password):
                # Create session data, we can access this data in other routes
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']

                # Fetch user role
                user_role = account['role']  # Assuming 'role' is a column in your users table
                
                # Redirect based on user role
                if user_role == 'teacher':
                    return redirect(url_for('guru_dashboard'))
                elif user_role == 'student':
                    return redirect(url_for('siswa_dashboard'))
                else:
                    # Handle unexpected roles, perhaps log an error or redirect to a default page
                    flash('Unknown user role')
                    return redirect(url_for('home'))
            else:
                # Account doesn't exist or username/password incorrect
                flash('Incorrect username/password')
        else:
            # Account doesn't exist or username/password incorrect
            flash('Incorrect username/password')
 
    return render_template('auth/login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form.get('fullname')
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        retype_password = request.form.get('retype_password')
        role = request.form.get('role')
        additional_info = request.form.get('additional_info')

        # Validasi data
        if password != retype_password:
            flash('Passwords do not match!')
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!')
        elif not re.match(r'[A-Za-z0-9]+', username):
            flash('Username must contain only characters and numbers!')
        elif not username or not password or not email or not role:
            flash('Please fill out the form!')
        elif role not in ['student', 'teacher']:
            flash('Invalid role selected!')
        elif not additional_info:
            flash(f'Please provide the { "NISN" if role == "student" else "NUPTK" }!')
        else:
            try:
                with get_db_connection() as conn:
                    with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
                        account = cursor.fetchone()

                        if account:
                            flash('Account already exists!')
                        else:
                            _hashed_password = generate_password_hash(password)
                            cursor.execute(
                                "INSERT INTO users (fullname, username, password, email, role, nisn_or_nuptk) VALUES (%s, %s, %s, %s, %s, %s)",
                                (fullname, username, _hashed_password, email, role, additional_info)
                            )
                            conn.commit()
                            flash('You have successfully registered!')
            except Exception as e:
                flash(f'An error occurred: {str(e)}')
                if conn is not None:
                    conn.rollback()  # Roll back the transaction on error

    return render_template('auth/register.html')

@app.route('/home')
def home():
    return 'Welcome to the home page!'

if __name__ == '__main__':
    app.run(debug=True)
