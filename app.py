from flask import Flask, request, session, redirect, url_for, render_template, flash
import psycopg2 
import psycopg2.extras
import re 
import secrets
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'excel-coba-kp'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@localhost:5432/lms'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

DB_HOST = "localhost"
DB_NAME = "sampledb"
DB_USER = "postgres"
DB_PASS = "Indonesia09"

def get_db_connection():
    return psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    nisn_or_nuptk = db.Column(db.String(50), nullable=False)

class kelas_ajar(db.Model):
    __tablename__='kelas_ajar'
    id_kelas = db.Column(db.Integer, primary_key=True)
    nama_mapel = db.Column(db.String(255), nullable=False)
    kelas = db.Column(db.String(5), nullable=False)

class enrollment(db.Model):
    __tablename__='enrollment'
    id_kelas = db.Column(db.Integer, db.ForeignKey('kelas_ajar.id_kelas'), primary_key=True, nullable=False)
    id_user = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True, nullable=False)
    token = db.Column(db.String(20), nullable=False)

class kuis(db.Model):
    __tablename__='kuis'
    id_kuis = db.Column(db.Integer, primary_key=True)
    id_kelas = db.Column(db.Integer, db.ForeignKey('kelas_ajar.id_kelas'), nullable=False)
    judul_kuis = db.Column(db.String(255), nullable=False)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/loginAdmin/', methods=['GET', 'POST'])
def loginAdmin():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()

        if not username or not password:
            flash('Please enter both username and password.')
            return render_template('admin/login-v2.html')

        try:
            with get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                    cursor.execute('SELECT * FROM admins WHERE username = %s', (username,))
                    account = cursor.fetchone()

                    if account and account['password'] == password:
                        session['loggedin'] = True
                        session['id'] = account['id']
                        session['username'] = account['username']
                        return redirect(url_for('admin_dashboard'))
                    else:
                        flash('Incorrect username or password')
        except Exception as e:
            flash(f'An error occurred: {str(e)}')

    return render_template('admin/login-v2.html')


@app.route('/login/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please enter both username and password.')
            return render_template('auth/login.html')

        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
                account = cursor.fetchone()

                if account and check_password_hash(account['password'], password):
                    session['loggedin'] = True
                    session['id'] = account['id']
                    session['username'] = account['username']
                    user_role = account['role']
                    is_accepted = account['is_accepted']
                    
                    # Redirect based on user role
                    if user_role == 'teacher':
                        if not is_accepted:
                            flash('Your account is pending approval by an admin.')
                            return redirect(url_for('home'))
                        return redirect(url_for('guru_dashboard'))
                    elif user_role == 'student':
                        return redirect(url_for('siswa_dashboard'))
                    else:
                        flash('Unknown user role')
                        return redirect(url_for('home'))
                else:
                    flash('Incorrect username or password')

    return render_template('auth/login.html')

@app.route('/logoutAdmin')
def logoutAdmin():
    # Menghapus data sesi pengguna
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    flash('You have been logged out successfully.')
    return redirect(url_for('loginAdmin'))


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

@app.route('/admin')
def admin_dashboard():
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
            cursor.execute("SELECT id, username, email, role, is_accepted FROM users")
            users = cursor.fetchall()
    return render_template('admin/manage_roles.html', users=users)


@app.route('/admin/manage_roles', methods=['GET', 'POST'])
def manage_roles():
    if request.method == 'POST':
        # Mengambil user_id dari form
        user_id = request.form.get('user_id')
        action_type = request.form.get('action_type')

        try:
            with get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                    if action_type == 'approve':
                        # Approve the user
                        cursor.execute('UPDATE users SET is_accepted = TRUE WHERE id = %s', (user_id,))
                        flash('User approved successfully!')
                    elif action_type == 'update_role':
                        # Update user role
                        new_role = request.form.get('new_role')
                        cursor.execute(
                            'UPDATE users SET role = %s, is_accepted = %s WHERE id = %s',
                            (new_role, False if new_role == 'teacher' else True, user_id)
                        )
                        flash('User role updated successfully!')

                    conn.commit()
        except Exception as e:
            flash(f'An error occurred: {str(e)}')

    # Fetch all users data to display
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
            cursor.execute("SELECT id, username, email, role, is_accepted FROM users")
            users = cursor.fetchall()

    return render_template('admin/manage_roles.html', users=users)

@app.route('/admin/manage_users')
def manage_users():
    search = request.args.get('search')
    role_filter = request.args.get('role_filter')
    
    # Base query untuk mengambil data user
    query = "SELECT id, username, fullname, email, role, nisn_or_nuptk FROM users WHERE 1=1"
    params = []
    
    # Tambahkan kondisi pencarian
    if search:
        # Gunakan ILIKE untuk case-insensitive search pada PostgreSQL
        query += " AND (username ILIKE %s OR email ILIKE %s OR nisn_or_nuptk ILIKE %s)"
        search_param = f"%{search}%"
        params.extend([search_param, search_param, search_param])
    
    # Tambahkan filter berdasarkan role jika ada
    if role_filter:
        query += " AND role = %s"
        params.append(role_filter)
    
    # Eksekusi query
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
            cursor.execute(query, tuple(params))
            users = cursor.fetchall()
    
    return render_template('admin/manage_users.html', users=users)


@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
def reset_password(user_id):
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                # Ambil username berdasarkan ID user
                cursor.execute('SELECT username FROM users WHERE id = %s', (user_id,))
                user = cursor.fetchone()
                
                if user:
                    # Tentukan password default: username + "12345"
                    default_password = user['username'] + '12345'
                    # Enkripsi password menggunakan generate_password_hash
                    hashed_password = generate_password_hash(default_password)
                    
                    # Update password dalam database
                    cursor.execute('UPDATE users SET password = %s WHERE id = %s', (hashed_password, user_id))
                    conn.commit()
                    flash(f"Password for user '{user['username']}' has been reset to the default.")
                else:
                    flash('User not found.')
    except Exception as e:
        flash(f'An error occurred: {str(e)}')

    return redirect(url_for('manage_users'))


@app.route('/guru/dashboard')
def guru_dashboard():
    if 'id' not in session:
        return redirect(url_for('login'))

    user_id = session['id']
    kelas_list = db.session.query(kelas_ajar).join(enrollment).filter(enrollment.id_user == user_id).all()
    return render_template('guru/guru_dashboard.html', classes=kelas_list)

@app.route('/guru/add_class', methods=['GET', 'POST'])
def add_class():
    if request.method == 'POST':
        nama_mapel = request.form['nama_mapel']
        kelas = request.form['kelas']
        id_user = session['id']


        if nama_mapel and kelas and id_user:
            new_class = kelas_ajar(nama_mapel=nama_mapel, kelas=kelas)
            db.session.add(new_class)
            db.session.commit()

            id_kelas = new_class.id_kelas
            random_token = secrets.token_hex(4)
            token = f'{id_kelas}{random_token}'

            enrollments = enrollment(id_kelas=id_kelas, id_user=id_user, token=token)
            db.session.add(enrollments)
            db.session.commit()
            return redirect(url_for('guru_dashboard'))
        else:
            return "Nama mapel dan kelas tidak boleh kosong", 400
    return render_template('guru/add_class.html')

@app.route('/guru/class/<int:class_id>')
def class_detail(class_id):
    selected_class = kelas_ajar.query.get(class_id)
    if selected_class:
        return render_template('guru/class_detail.html', selected_class=selected_class)
    else:
        return "Kelas tidak ditemukan", 404

@app.route('/guru/class/<int:class_id>/quizzes')
def class_quizzes(class_id):
    quizzes = kuis.query.filter_by(id_kelas=class_id).all()
    selected_class = kelas_ajar.query.get(class_id)
    return render_template('guru/class_quizzes.html', quizzes=quizzes, selected_class=selected_class)

@app.route('/guru/class/<int:class_id>/add_quiz', methods=['GET', 'POST'])
def add_quiz(class_id):
    if 'id' not in session:
        return redirect(url_for('login'))
    
    selected_class = kelas_ajar.query.get(class_id)
    if request.method == 'POST':
        judul_kuis = request.form['judul_kuis']
        kuis_baru = kuis(id_kelas=class_id, judul_kuis=judul_kuis)
        db.session.add(kuis_baru)
        db.session.commit()
         
        return redirect(url_for('class_quizzes', class_id=class_id))
    return render_template('guru/add_quiz.html', selected_class=selected_class) 

@app.route('/guru/class/<int:class_id>/enrollment')
def class_enrollments(class_id):
    enrollments = enrollment.query.filter_by(id_kelas=class_id).all()
    peserta = [User.query.get(enrollment.id_user) for enrollment in enrollments]
    selected_class = kelas_ajar.query.get(class_id)
    return render_template('guru/class_enrollments.html', peserta=peserta, selected_class=selected_class)

@app.route('/siswa/dashboard')
def siswa_dashboard():
    return render_template('siswa/siswa_dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)
