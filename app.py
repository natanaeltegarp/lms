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
DB_NAME = "lms"
DB_USER = "postgres"
DB_PASS = "postgres"

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
    token = db.Column(db.String(20), nullable=False)

class enrollment(db.Model):
    __tablename__='enrollment'
    id_kelas = db.Column(db.Integer, db.ForeignKey('kelas_ajar.id_kelas'), primary_key=True, nullable=False)
    id_user = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True, nullable=False)

class kuis(db.Model):
    __tablename__='kuis'
    id_kuis = db.Column(db.Integer, primary_key=True)
    id_kelas = db.Column(db.Integer, db.ForeignKey('kelas_ajar.id_kelas'), nullable=False)
    judul_kuis = db.Column(db.String(255), nullable=False)

class soal(db.Model):
    __tablename__='soal'
    id_soal = db.Column(db.Integer, primary_key=True)
    id_kuis = db.Column(db.Integer, db.ForeignKey('kuis.id_kuis'), nullable=False)
    pertanyaan = db.Column(db.Text, nullable=False)
    kunci_jawaban = db.Column(db.Text, nullable=False)

@app.route('/')
def index():
    return redirect(url_for('login'))

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
                    flash('Incorrect username or password')
 
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
            random_token = secrets.token_hex(4)
            token = f'{id_user}{random_token}'

            new_class = kelas_ajar(nama_mapel=nama_mapel, kelas=kelas,token=token)
            db.session.add(new_class)
            db.session.commit()

            id_kelas = new_class.id_kelas

            enrollments = enrollment(id_kelas=id_kelas, id_user=id_user)
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

@app.route('/guru/class/<int:class_id>/quizzes/<int:quiz_id>', methods=['GET', 'POST'])
def quiz_detail(class_id, quiz_id):
    selected_quiz = kuis.query.get(quiz_id)
    
    if not selected_quiz:
        return "Kuis tidak ditemukan", 404

    soal_list = soal.query.filter_by(id_kuis=quiz_id).all()

    if request.method == 'POST':
        pertanyaan = request.form['pertanyaan']
        kunci_jawaban = request.form['kunci_jawaban']

        soal_baru = soal(id_kuis=quiz_id, pertanyaan=pertanyaan, kunci_jawaban=kunci_jawaban)
        db.session.add(soal_baru)
        db.session.commit()

        return redirect(url_for('quiz_detail', class_id=class_id, quiz_id=quiz_id))

    return render_template('guru/quiz_detail.html', selected_quiz=selected_quiz, soal_list=soal_list)


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
