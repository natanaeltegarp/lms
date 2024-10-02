from flask import Flask, request, session, redirect, url_for, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2 
import psycopg2.extras
import secrets
import re

app = Flask(__name__)
app.secret_key = 'excel-coba-kp'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Indonesia09@localhost:5432/coba'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

DB_HOST = "localhost"
DB_NAME = "coba"
DB_USER = "postgres"
DB_PASS = "Indonesia09"

def get_db_connection():
    return psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    nisn_or_nuptk = db.Column(db.String(50), nullable=False)
    is_accepted = db.Column(db.Boolean, default=False)

class kelas_ajar(db.Model):
    __tablename__ = 'kelas_ajar'
    id_kelas = db.Column(db.Integer, primary_key=True)
    nama_mapel = db.Column(db.String(255), nullable=False)
    kelas = db.Column(db.String(5), nullable=False)
    token = db.Column(db.String(20), nullable=False)

class enrollment(db.Model):
    __tablename__ = 'enrollment'
    id_kelas = db.Column(db.Integer, db.ForeignKey('kelas_ajar.id_kelas'), primary_key=True, nullable=False)
    id_user = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True, nullable=False)

class Kuis(db.Model):
    __tablename__ = 'kuis'
    id_kuis = db.Column(db.Integer, primary_key=True)
    id_kelas = db.Column(db.Integer, db.ForeignKey('kelas_ajar.id_kelas'), nullable=False)
    judul_kuis = db.Column(db.String(255), nullable=False)

class Soal(db.Model):
    __tablename__='soal'
    id_soal = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id_kuis = db.Column(db.Integer, db.ForeignKey('kuis.id_kuis'), nullable=False)
    pertanyaan = db.Column(db.Text, nullable=False)
    kunci_jawaban = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f'<Soal {self.id_soal}>'

class Jawaban(db.Model):
    __tablename__ = 'jawaban'
    id_jawaban = db.Column(db.Integer, primary_key=True, autoincrement=True)  # Auto-increment primary key
    id_user = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Foreign key to users table
    id_soal = db.Column(db.Integer, db.ForeignKey('soal.id_soal'), nullable=False)  # Foreign key to soal table
    jawaban = db.Column(db.Text, nullable=False)  # Answer provided by the user

    # Relationships
    user = db.relationship('User', backref=db.backref('jawaban', lazy=True))
    soal = db.relationship('Soal', backref=db.backref('jawaban', lazy=True))

    def __repr__(self):
        return f'<Jawaban {self.id_jawaban}>'


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

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['loggedin'] = True
            session['id'] = user.id
            session['username'] = user.username
            user_role = user.role
            is_accepted = user.is_accepted
            
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
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    flash('You have been logged out successfully.')
    return redirect(url_for('loginAdmin'))

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    flash('You have been logged out successfully.')
    return redirect(url_for('login'))

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
            if User.query.filter_by(username=username).first():
                flash('Account already exists!')
            else:
                hashed_password = generate_password_hash(password)
                new_user = User(fullname=fullname, username=username, password=hashed_password, email=email, role=role, nisn_or_nuptk=additional_info)
                db.session.add(new_user)
                db.session.commit()
                flash('You have successfully registered!')

    return render_template('auth/register.html')

@app.route('/home')
def home():
    return 'Welcome to the home page!'

@app.route('/admin')
def admin_dashboard():
    users = User.query.all()
    return render_template('admin/manage_roles.html', users=users)

@app.route('/admin/manage_roles', methods=['GET', 'POST'])
def manage_roles():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action_type = request.form.get('action_type')

        user = User.query.get(user_id)
        if not user:
            flash('User not found.')
            return redirect(url_for('admin_dashboard'))

        if action_type == 'approve':
            user.is_accepted = True
            flash('User approved successfully!')
        elif action_type == 'update_role':
            new_role = request.form.get('new_role')
            user.role = new_role
            user.is_accepted = False if new_role == 'teacher' else True
            flash('User role updated successfully!')

        db.session.commit()

    users = User.query.all()
    return render_template('admin/manage_roles.html', users=users)

@app.route('/admin/manage_users')
def manage_users():
    search = request.args.get('search')
    role_filter = request.args.get('role_filter')
    
    query = User.query
    if search:
        search_param = f"%{search}%"
        query = query.filter(User.username.ilike(search_param) | User.email.ilike(search_param) | User.nisn_or_nuptk.ilike(search_param))
    
    if role_filter:
        query = query.filter(User.role == role_filter)
    
    users = query.all()
    return render_template('admin/manage_users.html', users=users)

@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
def reset_password(user_id):
    user = User.query.get(user_id)
    if user:
        default_password = user.username + '12345'
        hashed_password = generate_password_hash(default_password)
        user.password = hashed_password
        db.session.commit()
        flash(f"Password for user '{user.username}' has been reset to the default.")
    else:
        flash('User not found.')

    return redirect(url_for('manage_users'))

@app.route('/guru/dashboard')
def guru_dashboard():
    if 'id' not in session:
        return redirect(url_for('login'))

    user_id = session['id']
    kelas_list = kelas_ajar.query.join(enrollment).filter(enrollment.id_user == user_id).all()
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
    quizzes = Kuis.query.filter_by(id_kelas=class_id).all()
    selected_class = kelas_ajar.query.get(class_id)
    return render_template('guru/class_quizzes.html', quizzes=quizzes, selected_class=selected_class)

@app.route('/guru/class/<int:class_id>/add_quiz', methods=['GET', 'POST'])
def add_quiz(class_id):
    if 'id' not in session:
        return redirect(url_for('login'))
    
    selected_class = kelas_ajar.query.get(class_id)
    if request.method == 'POST':
        judul_kuis = request.form['judul_kuis']
        new_quiz = Kuis(id_kelas=class_id, judul_kuis=judul_kuis)
        db.session.add(new_quiz)
        db.session.commit()
        return redirect(url_for('class_quizzes', class_id=class_id))
    return render_template('guru/add_quiz.html', selected_class=selected_class)

@app.route('/guru/class/<int:class_id>/quizzes/<int:quiz_id>', methods=['GET', 'POST'])
def quiz_detail(class_id, quiz_id):
    selected_quiz = Kuis.query.get(quiz_id)
    
    if not selected_quiz:
        return "Kuis tidak ditemukan", 404

    soal_list = Soal.query.filter_by(id_kuis=quiz_id).all()

    if request.method == 'POST':
        pertanyaan = request.form['pertanyaan']
        kunci_jawaban = request.form['kunci_jawaban']

        soal_baru = Soal(id_kuis=quiz_id, pertanyaan=pertanyaan, kunci_jawaban=kunci_jawaban)
        db.session.add(soal_baru)
        db.session.commit()

        return redirect(url_for('quiz_detail', class_id=class_id, quiz_id=quiz_id))

    return render_template('guru/quiz_detail.html', selected_quiz=selected_quiz, soal_list=soal_list)

@app.route('/guru/class/<int:class_id>/quizzes/<int:quiz_id>/delete_question/<int:question_id>', methods=['POST'])
def delete_question(class_id, quiz_id, question_id):
    pertanyaan = Soal.query.get(question_id)
    if pertanyaan:
        db.session.delete(pertanyaan)
        db.session.commit()
        flash('Soal berhasil dihapus', 'success')
    else:
        flash('Soal tidak ditemukan', 'danger')
    return redirect(url_for('quiz_detail', class_id=class_id, quiz_id=quiz_id))

@app.route('/guru/class/<int:class_id>/enrollment')
def class_enrollments(class_id):
    enrollments = enrollment.query.filter_by(id_kelas=class_id).all()
    peserta = [User.query.get(enrollment.id_user) for enrollment in enrollments]
    selected_class = kelas_ajar.query.get(class_id)
    return render_template('guru/class_enrollments.html', peserta=peserta, selected_class=selected_class)

@app.route('/siswa/dashboard')
def siswa_dashboard():
    if 'id' not in session:
        return redirect(url_for('login'))

    user_id = session['id']
    # Ambil daftar kelas yang diambil oleh pengguna
    enrolled_classes = kelas_ajar.query.join(enrollment).filter(enrollment.id_user == user_id).all()
    return render_template('siswa/dashboard.html',classes=enrolled_classes)


@app.route('/siswa/class/<int:class_id>/quizzes')
def siswa_class_quizzes(class_id):
    if 'id' not in session:
        return redirect(url_for('login'))

    user_id = session['id']
    selected_class = kelas_ajar.query.get(class_id)
    
    if not selected_class:
        flash('Kelas tidak ditemukan', 'danger')
        return redirect(url_for('siswa_dashboard'))

    # Check if user is enrolled in the class
    is_enrolled = enrollment.query.filter_by(id_kelas=class_id, id_user=user_id).first()
    if not is_enrolled:
        flash('Anda tidak terdaftar di kelas ini.', 'warning')
        return redirect(url_for('siswa_dashboard'))

    quizzes = Kuis.query.filter_by(id_kelas=class_id).all()
    
    # Check if the user has taken each quiz
    quiz_status = {}
    for quiz in quizzes:
        has_taken = Jawaban.query.join(Soal).filter(
            Jawaban.id_user == user_id,
            Soal.id_kuis == quiz.id_kuis
        ).first() is not None
        quiz_status[quiz.id_kuis] = has_taken

    return render_template('siswa/siswa_quiz.html',  quizzes=quizzes, selected_class=selected_class, quiz_status=quiz_status)

@app.route('/siswa/dashboard_quiz', methods=['GET'])
def dashboard_quiz():
    user_id = session.get('id')
    # Ambil class_id dari session
    class_id = session.get('current_class_id')
    
    if class_id is None:
        flash('No class selected. Please go back to select a class.')
        return redirect(url_for('siswa_dashboard'))

    quizzes = Kuis.query.filter_by(id_kelas=class_id).all()
    return render_template('siswa/dashboard_quiz.html', quizzes=quizzes, class_id=class_id)


@app.route('/siswa/class/<int:class_id>/quizzes/<int:quiz_id>', methods=['GET', 'POST'])
def siswa_quiz_detail(class_id, quiz_id):
    if 'id' not in session:
        return redirect(url_for('login'))

    user_id = session['id']
    selected_quiz = Kuis.query.get(quiz_id)
    selected_class = kelas_ajar.query.get(class_id)

    if not selected_quiz or not selected_class:
        flash('Kuis atau kelas tidak ditemukan', 'danger')
        return redirect(url_for('siswa_dashboard'))

    # Check if user is enrolled in the class
    is_enrolled = enrollment.query.filter_by(id_kelas=class_id, id_user=user_id).first()
    if not is_enrolled:
        flash('Anda tidak terdaftar di kelas ini. Silakan daftar terlebih dahulu.', 'warning')
        return redirect(url_for('siswa_dashboard'))

    # Check if user has already submitted answers for this quiz
    has_submitted = Jawaban.query.join(Soal).filter(
        Jawaban.id_user == user_id,
        Soal.id_kuis == quiz_id
    ).first() is not None

    soal_list = Soal.query.filter_by(id_kuis=quiz_id).all()

    if request.method == 'POST' and not has_submitted:
        # Process student's answers
        for soal in soal_list:
            jawaban = request.form.get(f'jawaban_{soal.id_soal}')
            if jawaban:
                new_jawaban = Jawaban(id_user=user_id, id_soal=soal.id_soal, jawaban=jawaban)
                db.session.add(new_jawaban)
        db.session.commit()
        has_submitted = True  # Update has_submitted status

    return render_template('siswa/siswa_quiz_detail.html', selected_quiz=selected_quiz, selected_class=selected_class,soal_list=soal_list, has_submitted=has_submitted)

@app.route('/enroll_class', methods=['GET', 'POST'])
def enroll_class():
    if 'id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        enrollment_token = request.form.get('enrollment_token')
        user_id = session['id']

        if not enrollment_token:
            flash('Invalid request. Please provide the enrollment token.')
            return redirect(url_for('enroll_class'))

        # Cek apakah token valid di tabel kelas_ajar
        selected_class = kelas_ajar.query.filter_by(token=enrollment_token).first()

        if selected_class:
            # Cek apakah user sudah terdaftar di kelas
            existing_enrollment = enrollment.query.filter_by(id_kelas=selected_class.id_kelas, id_user=user_id).first()
            if existing_enrollment:
                flash('You are already enrolled in this class.')
            else:
                # Tambahkan user ke kelas di tabel Enrollment
                new_enrollment = enrollment(id_kelas=selected_class.id_kelas, id_user=user_id)
                db.session.add(new_enrollment)
                db.session.commit()
                flash('Successfully enrolled in the class!')
        else:
            error = 'Token yang dimasukkan salah. Silakan coba lagi.'
            return render_template('siswa/enroll_class.html', error=error)

        return redirect(url_for('siswa_dashboard'))

    # Handle GET request
    return render_template('siswa/enroll_class.html')



if __name__ == '__main__':
    app.run(debug=True)
