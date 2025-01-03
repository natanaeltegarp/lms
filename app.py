from flask import Flask, request, session, redirect, url_for, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import pytz
import psycopg2 
import psycopg2.extras
import secrets
import random
import re
import os
import requests
import csv

app = Flask(__name__)
app.secret_key = 'excel-coba-kp'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Indonesia09@localhost:5432/lms2'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)

DB_HOST = "localhost"
DB_NAME = "lms2"
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
    batas_waktu = db.Column(db.DateTime(timezone=True), nullable=True)

    def __init__(self, id_kelas, judul_kuis, batas_waktu=None, score=None):
        self.id_kelas = id_kelas
        self.judul_kuis = judul_kuis
        self.batas_waktu = batas_waktu

class Materi(db.Model):
    __tablename__ = 'materi'
    id_materi = db.Column(db.Integer, primary_key=True)
    id_kelas = db.Column(db.Integer, db.ForeignKey('kelas_ajar.id_kelas'), nullable=False)
    nama_materi = db.Column(db.String(255), nullable=False)
    file_materi = db.Column(db.String(255), nullable=False)  # Nama file untuk materi

    kelas = db.relationship('kelas_ajar', backref='materi', lazy=True)

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
    waktu_submit = db.Column(db.DateTime, default=datetime.now, nullable=False)
    nilai = db.Column(db.String(1), nullable=True)

    # Relationships
    user = db.relationship('User', backref=db.backref('jawaban', lazy=True))
    soal = db.relationship('Soal', backref=db.backref('jawaban', lazy=True))

    def __repr__(self):
        return f'<Jawaban {self.id_jawaban}>'
    
class Pengumuman(db.Model):
    __tablename__ = 'pengumuman'

    id_pengumuman = db.Column(db.Integer, primary_key=True)
    id_kelas = db.Column(db.Integer, db.ForeignKey('kelas_ajar.id_kelas'), nullable=False)
    judul = db.Column(db.String(255), nullable=False)
    konten = db.Column(db.Text, nullable=False)
    tanggal_dibuat = db.Column(db.DateTime, default=db.func.now(), nullable=False)

UPLOAD_FOLDER = 'static/uploads/materials'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.template_filter('display_batas_waktu')
def display_batas_waktu(value):
    if isinstance(value, datetime):
        return value.strftime('%Y-%m-%d %H:%M:%S')  # Adjust format as needed
    return value

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
    return  render_template('home/home.html')

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
    return render_template('guru/dashboard.html', classes=kelas_list)

@app.route('/guru/profile', methods=['GET', 'POST'])
def guru_profile():
    if 'id' not in session:
        return redirect(url_for('login'))

    user_id = session['id']
    user = User.query.get(user_id)

    if request.method == 'POST':
        if 'update_info' in request.form:
            # Update fullname and email
            new_fullname = request.form.get('fullname')
            new_email = request.form.get('email')
            
            updates = []

            if new_fullname and new_fullname != user.fullname:
                user.fullname = new_fullname
                updates.append('full name')

            if new_email and new_email != user.email:
                if User.query.filter_by(email=new_email).first():
                    flash('Email already in use.', 'danger')
                else:
                    user.email = new_email
                    updates.append('email')

            if updates:
                if len(updates) == 1:
                    flash(f'Your {updates[0]} has been updated successfully.', 'success')
                else:
                    flash('Your personal information has been updated successfully.', 'success')
            else:
                flash('No changes were made to your personal information.', 'info')

        elif 'change_password' in request.form:
            # Update password
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            if current_password and new_password and confirm_password:
                if check_password_hash(user.password, current_password):
                    if new_password == confirm_password:
                        user.password = generate_password_hash(new_password)
                        flash('Password updated successfully.', 'success')
                    else:
                        flash('New passwords do not match.', 'danger')
                else:
                    flash('Current password is incorrect.', 'danger')
            else:
                flash('All password fields are required.', 'danger')

        db.session.commit()
        return redirect(url_for('guru_profile'))

    return render_template('guru/profile.html', user=user)

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
    
@app.route('/guru/class/<int:class_id>/delete', methods=['POST'])
def delete_class(class_id):
    selected_class = kelas_ajar.query.get_or_404(class_id)
    user_id = session['id']
    kelas_list = kelas_ajar.query.join(enrollment).filter(enrollment.id_user == user_id).all()

    try:
        kuis_ids = [kuis.id_kuis for kuis in Kuis.query.filter_by(id_kelas=class_id).all()]
        Jawaban.query.filter(Jawaban.id_soal.in_(
            db.session.query(Soal.id_soal).filter(Soal.id_kuis.in_(kuis_ids))
        )).delete()
        Soal.query.filter(Soal.id_kuis.in_(kuis_ids)).delete()
        Kuis.query.filter_by(id_kelas=class_id).delete()

        enrollment.query.filter_by(id_kelas=class_id).delete()

        db.session.delete(selected_class)
        db.session.commit()
        flash("Kelas berhasil dihapus.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Terjadi kesalahan saat menghapus kelas: {str(e)}", "danger")

    return redirect(url_for('guru_dashboard', classes=kelas_list))

@app.route('/guru/class/<int:class_id>/announcements', methods=['GET'])
def class_announcements(class_id):
    selected_class = kelas_ajar.query.get_or_404(class_id)
    pengumuman_list = Pengumuman.query.filter_by(id_kelas=class_id).order_by(Pengumuman.tanggal_dibuat.desc()).all()
    return render_template('guru/class_announcements.html', selected_class=selected_class, pengumuman_list=pengumuman_list)

@app.route('/guru/class/<int:class_id>/announcements/add', methods=['GET', 'POST'])
def add_announcement(class_id):
    selected_class = kelas_ajar.query.get_or_404(class_id)
    if request.method == 'POST':
        judul = request.form['judul']
        konten = request.form['konten']

        if not judul or not konten:
            flash("Judul dan konten tidak boleh kosong", "danger")
            return redirect(url_for('add_announcement', class_id=class_id))
        
        pengumuman = Pengumuman(id_kelas=class_id, judul=judul, konten=konten)
        db.session.add(pengumuman)
        db.session.commit()
        flash("Pengumuman berhasil dibuat", "success")
        return redirect(url_for('class_announcements', class_id=class_id))
    return render_template('guru/add_announcement.html', selected_class=selected_class)

@app.route('/guru/class/<int:class_id>/announcements/<int:announcement_id>/delete', methods=['POST'])
def delete_announcement(class_id,announcement_id):
    pengumuman = Pengumuman.query.get_or_404(announcement_id)
    db.session.delete(pengumuman)
    db.session.commit()
    flash("Pengumuman berhasil dihapus", "success")
    return redirect(url_for('class_announcements', class_id=class_id))

@app.route('/guru/class/<int:class_id>/materials', methods=['GET'])
def class_materials(class_id):
    selected_class = kelas_ajar.query.get_or_404(class_id)
    materi_list = Materi.query.filter_by(id_kelas=class_id).all()
    return render_template('guru/class_materials.html', selected_class=selected_class, materi_list=materi_list)                                                    

@app.route('/guru/class/<int:class_id>/materials/add', methods=['GET', 'POST'])
def add_material(class_id):
    selected_class = kelas_ajar.query.get_or_404(class_id)
    if request.method == 'POST':
        nama_materi = request.form['nama_materi']
        file_materi = request.files['file_materi']
        if not nama_materi or not file_materi:
            flash("Nama materi dan file materi tidak boleh kosong", "danger")
            return redirect(url_for('add_material', class_id=class_id))
        
        materi = Materi(id_kelas=class_id, nama_materi=nama_materi, file_materi="")
        db.session.add(materi)
        db.session.commit()
        
        filename = f"{materi.id_materi}_{materi.id_kelas}{os.path.splitext(file_materi.filename)[-1]}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file_materi.save(file_path)
        materi.file_materi = file_path
        db.session.commit()
        
        flash("Materi berhasil dibuat", "success")
        return redirect(url_for('class_materials', class_id=class_id))
    return render_template('guru/add_material.html', selected_class=selected_class)

@app.route('/guru/class/<int:class_id>/materials/<int:material_id>/delete', methods=['POST'])
def delete_material(class_id, material_id):
    materi = Materi.query.get_or_404(material_id)
    if materi.file_materi and os.path.exists(materi.file_materi):
        os.remove(materi.file_materi)
    
    db.session.delete(materi)
    db.session.commit()
    flash("Materi berhasil dihapus", "success")
    return redirect(url_for('class_materials', class_id=class_id))

@app.route('/guru/class/<int:class_id>/quizzes')
def class_quizzes(class_id):
    quizzes = Kuis.query.filter_by(id_kelas=class_id).all()
    selected_class = kelas_ajar.query.get(class_id)
    return render_template('guru/class_quizzes.html', quizzes=quizzes, selected_class=selected_class)

@app.route('/guru/class/<int:class_id>/add_quiz', methods=['GET', 'POST'])
def add_quiz(class_id):
    if 'id' not in session:
        return redirect(url_for('login'))
    
    selected_class = kelas_ajar.query.get_or_404(class_id)
    if request.method == 'POST':
        judul_kuis = request.form['judul_kuis']
        batas_waktu = request.form['batas_waktu']
        batas_waktu = datetime.fromisoformat(batas_waktu)
        new_quiz = Kuis(id_kelas=class_id, judul_kuis=judul_kuis, batas_waktu=batas_waktu)
        db.session.add(new_quiz)
        db.session.commit()
        flash("Kuis berhasil ditambahkan.", "success")

        return redirect(url_for('quiz_edit', class_id=class_id, quiz_id=new_quiz.id_kuis))
    return render_template('guru/add_quiz.html', selected_class=selected_class)

@app.route('/guru/class/<int:class_id>/quizzes/<int:quiz_id>', methods=['GET'])
def quiz_detail(class_id, quiz_id):

    selected_quiz = Kuis.query.get(quiz_id)
    selected_class = kelas_ajar.query.get(class_id)
    if not selected_quiz:
        return "Kuis tidak ditemukan", 404
    return render_template('guru/quiz_detail.html', selected_class=selected_class, selected_quiz=selected_quiz)

@app.route('/guru/class/<int:class_id>/quizzes/<int:quiz_id>/delete_quiz', methods=['POST'])
def delete_quiz(class_id, quiz_id):
    selected_class = kelas_ajar.query.get(class_id)
    quizzes = Kuis.query.filter_by(id_kelas=class_id).all()
    selected_quiz = Kuis.query.get_or_404(quiz_id)

    try:
        Jawaban.query.filter(Jawaban.id_soal.in_(
            db.session.query(Soal.id_soal).filter_by(id_kuis=quiz_id)
        )).delete()
        Soal.query.filter_by(id_kuis=quiz_id).delete()

        db.session.delete(selected_quiz)
        db.session.commit()
        flash("Kuis berhasil dihapus.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Terjadi kesalahan saat menghapus kuis: {str(e)}", "danger")
    return redirect(url_for('class_quizzes', quizzes=quizzes, class_id=selected_class.id_kelas))

@app.template_filter('display_batas_waktu')
def display_batas_waktu(batas_waktu):
    if batas_waktu is None:
        return "Tidak ada batas waktu"
    return batas_waktu.strftime('%d-%m-%Y %H:%M') 

@app.route('/guru/class/<int:class_id>/quizzes/<int:quiz_id>/answers', methods=['GET'])
def quiz_answer(class_id, quiz_id):
    selected_class = kelas_ajar.query.get(class_id)
    selected_quiz = Kuis.query.get(quiz_id)
    soal_list = Soal.query.filter_by(id_kuis=quiz_id).all()
    jawaban_list = db.session.query(Jawaban, User).join(User,Jawaban.id_user == User.id).filter(Jawaban.id_soal.in_([Soal.id_soal for soal in soal_list])).all()
    return render_template('guru/quiz_answer.html', selected_class=selected_class, selected_quiz=selected_quiz, soal_list=soal_list, jawaban_list=jawaban_list)

@app.route('/guru/class/<int:class_id>/quizzes/<int:quiz_id>/answers/grade', methods=['POST'])
def answer_grade(quiz_id, class_id):
    soal_list = Soal.query.filter_by(id_kuis=quiz_id).all()
    jawaban_list = db.session.query(Jawaban, Soal).join(Soal, Jawaban.id_soal == Soal.id_soal).filter(
        Soal.id_kuis == quiz_id
    ).all()
    csv_file = f'temp_answers_{quiz_id}.csv'
    csv_filepath = os.path.join('static/uploads/temp/', csv_file)
    os.makedirs(os.path.dirname(csv_filepath), exist_ok=True)

    with open(csv_filepath, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        # Tulis header CSV
        writer.writerow(['id_jawaban', 'id_soal', 'kunci_jawaban', 'jawaban'])
        # Tulis data jawaban
        for jawaban, soal in jawaban_list:
            writer.writerow([jawaban.id_jawaban, soal.id_soal, soal.kunci_jawaban, jawaban.jawaban])

    try:
        with open(csv_filepath, 'rb') as f:
            response = requests.post('http://127.0.0.1:5001/evaluate', files={'file':f})
        if response.status_code == 200:
            result = response.json()
            for id_jawaban, nilai in result.items():
                jawaban = Jawaban.query.get(id_jawaban)
                jawaban.nilai = nilai
            db.session.commit()
            flash("Penilaian otomatis berhasil dilakukan", "success")
        else:
            flash("Penilaian otomatis gagal dilakukan", "danger")
    except Exception as e:
        flash(f"Terjadi kesalahan: {e}", "danger")
    finally:
        if os.path.exists(csv_filepath):
            os.remove(csv_filepath)

    return redirect(url_for('quiz_answer', class_id=class_id, quiz_id=quiz_id))

@app.route('/guru/class/<int:class_id>/quizzes/<int:quiz_id>/edit', methods=['GET', 'POST'])
def quiz_edit(class_id, quiz_id):
    selected_class = kelas_ajar.query.get(class_id)
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

        return redirect(url_for('quiz_edit', class_id=class_id, quiz_id=quiz_id))
    return render_template('guru/quiz_edit.html', selected_class=selected_class, selected_quiz=selected_quiz, soal_list=soal_list)

@app.route('/guru/class/<int:class_id>/quizzes/<int:quiz_id>/view', methods=['GET'])
def quiz_view(class_id, quiz_id):
    selected_class = kelas_ajar.query.get(class_id)
    selected_quiz = Kuis.query.get(quiz_id)
    soal_list = Soal.query.filter_by(id_kuis=quiz_id).all()
    return render_template('guru/quiz_view.html', selected_class=selected_class, selected_quiz=selected_quiz, soal_list=soal_list)


@app.route('/guru/class/<int:class_id>/quizzes/<int:quiz_id>/delete_question/<int:question_id>', methods=['POST'])
def delete_question(class_id, quiz_id, question_id):
    try:
        pertanyaan = db.session.get(Soal, question_id)
        if pertanyaan:
            db.session.delete(pertanyaan)
            db.session.commit()
            flash('Soal berhasil dihapus', 'success')
        else:
            flash('Soal tidak ditemukan', 'danger')
    except Exception as e:
        db.session.rollback()
        flash(f'Terjadi kesalahan saat menghapus soal: {str(e)}', 'danger')
    
    return redirect(url_for('quiz_detail', class_id=class_id, quiz_id=quiz_id))

@app.route('/guru/class/<int:class_id>/enrollment')
def class_enrollments(class_id):
    selected_class = kelas_ajar.query.get_or_404(class_id)
    enrollments = enrollment.query.filter_by(id_kelas=class_id).all()
    peserta = [User.query.get(enrollment.id_user) for enrollment in enrollments if enrollment.id_user != session['id']]
    return render_template('guru/class_enrollments.html', peserta=peserta, selected_class=selected_class)

@app.route('/guru/class/<int:class_id>/<int:user_id>/enrollment', methods=['POST'])
def delete_enrollment(class_id, user_id):
    selected_class = kelas_ajar.query.get_or_404(class_id)
    if selected_class.id_guru != session['id']:
        flash("Anda tidak memiliki izin untuk menghapus peserta ini.", "danger")
        return redirect(url_for('class_enrollments', class_id=class_id))
    
    enrollment = enrollment.query.filter_by(id_kelas=class_id, id_user=user_id).first()
    
    if enrollment:
        db.session.delete(enrollment)
        db.session.commit()
        flash('Peserta berhasil dihapus', 'success')
    else:
        flash('Peserta tidak ditemukan', 'danger')
    
    return redirect(url_for('class_enrollments', class_id=class_id))

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

    is_enrolled = enrollment.query.filter_by(id_kelas=class_id, id_user=user_id).first()
    if not is_enrolled:
        flash('Anda tidak terdaftar di kelas ini.', 'warning')
        return redirect(url_for('siswa_dashboard'))

    quizzes = Kuis.query.filter_by(id_kelas=class_id).all()
    
    quiz_status = {}
    current_time = datetime.now()  # Naive datetime, tanpa zona waktu
    for quiz in quizzes:
        has_taken = Jawaban.query.join(Soal).filter(
            Jawaban.id_user == user_id,
            Soal.id_kuis == quiz.id_kuis
        ).first() is not None
        
        # Menghapus zona waktu dari batas_waktu jika dia offset-aware
        if quiz.batas_waktu.tzinfo:
            quiz.batas_waktu = quiz.batas_waktu.replace(tzinfo=None)  # Mengubah menjadi naive datetime

        # Sekarang perbandingan antara dua naive datetime
        is_deadline_passed = quiz.batas_waktu and current_time > quiz.batas_waktu
        quiz_status[quiz.id_kuis] = {
            'has_taken': has_taken,
            'is_deadline_passed': is_deadline_passed
        }

    return render_template('siswa/siswa_quiz.html', 
                         quizzes=quizzes, 
                         selected_class=selected_class, 
                         quiz_status=quiz_status)

@app.route('/siswa/class/<int:class_id>/pengumuman', methods=['GET'])
def siswa_class_pengumuman(class_id):
    # Mengambil informasi pengumuman berdasarkan ID kelas
    pengumuman_list = Pengumuman.query.filter_by(id_kelas=class_id).all()
    
    # Mengambil informasi kelas yang dipilih
    selected_class = kelas_ajar.query.get(class_id)

    # Menentukan pesan untuk ditampilkan jika tidak ada pengumuman
    no_pengumuman_message = None
    if not pengumuman_list:
        no_pengumuman_message = 'Belum ada pengumuman yang tersedia untuk kelas ini.'

    return render_template('siswa/siswa_class_pengumuman.html', 
                           pengumuman_list=pengumuman_list, 
                           no_pengumuman_message=no_pengumuman_message, 
                           selected_class=selected_class)

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

    soal_list = Soal.query.filter_by(id_kuis=quiz_id).all()
    
    # Get previous answers and submission time ONLY for the current user
    previous_answers = {}
    last_submission = None
    submitted_answers = Jawaban.query.join(Soal).filter(
        Jawaban.id_user == user_id,  # Filter specifically for current user
        Soal.id_kuis == quiz_id
    ).all()
    
    has_submitted = len(submitted_answers) > 0
    
    if has_submitted:
        for jawaban in submitted_answers:
            # Ensure this answer belongs to the current user
            if jawaban.id_user == user_id:
                previous_answers[jawaban.id_soal] = jawaban.jawaban
                if last_submission is None or jawaban.waktu_submit > last_submission:
                    last_submission = jawaban.waktu_submit

    if request.method == 'POST':
        try:
            # Gunakan timezone-aware datetime untuk perbandingan
            local_tz = pytz.timezone("Asia/Jakarta")
            current_time = datetime.now(local_tz)  # waktu sekarang dengan zona waktu

            # Pastikan batas waktu kuis adalah timezone-aware (gunakan UTC atau zona waktu yang sesuai)
            if selected_quiz.batas_waktu:
                selected_quiz_batas_waktu = selected_quiz.batas_waktu.astimezone(local_tz)  # Konversi ke zona waktu yang sesuai

                # Bandingkan waktu hanya jika batas waktu ada
                if current_time > selected_quiz_batas_waktu:
                    flash('Maaf, batas waktu pengumpulan kuis telah berakhir', 'danger')
                    return redirect(url_for('siswa_class_quizzes', class_id=class_id))

            # Proses jawaban dengan validasi
            for soal in soal_list:
                jawaban_text = request.form.get(f'jawaban_{soal.id_soal}')
                
                # Pastikan jawaban tidak kosong dan valid
                if not jawaban_text or not isinstance(jawaban_text, str) or len(jawaban_text.strip()) == 0:
                    flash(f"Jawaban untuk soal {soal.id_soal} tidak valid", 'danger')
                    return redirect(url_for('siswa_quiz_detail', class_id=class_id, quiz_id=quiz_id))

                # Cek apakah jawaban sudah ada atau belum
                existing_jawaban = Jawaban.query.filter_by(
                    id_user=user_id,
                    id_soal=soal.id_soal
                ).first()

                if existing_jawaban:
                    flash('Jawaban hanya bisa dikirimkan sekali.', 'danger')
                    return redirect(url_for('siswa_class_quizzes', class_id=class_id))  # Kembali ke halaman quiz jika sudah submit

                # Jika belum ada jawaban, buat jawaban baru
                new_jawaban = Jawaban(
                    id_user=user_id,
                    id_soal=soal.id_soal,
                    jawaban=jawaban_text,
                    waktu_submit=current_time
                )
                db.session.add(new_jawaban)

            db.session.commit()
            flash('Jawaban Anda berhasil dikirim!', 'success')
            return redirect(url_for('siswa_class_quizzes', class_id=class_id))  # Kembali ke daftar kuis

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error occurred while committing answers: {str(e)}")  # Log error
            flash('Terjadi kesalahan saat menyimpan jawaban. Silakan coba lagi.', 'danger')
            return redirect(url_for('siswa_quiz_detail', class_id=class_id, quiz_id=quiz_id))

    # Format last submission time for display
    formatted_last_submission = last_submission.strftime("%d %B %Y %H:%M:%S") if last_submission else None

    return render_template(
        'siswa/siswa_quiz_detail.html',
        selected_quiz=selected_quiz,
        selected_class=selected_class,
        soal_list=soal_list,
        has_submitted=has_submitted,
        previous_answers=previous_answers,
        last_submission_time=formatted_last_submission
    )

@app.route('/siswa/class/<int:class_id>/quizzes/<int:quiz_id>/score')
def score_quiz(class_id, quiz_id):
    if 'id' not in session:
        return redirect(url_for('login'))

    user_id = session['id']
    selected_class = kelas_ajar.query.get(class_id)
    selected_quiz = Kuis.query.get(quiz_id)

    if not selected_class or not selected_quiz:
        flash('Kelas atau kuis tidak ditemukan', 'danger')
        return redirect(url_for('siswa_dashboard'))

    # Ambil soal-soal dalam kuis
    soal_list = Soal.query.filter_by(id_kuis=quiz_id).all()

    # Ambil jawaban pengguna untuk setiap soal
    jawaban_details = []
    for soal in soal_list:
        jawaban = Jawaban.query.filter_by(id_user=user_id, id_soal=soal.id_soal).first()
        jawaban_details.append({
            'soal': soal,
            'jawaban_user': jawaban.jawaban if jawaban else 'Tidak dijawab',
            'kunci_jawaban': soal.kunci_jawaban,
            'nilai': jawaban.nilai if jawaban else 'Belum dinilai'
        })

    return render_template('siswa/score_quiz.html', 
                           selected_class=selected_class, 
                           selected_quiz=selected_quiz, 
                           jawaban_details=jawaban_details)

@app.route('/siswa/class/<int:class_id>/materi', methods=['GET'])
def siswa_class_materi(class_id):
    # Mengambil informasi materi berdasarkan ID kelas
    materi_list = Materi.query.filter_by(id_kelas=class_id).all()
    
    # Mengambil informasi kelas yang dipilih
    selected_class = kelas_ajar.query.get(class_id)  # Ganti 'Kelas' dengan model yang sesuai

    # Menentukan pesan untuk ditampilkan jika tidak ada materi
    no_materi_message = None
    if not materi_list:
        no_materi_message = 'Belum ada materi yang tersedia untuk kelas ini.'

    return render_template('siswa/siswa_class_materi.html', 
                           materi_list=materi_list, 
                           no_materi_message=no_materi_message, 
                           selected_class=selected_class)


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

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'id' not in session:
        return redirect(url_for('login'))

    user_id = session['id']
    user = User.query.get(user_id)

    if request.method == 'POST':
        if 'update_info' in request.form:
            # Update fullname and email
            new_fullname = request.form.get('fullname')
            new_email = request.form.get('email')
            
            updates = []

            if new_fullname and new_fullname != user.fullname:
                user.fullname = new_fullname
                updates.append('full name')

            if new_email and new_email != user.email:
                if User.query.filter_by(email=new_email).first():
                    flash('Email already in use.', 'danger')
                else:
                    user.email = new_email
                    updates.append('email')

            if updates:
                if len(updates) == 1:
                    flash(f'Your {updates[0]} has been updated successfully.', 'success')
                else:
                    flash('Your personal information has been updated successfully.', 'success')
            else:
                flash('No changes were made to your personal information.', 'info')

        elif 'change_password' in request.form:
            # Update password
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            if current_password and new_password and confirm_password:
                if check_password_hash(user.password, current_password):
                    if new_password == confirm_password:
                        user.password = generate_password_hash(new_password)
                        flash('Password updated successfully.', 'success')
                    else:
                        flash('New passwords do not match.', 'danger')
                else:
                    flash('Current password is incorrect.', 'danger')
            else:
                flash('All password fields are required.', 'danger')

        db.session.commit()
        return redirect(url_for('profile'))

    return render_template('siswa/profile.html', user=user)

if __name__ == '__main__':
    app.run(debug=True)
