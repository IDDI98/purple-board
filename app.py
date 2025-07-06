from flask import Flask, render_template, request, redirect, flash, session, jsonify, url_for, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import requests
import pymysql
import os
import smtplib
from email.message import EmailMessage
import secrets
import string
import uuid

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

# .env 파일로부터 DB 설정 값 불러옴
load_dotenv()

# FLASK 앱 및 32바이트 크기의 secret key 생성
app = Flask(__name__)
app.secret_key = os.urandom(32)

# 파일 업로드 경로 및 허용할 확장자
UPLOAD_FOLDER = os.path.join('uploads', 'posts')
PROFILE_UPLOAD_FOLDER = os.path.join('uploads', 'profile_images')

ALLOWED_EXTENSIONS = {'zip'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROFILE_UPLOAD_FOLDER, exist_ok=True)

# pymysql 라이브러리를 이용하여 DB 연결
conn = pymysql.connect(
    host=os.getenv("DB_HOST"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    db=os.getenv("DB_NAME"),
    charset='utf8mb4',

# DB 결과를 Dictionary 형태로 반환하도록 설정
    cursorclass=pymysql.cursors.DictCursor
)

# Root route 접속 시 index.html을 반환
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

# signup route 접속 시 signup.html을 반환
@app.route('/signup', methods=['GET'])
def signup_form():
    return render_template('auth/signup.html')

# signup의 회원가입 처리 기능(사용자 입력 값을 변수에 저장)
# reCAPTCHA 인증을 위한 토큰 및 검증 URL 준비
@app.route('/signup', methods=['POST'])
def signup():
    fullname = request.form.get('fullname', '').strip()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    hashed_password = generate_password_hash(password)
    password_confirm = request.form.get('password_confirm', '').strip()
    email = request.form.get('email', '').strip()
    school = request.form.get('school', '').strip()
    phone = request.form.get('phone', '').strip()
    token = request.form['g-recaptcha-response']
    secret = os.getenv("SECRET_KEY")
    verify_url = 'https://www.google.com/recaptcha/api/siteverify'

# 서버 측 공백 회원가입 필터링
    if not fullname or not username or not password or not password_confirm or not email or not school or not phone:
        flash('Please fill in all fields.')
        return redirect('/signup')

# 서버 측 중복 username 검사
# 중복 username이 존재할 경우 redirect
    with conn.cursor() as cursor:
        sql = "SELECT * FROM users WHERE username = %s"
        cursor.execute(sql, (username,))
        existing_user = cursor.fetchone()

    if existing_user:
        flash('This username is already taken.', "error")
        return redirect('/signup')

# 서버 측 회원가입 패스워드 확인
    if password != password_confirm:
        flash('Password and confirmation do not match.')
        return redirect('/signup')
    
    response = requests.post(verify_url, data={
        'secret': secret,
        'response': token
    })
    result = response.json()

# CAPTCHA 인증에 성공할 경우 회원 정보 입력 값 DB 등록(비밀번호를 hash로 저장)
# CAPTCHA 인증에 실패할 경우 "Captcha verification failed."를 반환
    if result.get("success"):
        with conn.cursor() as cursor:
            sql = "INSERT INTO users (fullname, username, password, email, school, phone) VALUES (%s, %s, %s, %s, %s, %s)"
            cursor.execute(sql, (fullname, username, hashed_password, email, school, phone))
            conn.commit()
        flash('Sign-up successful!', "success")
        return render_template('/index.html')
    else:
        return '''
        <p>Captcha verification failed.</p>
        <a href="/signup">&#x276E; Back to Home</a>
        '''

# login route 접속 시 login.html을 반환
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

# 서버 측 입력 검증
        if not username or not password:
            flash("Please fill in all fields.", "error")
            return redirect('/login')

# DB에 저장된 회원정보와 사용자 입력 값 처리
        with conn.cursor() as cursor:
            sql = "SELECT * FROM users WHERE username=%s"
            cursor.execute(sql, (username, ))
            user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['fullname'] = user['fullname']
            flash("Welcome " + user['fullname'] + "! You're now ready to write a Purple.", "success")
            return redirect('/')
        else:
            flash("Incorrect username or password.", "error")
            return redirect('/login')
    else: 
        return render_template('auth/login.html')

# signup.html의 중복 검사 버튼 클릭 시 실행.
# 만약 DB에 이미 존재하는 username이 있을 경우 True 값을 signup.html으로 전달
@app.route('/check-username')
def check_username():
    username = request.args.get('username', '').strip()
    if not username:
        return jsonify({'error': 'Username is required.'}), 400

    with conn.cursor() as cursor:
        sql = "SELECT * FROM users WHERE username=%s"
        cursor.execute(sql, (username,))
        user = cursor.fetchone()
    return jsonify({'exists': bool(user)})

# logout route 접속 시 logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("Goodbye. Come back to Purple anytime.", "success")
    return redirect('/')

def send_username_email(to_email, username):
    msg = EmailMessage()
    msg["Subject"] = "[PurpleBoard] Recover your username"
    msg["From"] = SMTP_USER
    msg["To"] = to_email
    msg.set_content(
        f"""Hello,

We received a request to recover your username.

{username}

"""
    )
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)

# 아이디 찾기 route
@app.route("/forgot-id", methods=["GET", "POST"])
def forgot_id():
    if request.method == "POST":
        email = request.form.get("email", "").strip()

        if not email:
            flash("Please enter your email address.", "error")
            return redirect("/forgot-id")

        with conn.cursor() as cursor:
            cursor.execute("SELECT username FROM users WHERE email=%s", (email,))
            user = cursor.fetchone()

        if user:
            send_username_email(email, user["username"])
            flash("Your username has been sent to your email.", "success")
            return redirect('/login')
        else:
            flash("No account found with that email.", "error")
            return redirect("/forgot-id")

    return render_template("auth/forgot_id.html")

def generate_temp_password(length=8):
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

def send_temp_password_email(to_email, temp_pw):
    msg = EmailMessage()
    msg["Subject"] = "[PurpleBoard] Reset your password"
    msg["From"] = SMTP_USER
    msg["To"] = to_email
    msg.set_content(
f"""Hello,

We received a request to reset your password.

{temp_pw}

Please log in and update your password as soon as you can.

"""
    )
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()

        if not username or not email:
            flash("Please fill in all fields.", "error")
            return redirect("/forgot-password")

        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE username=%s AND email=%s", (username, email))
            user = cursor.fetchone()

        flash_msg = "If the account exists, a temporary password has been sent to the registered email."

        if user:
            temp_pw = generate_temp_password()
            hashed_pw = generate_password_hash(temp_pw)

            with conn.cursor() as cursor:
                cursor.execute("UPDATE users SET password=%s WHERE username=%s", (hashed_pw, username))
                conn.commit()

            try:
                send_temp_password_email(email, temp_pw)
            except Exception:
                flash("Failed to send email. Please try again later.", "error")
                return redirect("/forgot-password")

        flash(flash_msg, "success")
        return redirect('/login')

    return render_template("auth/forgot_pw.html")

# board route 접속 시 로그인 여부 검증
# posts table의 데이터 게시판에 출력
@app.route('/board')
def board():
    if 'username' not in session:
        flash('You must be logged in.', "error")
        return redirect('/login')

    keyword = request.args.get('keyword', '').strip()
    category = request.args.get('category', 'all')

    with conn.cursor() as cursor:
        sql = """
            SELECT 
                id, title, content, author, secret,
                CASE
                    WHEN DATE(created_at) = CURDATE() THEN DATE_FORMAT(created_at, '%%H:%%i')
                    ELSE DATE_FORMAT(created_at, '%%y/%%m/%%d')
                END AS created_at_display
            FROM posts
        """
        values = []

        if keyword:
            if category == 'title':
                sql += " WHERE title LIKE %s"
                values.append(f"%{keyword}%")
            elif category == 'content':
                sql += " WHERE content LIKE %s"
                values.append(f"%{keyword}%")
            else:
                sql += " WHERE title LIKE %s OR content LIKE %s"
                values.extend([f"%{keyword}%", f"%{keyword}%"])

        sql += " ORDER BY posts.created_at DESC"

        cursor.execute(sql, values)
        posts = cursor.fetchall()

    return render_template('post/list.html', posts=posts, keyword=keyword, category=category)

# 게시판 접속 시 로그인 여부 검증
# 게시글 작성 폼 및 제출
@app.route('/write', methods=['GET', 'POST'])
def write():
    if 'username' not in session:
        flash('You must be logged in.', "error")
        return redirect('/login')

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        author = session['fullname']

        if 'secret' in request.form:
            secret = 1
            secret_pw_plain = request.form.get('secret_pw')
            if not secret_pw_plain:
                flash("Secret post password is required but missing.", "error")
                return redirect('/write')
            secret_pw_hash = generate_password_hash(secret_pw_plain)
        else:
            secret = 0
            secret_pw_hash = None

        # 초기 값 None 설정
        uploaded_filename = None
        # 파일 업로드 시 실행
        if 'file' in request.files:
            file = request.files['file']
            if file and file.filename != '':
                
        # 파일의 확장자 확인
                if allowed_file(file.filename):
        # 파일의 확장자 추출
                    ext = os.path.splitext(file.filename)[1].lower()
        # uuid를 통해 고유한 파일명 생성(32자리 hex 문자열 사용)
                    unique_filename = f"{uuid.uuid4().hex}{ext}"
        # 경로 생성
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        # 파일 디스크에 저장
                    file.save(filepath)
                    uploaded_filename = unique_filename
                else:
                    flash('Unsupported file type.', 'error')
                    return redirect('/write')

        with conn.cursor() as cursor:
            sql = """
                INSERT INTO posts (title, content, author, secret, secret_pw, attached_file)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(sql, (title, content, author, secret, secret_pw_hash, uploaded_filename))
            conn.commit()
            flash('Purple submitted successfully.', 'success')
        return redirect('/board')

    return render_template('/post/create.html')


# 게시글 접속 시 DB의 posts 테이블에서 내용을 가져와 view_port.html을 반환.
@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def view_post(post_id):
    if 'username' not in session:
        flash('You must be logged in.', "error")
        return redirect('/login')

    with conn.cursor(pymysql.cursors.DictCursor) as cursor:
        sql = "SELECT id, title, content, author, secret, secret_pw, attached_file, created_at FROM posts WHERE id = %s"
        cursor.execute(sql, (post_id,))
        post = cursor.fetchone()

    if not post:
        flash("This Purple doesn't exist.", "error")
        return redirect('/board')

    if post['secret'] == 0:
        # 비밀글 아니면 바로 글 보여줌
        return render_template('post/detail.html', post=post)

    if request.method == 'POST':
        input_pw = request.form.get('password', '')

# 비밀번호 인증 성공 세션 저장
        if input_pw and check_password_hash(post['secret_pw'], input_pw):
            session[f'secret_auth_{post_id}'] = True
            return render_template('post/detail.html', post=post)
        else:
            flash('Incorrect password for secret post.', 'error')
            return render_template('post/verify_pw.html', post_id=post_id)
    if not session.get(f'secret_auth_{post_id}'):

# 인증 실패 시 비밀번호 입력 폼 출력
        return render_template('post/verify_pw.html', post_id=post_id)

# 인증 성공 시 비밀 글 출력
    return render_template('post/detail.html', post=post)

# edit route 접속 시 해당 posts에 저장되었던 DB 내용을 다시 UPDATE 함.
@app.route('/edit/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    if 'username' not in session:
        flash('You must be logged in.', "error")
        return redirect('/login')

    with conn.cursor() as cursor:
        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            content = request.form.get('content', '').strip()
            
            if not title or not content:
                flash('Please fill in all fields.')
                return redirect(f'/edit/{post_id}')
            
            sql = "UPDATE posts SET title=%s, content=%s WHERE id=%s"
            cursor.execute(sql, (title, content, post_id))
            conn.commit()
            
            flash('Purple edited successfully.', "success")
            return redirect('/')
        
# 게시글이 없을 때 URL 접속 시 This Purple doesn't exist.를 출력하며 root route로 redirect.
        sql = "SELECT * FROM posts WHERE id=%s"
        cursor.execute(sql, (post_id,))
        post = cursor.fetchone()
        if not post:
            flash('This Purple doesn\'t exist.', "error")
            return redirect('/')
    return render_template('post/edit.html', post=post)

# 게시글 삭제 기능. DB의 posts 테이블의 내용을 삭제함.
@app.route('/delete/<int:post_id>', methods=['GET'])
def delete_post(post_id):
    if 'username' not in session:
        flash('You must be logged in.', "error")
        return redirect('/login')

    with conn.cursor() as cursor:
        sql = "DELETE FROM posts WHERE id=%s"
        cursor.execute(sql, (post_id,))
        conn.commit()
    
    flash('Purple deleted successfully.', "success")
    return redirect('/board')

@app.route('/check-secret-pw', methods=['POST'])
def check_secret_pw():
    post_id = request.form.get('post_id')
    input_pw = request.form.get('secret_password')

    if not post_id or not input_pw:
        return jsonify({'success': False, 'message': 'Post ID and password are required.'}), 400

    with conn.cursor() as cursor:
        sql = "SELECT secret_pw FROM posts WHERE id = %s"
        cursor.execute(sql, (post_id,))
        post = cursor.fetchone()

    if not post or not post['secret_pw']:
        return jsonify({'success': False, 'message': 'Post not found or no secret password set.'}), 404

    if check_password_hash(post['secret_pw'], input_pw):
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'message': 'Incorrect password.'}), 401
    
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 파일 다운로드 기능
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route("/profile", methods=["GET", "POST"])
def my_profile():
    if 'username' not in session:
        flash("You must be logged in.", "error")
        return redirect('/login')

    username = session['username']

    with conn.cursor() as cursor:
        cursor.execute("SELECT fullname, email, school, profile_image FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()

    if not user:
        flash("User not found.", "error")
        return redirect('/')

    if request.method == "POST":
        new_name = request.form.get("fullname", "").strip()
        new_email = request.form.get("email", "").strip()
        new_school = request.form.get("school", "").strip()

        profile_image_path = user["profile_image"]

    if "profile_image" in request.files:
        file = request.files["profile_image"]
        if file and file.filename:
            ext = os.path.splitext(file.filename)[1].lower()
            unique_filename = f"{uuid.uuid4().hex}{ext}"
            file_path = os.path.join(PROFILE_UPLOAD_FOLDER, unique_filename)
            os.makedirs(PROFILE_UPLOAD_FOLDER, exist_ok=True)
            file.save(file_path)
            profile_image_path = f"profile_images/{unique_filename}"


        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE users SET fullname=%s, email=%s, school=%s, profile_image=%s WHERE username=%s",
                (new_name, new_email, new_school, profile_image_path, username)
            )
            conn.commit()

        session['fullname'] = new_name
        flash("Profile updated successfully.", "success")
        return redirect("/profile")

    return render_template("user/profile_edit.html", user=user)


@app.route("/profile/<username>")
def view_profile(username):
    if 'username' not in session:
        flash("You must be logged in.", "error")
        return redirect('/login')

    with conn.cursor() as cursor:
        cursor.execute("SELECT fullname, email, school, profile_image FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()

    if not user:
        flash("User not found.", "error")
        return redirect('/users')

    return render_template("user/profile_view.html", user=user)


@app.route('/uploads/profile_images/<filename>')
def uploaded_profile_image(filename):
    return send_from_directory(PROFILE_UPLOAD_FOLDER, filename, as_attachment=False)

@app.route('/users')
def user_list():
    if 'username' not in session:
        flash("You must be logged in.", "error")
        return redirect('/login')

    with conn.cursor() as cursor:
        cursor.execute("SELECT username, fullname FROM users")
        users = cursor.fetchall()

    return render_template("user/list.html", users=users)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)