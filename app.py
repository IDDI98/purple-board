from flask import Flask, render_template, request, redirect, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import requests
import pymysql
import os

# .env 파일로부터 DB 설정 값 불러옴
load_dotenv()

# FLASK 앱 및 32바이트 크기의 secret key 생성
app = Flask(__name__)
app.secret_key = os.urandom(32)

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
    return render_template('signup.html')

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
    phone = request.form.get('phone', '').strip()
    token = request.form['g-recaptcha-response']
    secret = os.getenv("SECRET_KEY")
    verify_url = 'https://www.google.com/recaptcha/api/siteverify'

# 서버 측 공백 회원가입 필터링
    if not fullname or not username or not password or not password_confirm or not email or not phone:
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
            sql = "INSERT INTO users (fullname, username, password, email, phone) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(sql, (fullname, username, hashed_password, email, phone))
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

# DB에 저장된 회원정보와 사용자 입력 값 비교
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
        return render_template('login.html')

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

# board route 접속 시 로그인 여부 검증
# posts table의 데이터 게시판에 출력
@app.route('/board')
def board():
    if 'username' not in session:
        flash('You must be logged in.', "error")
        return redirect('/login')

    with conn.cursor() as cursor:
        sql = """
            SELECT 
                id, title, content, author,
                CASE
                    WHEN DATE(created_at) = CURDATE() THEN DATE_FORMAT(created_at, '%H:%i')
                    ELSE DATE_FORMAT(created_at, '%y/%m/%d')
                END AS created_at
            FROM posts
            ORDER BY created_at DESC
        """
        cursor.execute(sql)
        posts = cursor.fetchall()
    return render_template('board.html', posts=posts)


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

        with conn.cursor() as cursor:
            sql = "INSERT INTO posts (title, content, author) VALUES (%s, %s, %s)"
            cursor.execute(sql, (title, content, author))
            conn.commit()

        flash('Purple submitted successfully.',"success")
        return redirect('/board')
    return render_template('new_post.html')


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
        
        # GET 요청일 때, 기존 게시글 불러오기
        sql = "SELECT * FROM posts WHERE id=%s"
        cursor.execute(sql, (post_id,))
        post = cursor.fetchone()
        if not post:
            flash('This Purple doesn\'t exist.', "error")
            return redirect('/')
    return render_template('edit_post.html', post=post)

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

@app.route('/post/<int:post_id>', methods=['GET'])
def view_post(post_id):
    if 'username' not in session:
        flash('You must be logged in.', "error")
        return redirect('/login')

    with conn.cursor() as cursor:
        sql = "SELECT id, title, content, author, created_at FROM posts WHERE id = %s"
        cursor.execute(sql, (post_id,))
        post = cursor.fetchone() 
    return render_template('view_post.html', post=post)

if __name__ == "__main__":
    app.run(debug=True)

