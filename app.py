from flask import Flask, render_template, request, jsonify, redirect, url_for
from datetime import datetime, timezone, timedelta
from pymongo import MongoClient
from bson.objectid import ObjectId
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
import bcrypt
import random


app = Flask(__name__)

# JWT 설정
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = False  # 개발 환경에서는 False
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # 개발 환경에서는 False
app.config['JWT_SECRET_KEY'] = 'USE_SAFETY_KEY'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
jwt = JWTManager(app) 

jungle_quiz = [
    {"question": "세탁실에 있는 세탁기의 갯수는?", "answer": "8"},
    {"question": "정글 카페테리아 한끼 식사의 가격은?", "answer": "7000"},
    {"question": "정글 과정에서 사용하는 교과서의 개수는?", "answer": "4"},
    {"question": "운영체제 교과서의 옮긴이는 총 몇명?", "answer": "3"},
    {"question": "숙소동의 층수는?", "answer": "4"},
    {"question": "숙소 비밀번호의 자릿수는?", "answer": "5"}
]


# 공통 함수로 현재 사용자 정보 가져오기
def get_current_user():
    try:
        print("Cookies:", request.cookies)
        current_identity = get_jwt_identity()
        print("JWT Identity:", current_identity)
        if current_identity:
            user = db.cp_users.find_one({'username': current_identity})
            print("User from DB:", user)
            return user
    except Exception as e:
        print(f"Error in get_current_user: {e}")
    return None

# 미인증 사용자 처리
@jwt.unauthorized_loader
def unauthorized_callback(callback):
    # 로그인 페이지로 리다이렉트
    return redirect(url_for('login', next=request.path))


# MongoDB 연결
client = MongoClient('localhost', 27017)
db = client.dbjungle

@app.route('/')
@jwt_required(optional=True)
def home():
    # 리다이렉트 대신 직접 구현
    category_receive = request.args.get('category', '0')
    if category_receive == "0":
        result = list(db.cp_invites.find({}, {}).sort("created_at", -1))
    else:
        result = list(db.cp_invites.find({'category': category_receive}, {}).sort("created_at", -1))

    # 날짜 형식 변경 DB 자료 확인용
    for invite in result:
        if 'created_at' in invite:
            invite['created_at'] = invite['created_at'].strftime('%Y-%m-%d %H:%M')

    # 현재 사용자 정보 추가
    print("Cookies in home route:", request.cookies)
    current_user = get_current_user()
    print("Current user in home route:", current_user)

    return render_template('home.html', invites=result, user=current_user)


#초대장 가지고 오기 (카테고리 별)
@app.route('/home', methods=['GET'])
@jwt_required(optional=True)
def read_invite():
    category_receive = request.args.get('category', '0')
    title_receive = request.args.get('title', ' ')
    if category_receive == "0":
        if title_receive == ' ' :
            result = list(db.cp_invites.find({}, {}).sort("created_at", -1))
        else :
            result = list(db.cp_invites.find({'title' : title_receive}, {}).sort("created_at", -1))
    else:
        if title_receive == ' ' :
            result = list(db.cp_invites.find({'category': category_receive}, {}).sort("created_at", -1))
        else :
            result = list(db.cp_invites.find({'title' : title_receive, 'category': category_receive}, {}).sort("created_at", -1))

    # 날짜 형식 변경
    for invite in result:
        if 'created_at' in invite:
            invite['created_at'] = invite['created_at'].strftime('%Y-%m-%d %H:%M')
    # 현재 사용자 정보 추가
    print("Cookies in home route:", request.cookies)
    current_user = get_current_user()
    print("Current user in home route:", current_user)

    return render_template('home.html', invites=result, user=current_user) 




#초대장 검색 (제목)
@app .route('/select', methods=['POST'])
def select():
    title_recevie = request.form['title_give']
    return redirect('read_invite', title=title_recevie, category=0)


#파티 모집 신청
@app.route('/apply', methods=['GET','POST'])
@jwt_required()
def apply():
    if request.method == 'POST' :
        title_receive = request.form['title_give']
        category_receive = request.form['category_give']
        chat_receive = request.form['chat_give']
        pw_receive = request.form['pw_give']

        if not title_receive :
            current_user = get_current_user()
            return render_template('apply.html', error_message= '제목을 입력해주세요!', user=current_user)
        elif not chat_receive :
            current_user = get_current_user()
            return render_template('apply.html', error_message= '오픈 채팅 URL을 입력해주세요!', user=current_user)
        elif not pw_receive :
            current_user = get_current_user()
            return render_template('apply.html', error_message= '비밀번호를를 입력해주세요!', user=current_user)


        
        limit_person_receive = request.form['limit_person_give']
        type_receive = request.form['type_give']
        note_receive = request.form['note_give']

        invite = {
            'title': title_receive,
            'limit_person': int(limit_person_receive),
            'now_person': 0,
            'type': type_receive,
            'category': category_receive,
            'chat': chat_receive,
            'note': note_receive,
            'pw': pw_receive,
            "created_at": datetime.now(timezone.utc) + timedelta(hours=9) #한국 시간으로 설정하기
        }

        db.cp_invites.insert_one(invite)
        return redirect(url_for('read_invite', category=0))
    current_user = get_current_user()
    return render_template('apply.html', user=current_user)



#초대장 삭제 (기본키 이용)
@app.route('/delete', methods=['POST'])
@jwt_required()
def delete():
    id_receive = ObjectId(request.form.get('id_give'))
    db.cp_invites.delete_one({'_id': id_receive})
    return redirect(url_for('read_invite', category=0))


#파티 참가 (기본키 이용)
@app.route('/complete', methods=['GET','POST'])
@jwt_required()
def complete():
    if request.method == 'POST' :
        id_receive = ObjectId(request.form['id_give'])
        db.cp_invites.update_one({'_id': id_receive}, {'$inc': {'now_person': 1}})
        return redirect(url_for('complete', id=str(id_receive)))
    id = ObjectId(request.args.get('id'))
    result = db.cp_invites.find_one({'_id': id}, {'_id': 0})

    # 날짜 형식 변경
    result['created_at'] = result['created_at'].strftime('%Y-%m-%d %H:%M')

    # 현재 사용자 정보 추가
    current_user = get_current_user()
    return render_template('complete.html', invite=result, user=current_user)


#업데이트
@app.route('/update', methods=['POST'])
def update():
    id_receive = ObjectId(request.form['id_give'])
    result = list(db.cp_invites.find({'_id': id_receive}, {}))
    return render_template('update.html', invite=result[0])




@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # 사용자 찾기
        user = db.cp_users.find_one({'username': username})
        
        # 사용자가 존재하고 비밀번호가 일치하는지 확인
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            # JWT 액세스 토큰 생성
            access_token = create_access_token(identity=username)
            
            # next 파라미터가 있으면 해당 페이지로 리다이렉트
            next_page = request.args.get('next')
            if next_page:
                resp = redirect(next_page)
            else:
                resp = redirect(url_for('read_invite', category=0))
                
            resp.set_cookie('access_token_cookie', access_token, httponly=True, path='/')
            return resp
        else:
            current_user = get_current_user()
            return render_template('login.html', error_message='아이디 또는 비밀번호가 일치하지 않습니다!', user=current_user)
    
    message = request.args.get('message', '')
    current_user = get_current_user()
    next_page = request.args.get('next', '')
    return render_template('login.html', message=message, user=current_user, next=next_page)
    

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        # 폼 데이터 받기
        username = request.form.get('username')
        password = request.form.get('password')
        nickname = request.form.get('nickname')
        quiz_answer = request.form.get('quiz_answer')
        quiz_index = int(request.form.get('quiz_index', 0))
        
        # 유효성 검사
        if not username or not password or not nickname:
            current_user = get_current_user()
            return render_template('signup.html', error_message='모든 필드를 입력해주세요!', user=current_user)
        
        # 퀴즈 답변 확인 - 문자열로 변환하여 비교
        correct_answer = str(jungle_quiz[quiz_index]["answer"]).strip()
        user_answer = quiz_answer.strip()
        
        if user_answer != correct_answer:
            # 새로운 랜덤 퀴즈 선택
            random_quiz = random.choice(jungle_quiz)
            random_index = jungle_quiz.index(random_quiz)
            current_user = get_current_user()
            return render_template('signup.html', error_message='정글 퀴즈 정답이 틀렸습니다!', 
                                 quiz=random_quiz, quiz_index=random_index, user=current_user)
        
        # 사용자 중복 확인
        existing_user = db.cp_users.find_one({'username': username})
        if existing_user:
            # 새로운 랜덤 퀴즈 선택
            random_quiz = random.choice(jungle_quiz)
            random_index = jungle_quiz.index(random_quiz)
            current_user = get_current_user()
            return render_template('signup.html', error_message='이미 존재하는 아이디입니다!', 
                                 quiz=random_quiz, quiz_index=random_index, user=current_user)
        
        # 비밀번호 해싱
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # 새 사용자 저장
        user = {
            'username': username,
            'password': hashed_password,
            'nickname': nickname,
        }
        db.cp_users.insert_one(user)
        
        return redirect(url_for('login', message='회원가입 성공! 로그인해주세요.'))
    
    # GET 요청 처리 - 랜덤 퀴즈 선택
    random_quiz = random.choice(jungle_quiz)
    random_index = jungle_quiz.index(random_quiz)
    current_user = get_current_user()
    return render_template('signup.html', quiz=random_quiz, quiz_index=random_index, user=current_user)

# 아이디 중복 확인 API
@app.route('/api/check-username', methods=['POST'])
def check_username():
    username = request.form.get('username')
    
    if not username:
        return jsonify({'success': False, 'message': '아이디를 입력해주세요.'})
    
    # 사용자 중복 확인
    existing_user = db.cp_users.find_one({'username': username})
    
    if existing_user:
        return jsonify({'success': False, 'message': '이미 사용 중인 아이디입니다.'})
    else:
        return jsonify({'success': True, 'message': '사용 가능한 아이디입니다.'})

# 로그아웃 라우트
@app.route('/logout', methods=['GET'])
def logout():
    resp = redirect(url_for('login'))
    resp.delete_cookie('access_token_cookie', path='/')  # path='/' 추가
    return resp

@app.route('/check-jwt')
@jwt_required()
def check_jwt():
    print("Cookies:", request.cookies)
    try:
        identity = get_jwt_identity()
        print("Identity:", identity)
        if identity:
            user = db.cp_users.find_one({'username': identity})
            return jsonify({"logged_in": True, "username": identity, "user": str(user)})
        return jsonify({"logged_in": False})
    except Exception as e:
        return jsonify({"error": str(e)})



if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
