# Python 3.11 slim 이미지 사용
FROM python:3.11-slim

# 작업 디렉토리를 /app으로 설정
WORKDIR /app

# /app/requirments.txt 경로로 파일 복사
COPY requirements.txt ./

# requirements.txt 파일에 명시된 모든 패키지를 캐시없이 설치
RUN pip install --no-cache-dir -r requirements.txt

# 로컬 프로젝트 폴더에 있는 파일 전부를 컨테이너 내부의 작업 디렉토리 /app 폴더로 복사
COPY . .

# 환경 변수 설정
# FLASK_APP의 Entrypoint를 app.py로 지정
ENV FLASK_APP=app.py

# Flask 개발 서버를 모든 IP 주소에서 접근 가능하도록 설정
ENV FLASK_RUN_HOST=0.0.0.0

# 디버그 설정을 끄고 배포용으로 실행
ENV FLASK_ENV=production

# 5000번 포트 사용
EXPOSE 5000

# 컨테이너가 실행될 때 flask run 명령 실행
CMD ["flask", "run"]
