# Sentinel DLP — AI 문서 보안 검열

LLM 기반 내부 문서 민감정보 자동 탐지 및 비식별화 시스템

## 프로젝트 구조

```
sentinel-dlp/
├── app.py                 # Flask 백엔드
├── templates/
│   ├── index.html         # 파일 업로드 페이지
│   └── success.html       # 검열 결과 페이지
├── requirements.txt       # Python 패키지
├── render.yaml            # Render 배포 설정
└── .gitignore
```

## 배포 방법 (Render — 무료)

### 1단계: GitHub 레포지토리 생성

```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/sentinel-dlp.git
git branch -M main
git push -u origin main
```

### 2단계: Render 연결

1. [render.com](https://render.com) 가입 (GitHub 계정으로 로그인)
2. Dashboard → **New** → **Web Service**
3. GitHub 레포지토리 `sentinel-dlp` 선택
4. 설정 자동 감지됨 (render.yaml 기반). 아래만 확인:
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app --bind 0.0.0.0:$PORT`
5. **Environment Variables** 탭에서 추가:
   - Key: `OPENAI_API_KEY`
   - Value: `sk-proj-...` (본인의 OpenAI API 키)
6. **Deploy** 클릭

배포 완료 후 `https://sentinel-dlp.onrender.com` 형태의 URL이 생성됨.

### 로컬 실행 (개발용)

```bash
pip install -r requirements.txt
export OPENAI_API_KEY="sk-proj-..."   # macOS/Linux
# set OPENAI_API_KEY=sk-proj-...     # Windows CMD
python app.py
```

http://localhost:5000 에서 접속.

## 주의사항

- **API 키는 절대 코드에 하드코딩하지 마세요.** 환경변수(`OPENAI_API_KEY`)로 관리합니다.
- Render 무료 티어는 15분 비활성 시 서버가 슬립됩니다. 첫 요청 시 ~30초 대기가 있을 수 있습니다.
- `uploads/`와 `results/` 디렉토리는 서버 시작 시 자동 생성됩니다.
