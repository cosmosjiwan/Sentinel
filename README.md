# Sentinel DLP — AI 문서 보안 검열

LLM 기반 내부 문서 민감정보 자동 탐지 및 비식별화 시스템

## 주요 기능

- **AI 민감정보 탐지 + ISO 27005 위험성 평가** — 등급별 검열(특급=차단 / 1급=마스킹 / 2급=치환 / 3급=공개)
- **검토자 검토 화면** — 탐지 항목별 검열 방식 전환·치환 표현 직접 수정, 탐지 근거 및 기밀성/무결성/가용성(C·I·A) 분해 표시
- **검토 도구** — 등급 필터·정렬, 표시 항목 일괄 적용(마스킹/치환/공개)
- **수동 추가 검열** — 본문에서 텍스트를 드래그해 AI가 놓친 항목을 직접 추가/삭제
- **검열본 내보내기** — TXT / PDF / DOCX (한글 포함, 단락 구조 유지)
- **검열 이력 & 대시보드** — 과거 결과 재방문, 위험 현황·등급 분포 통계
- **정책 설정 UI** — 점수 가중치·등급 임계값·커스텀 정규식·키워드 사전을 코드 수정 없이 조정 (`policy.json`)

## 프로젝트 구조

```
sentinel-dlp/
├── app.py                 # Flask 백엔드 (라우팅·검열 파이프라인)
├── patterns.py            # 정규식 1차 탐지 + 정책 커스텀 규칙/사전
├── risk.py                # ISO 27005 점수·등급 산출 (정책 기반)
├── policy.py              # 정책(policy.json) 로드/저장
├── export.py              # 검열본 PDF/DOCX 생성
├── templates/
│   ├── input.html         # 파일 업로드 페이지
│   ├── loading.html       # 검열 진행 오버레이
│   ├── list.html          # 일괄 검열 결과 목록
│   ├── output.html        # 검열 결과 검토 화면
│   ├── dashboard.html     # 검열 이력 & 대시보드
│   └── policy.html        # 정책 설정
├── static/css/            # 화면별 스타일
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
