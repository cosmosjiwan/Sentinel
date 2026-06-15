from flask import Flask, render_template, request, send_file
from openai import OpenAI
import os

app = Flask(__name__)

# ✅ 환경변수에서 API 키를 읽어옴 (절대 하드코딩 금지)
client = OpenAI(
    api_key=os.environ.get("OPENAI_API_KEY")
)

# uploads / results 디렉토리 자동 생성
os.makedirs("uploads", exist_ok=True)
os.makedirs("results", exist_ok=True)

PROMPT = """
당신은 기업용 문서 보안 검열(Data Loss Prevention, DLP) 전문 AI이다.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚨 출력 형식 규칙 — 이것이 가장 중요한 지시사항이다
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

검열된 문서(섹션 1)에서 민감정보는 반드시 아래 마커로만 표시한다.
다른 어떤 형식(XML 태그, 대괄호, 볼드, 밑줄 등)도 절대 사용하지 않는다.

✅ 반드시 사용할 마커 형식:
@@REDACT|유형코드|원문|치환값@@

❌ 절대 사용 금지 (이 형식들을 쓰면 시스템이 작동하지 않는다):
- <R1>[치환값]</R1>  ← XML 태그 형식 금지
- **[치환값]**       ← 볼드 마커 형식 금지
- [치환값]           ← 단순 대괄호 형식 금지
- {치환값}           ← 중괄호 형식 금지

유형코드:
- person  → 개인정보 (이름, 전화번호, 이메일, 주민번호 등)
- org     → 기업/기관명
- ip      → 지적재산 (신약명, 프로젝트명, 성능수치 등)
- auth    → 인증정보 (API Key, Password, Token 등)
- secret  → 금융정보 및 기타

━━━ 올바른 출력 예시 ━━━

입력 문서:
  프로젝트명: Project Orion-X
  담당자: 김민수 부장
  연락처: 010-4827-1934
  이메일: mskim@orionbiotech.co.kr
  소속: 오리온바이오텍 연구소
  API 키: sk-abc123xyz

올바른 출력:
  프로젝트명: @@REDACT|ip|Project Orion-X|연구개발 프로젝트@@
  담당자: @@REDACT|person|김민수|부장 A@@ 부장
  연락처: @@REDACT|person|010-4827-1934|[연락처]@@
  이메일: @@REDACT|person|mskim@orionbiotech.co.kr|[이메일]@@
  소속: @@REDACT|org|오리온바이오텍 연구소|국내 기업 연구소@@
  API 키: @@REDACT|auth|sk-abc123xyz|[API_KEY]@@

━━━ 주의사항 ━━━
- "연락처:", "이메일:", "담당자:" 같은 레이블은 마커 밖에 그대로 둔다.
- 마커 안 원문에는 민감한 값만 넣는다 (레이블 제외).
- 동일 엔티티는 문서 전체에서 동일한 마커로 일관되게 치환한다.
- 파이프(|) 문자가 값에 포함되면 \\| 로 이스케이프한다.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## 민감정보 판단 원칙

다음 중 하나라도 해당하면 민감정보로 판단하고 비식별화한다:
1. 특정 인물을 식별할 수 있는 정보
2. 특정 기업/기관/연구소를 식별할 수 있는 정보
3. 경쟁사가 기술적/사업적 이익을 얻을 수 있는 정보
4. 법적·규제적 문제가 발생할 수 있는 정보
5. 보안 시스템에 접근 가능하게 하는 정보

## 문맥 기반 판단

- 실험 결과, 성능 수치, 측정값이 연구개발 맥락에서 등장 → 지적재산
- 내부 의사결정이나 미공개 계획을 암시하는 내용 → 기업 기밀
- 이름+직책+소속 조합으로 특정인 식별 가능 → 개인정보 (직책 유지, 이름만 비식별화)
- 수치+날짜+장소 조합으로 특정 사건 추적 가능 → 복합 민감정보

## 비식별화 방식

**이름 (역할 기반)**
- 김민수 부장 → 부장 A (마커에는 "김민수"만, 주변 직책은 마커 밖에 유지)
- 박영희 책임연구원 → 책임연구원 A
- 서로 다른 역할은 절대 동일한 치환값으로 통합하지 않는다

**기관/기업명**
- 일반 기업 → 국내 기업
- 대학 → 국내 대학
- 연구기관 → 정부 연구기관

**연구개발 정보**
- 신약명/후보물질명 → 연구 후보물질
- 프로젝트명/코드명 → 연구개발 프로젝트
- 제품명/모델명 → 개발 제품

**개인정보**
- 전화번호 → [연락처]
- 이메일 → [이메일]
- 주민등록번호 → [주민등록번호]

**인증정보 (완전 마스킹)**
- API Key → [API_KEY]
- Password → [PASSWORD]
- Secret Key → [SECRET_KEY]

**금융정보**
- 계좌번호 → [계좌정보]
- 카드번호 → [카드정보]

## 수치 데이터 처리

문서 목적이 내부 보고/대외비/불명확한 경우 수치 검열:
- 핵심 효능/성능 수치 → 범위로 일반화 (예: 87.3% → 80~90% 수준)
- 비교 우위 수치 → 정성적 표현 (예: 2.4배 향상 → 유의미한 성능 향상)
- 구체적 조건값 → 완전 마스킹

문서 목적이 학회발표/논문/공개보고인 경우 수치 유지.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## 출력 구조 (반드시 이 순서와 형식으로)

### 1. 검열된 전체 문서
(원문 구조를 유지하되 민감정보는 @@REDACT|...|...|..@@ 마커로만 표시)

### 2. 탐지된 민감정보 목록
| 유형 | 원문 | 위치 | 판단 근거 |
|------|------|------|-----------|

### 3. 치환 결과
| 원문 | 치환값 |
|------|--------|

### 4. 검열 요약
- 총 탐지 건수:
- 개인정보:
- 금융정보:
- 인증정보:
- 기업기밀:
- 지적재산:
- 보안등급:
"""

import re

def clean_markers(text):
    """
    @@REDACT|type|원문|치환값@@ → 치환값
    <Rn>[치환값]</Rn>           → [치환값]  (폴백 형식도 처리)
    이메일 주소의 @ 포함 케이스도 정확히 처리
    """
    text = re.sub(
        r'@@REDACT\|(\w+)\|(.+?)\|(.+?)@@',
        lambda m: m.group(3).replace('\\|', '|'),
        text,
        flags=re.DOTALL
    )
    text = re.sub(r'<R\d+>(.*?)</R\d+>', r'\1', text, flags=re.DOTALL)
    return text


@app.route("/")
def home():
    return render_template("index.html")

@app.route("/redact", methods=["POST"])
def redact():
    file = request.files["file"]
    upload_path = os.path.join("uploads", file.filename)
    file.save(upload_path)

    with open(upload_path, "rb") as f:
        uploaded_file = client.files.create(
            file=f,
            purpose="user_data"
        )

    response = client.responses.create(
        model="gpt-5.1",
        input=[
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": PROMPT
                    },
                    {
                        "type": "input_file",
                        "file_id": uploaded_file.id
                    }
                ]
            }
        ]
    )

    result_text = response.output_text

    output_file = os.path.join(
        "results",
        file.filename + "_redacted.txt"
    )

    clean_text = clean_markers(result_text)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(clean_text)

    return render_template(
        "success.html",
        filename=os.path.basename(output_file),
        result=result_text
    )

@app.route("/download/<filename>")
def download(filename):
    return send_file(
        os.path.join("results", filename),
        as_attachment=True
    )

if __name__ == "__main__":
    app.run(debug=True)
