from flask import Flask, render_template, request, send_file, jsonify, abort
from openai import OpenAI
import os
import re
import json

from patterns import scan_regex, force_mask_residual, MASK_TOKEN
from risk import compute_score, grade_for_score, action_for_grade, GRADE_LABEL

app = Flask(__name__)

# ✅ 환경변수에서 API 키를 읽어옴 (절대 하드코딩 금지)
client = OpenAI(
    api_key=os.environ.get("OPENAI_API_KEY")
)

# uploads / results 디렉토리 자동 생성
os.makedirs("uploads", exist_ok=True)
os.makedirs("results", exist_ok=True)

TEXT_EXTS = (".txt", ".md")

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
- 아래 "사전 탐지된 정규식 매칭 항목"이 입력으로 함께 제공되면, 해당 항목들은
  반드시 누락 없이 마커로 포함시키고, 추가로 발견되는 항목도 함께 탐지한다.

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

## ISO 27005 기반 위험성 평가 (반드시 수행)

문서 전체의 민감도를 기밀성(Confidentiality) / 무결성(Integrity) / 가용성(Availability)
3가지 기준으로 각각 0~100점으로 평가한다.

- 기밀성(C): 이 문서가 외부에 노출되었을 때의 피해 정도.
  개인 식별정보·인증정보·금융정보·경쟁사에 유리한 핵심 기밀이 많을수록 높음 (90~100).
  일반적인 기업 정보는 40~70, 누구나 알아도 무방한 정보는 0~20.
- 무결성(I): 문서 내용이 변조/오염될 경우 업무적·법적으로 미치는 영향.
  계약, 규정, 실험 데이터, 의사결정 근거 문서는 높게, 단순 공지성 문서는 낮게.
- 가용성(A): 문서가 유실되거나 비공개 처리될 경우 업무에 미치는 영향.
  핵심 연구/의사결정 자료는 높게, 참고용 자료는 낮게.

이 3가지 점수는 섹션 5에 아래 형식의 한 줄 JSON으로 반드시 출력한다 (다른 텍스트 섞지 말 것):

RISK_JSON: {"confidentiality": <0-100 정수>, "integrity": <0-100 정수>, "availability": <0-100 정수>}

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

### 5. 위험성 평가 (ISO 27005)
RISK_JSON: {"confidentiality": 0, "integrity": 0, "availability": 0}
"""

RISK_RE = re.compile(r'RISK_JSON:\s*(\{[^\n]*\})')
MARKER_RE = re.compile(r'@@REDACT\|(\w+)\|(.+?)\|(.+?)@@', re.DOTALL)


def clean_markers(text):
    """
    @@REDACT|type|원문|치환값@@ → 치환값
    <Rn>[치환값]</Rn>           → [치환값]  (폴백 형식도 처리)
    """
    text = MARKER_RE.sub(
        lambda m: m.group(3).replace('\\|', '|'),
        text
    )
    text = re.sub(r'<R\d+>(.*?)</R\d+>', r'\1', text, flags=re.DOTALL)
    return text


def extract_text(path, filename):
    """텍스트 파일(.txt/.md)은 직접 읽어 정규식 사전탐지 및 인라인 전달에 사용한다.
    그 외 형식(.pdf/.docx)은 OpenAI Files API로 업로드해 처리한다."""
    if filename.lower().endswith(TEXT_EXTS):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except OSError:
            return None
    return None


def run_detection(upload_path, filename, raw_text):
    """OpenAI에 탐지+위험성평가를 요청하고 원본 응답 텍스트를 반환한다."""
    if raw_text is not None:
        regex_hits = scan_regex(raw_text)
        hint = ""
        if regex_hits:
            lines = "\n".join(f"- [{h['type']}] {h['value']}" for h in regex_hits)
            hint = f"\n\n## 사전 탐지된 정규식 매칭 항목\n{lines}\n"
        response = client.responses.create(
            model="gpt-5.1",
            input=[
                {
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": PROMPT + hint + "\n\n## 검열 대상 문서\n" + raw_text},
                    ],
                }
            ],
        )
        return response.output_text

    with open(upload_path, "rb") as f:
        uploaded_file = client.files.create(file=f, purpose="user_data")

    response = client.responses.create(
        model="gpt-5.1",
        input=[
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "text": PROMPT},
                    {"type": "input_file", "file_id": uploaded_file.id},
                ],
            }
        ],
    )
    return response.output_text


def parse_risk(result_text):
    """RISK_JSON을 파싱하고, C/I/A로부터 점수·등급을 서버 측에서 일관되게 산출한다."""
    m = RISK_RE.search(result_text)
    confidentiality = integrity = availability = 50
    if m:
        try:
            data = json.loads(m.group(1))
            confidentiality = int(data.get("confidentiality", 50))
            integrity = int(data.get("integrity", 50))
            availability = int(data.get("availability", 50))
        except (ValueError, json.JSONDecodeError):
            pass
    score = compute_score(confidentiality, integrity, availability)
    grade = grade_for_score(score)
    return {
        "confidentiality": confidentiality,
        "integrity": integrity,
        "availability": availability,
        "score": score,
        "grade": grade,
        "grade_label": GRADE_LABEL[grade],
    }


def safe_force_mask(text, grade):
    """마커 구간은 보존한 채, 마커 밖에 평문으로 남은 정규식 매칭 잔여 노출을 강제 마스킹한다."""
    if grade == "3급":
        return text
    placeholders = []

    def stash(m):
        placeholders.append(m.group(0))
        return f"\x00{len(placeholders) - 1}\x00"

    stashed = MARKER_RE.sub(stash, text)
    masked = force_mask_residual(stashed)

    def restore(m):
        return placeholders[int(m.group(1))]

    return re.sub(r'\x00(\d+)\x00', restore, masked)


def apply_grade_marker_rewrite(text, grade):
    """등급별 처리 방침에 따라 마커의 '치환값' 필드를 재작성한다.
    (마커 구조 자체는 유지하므로 프론트엔드 파서는 변경 없이 그대로 동작한다)"""
    action = action_for_grade(grade)

    if action == "publish":  # 3급: 원문 그대로 노출
        return MARKER_RE.sub(lambda m: f"@@REDACT|{m.group(1)}|{m.group(2)}|{m.group(2)}@@", text)

    if action == "mask":  # 1급: 완전 마스킹
        return MARKER_RE.sub(
            lambda m: f"@@REDACT|{m.group(1)}|{m.group(2)}|{MASK_TOKEN.get(m.group(1), '[마스킹]')}@@",
            text,
        )

    # substitute (2급): 모델이 제안한 의미유지 치환값 그대로 사용
    return text


def process_file(upload_path, filename):
    """단일 파일에 대해 탐지 → 위험성평가 → 등급별 처리까지 전체 파이프라인을 수행하고
    결과를 results/ 에 저장한 뒤 요약 dict를 반환한다."""
    raw_text = extract_text(upload_path, filename)
    result_text = run_detection(upload_path, filename, raw_text)
    risk = parse_risk(result_text)
    grade = risk["grade"]

    result_text = safe_force_mask(result_text, grade)

    blocked = action_for_grade(grade) == "block"
    if blocked:
        display_text = None
        clean_text = (
            f"[차단됨] 본 문서는 위험성 평가 결과 '{risk['grade_label']}' 등급으로 분류되어 "
            f"공개·다운로드가 금지됩니다. (민감성 점수: {risk['score']})"
        )
    else:
        display_text = apply_grade_marker_rewrite(result_text, grade)
        clean_text = clean_markers(display_text)

    base = os.path.basename(filename)
    txt_path = os.path.join("results", base + "_redacted.txt")
    json_path = os.path.join("results", base + ".json")

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(clean_text)

    record = {
        "filename": base,
        "raw_result": display_text if not blocked else "",
        "clean_text": clean_text,
        "risk": risk,
        "blocked": blocked,
        "txt_name": base + "_redacted.txt",
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(record, f, ensure_ascii=False, indent=2)

    return record


@app.route("/")
def home():
    return render_template("input.html")


@app.route("/redact", methods=["POST"])
def redact():
    files = request.files.getlist("file")
    if not files or all(f.filename == "" for f in files):
        abort(400)

    results = []
    for file in files:
        if not file.filename:
            continue
        upload_path = os.path.join("uploads", os.path.basename(file.filename))
        file.save(upload_path)
        record = process_file(upload_path, file.filename)
        results.append(record)

    return render_template("batch_result.html", results=results)


@app.route("/view/<filename>")
def view_result(filename):
    json_path = os.path.join("results", os.path.basename(filename) + ".json")
    if not os.path.exists(json_path):
        abort(404)
    with open(json_path, "r", encoding="utf-8") as f:
        record = json.load(f)

    return render_template(
        "output.html",
        filename=record["filename"],
        result=record["raw_result"],
        risk=record["risk"],
        blocked=record["blocked"],
    )


@app.route("/apply_review/<filename>", methods=["POST"])
def apply_review(filename):
    """검토자가 항목별 치환 표현을 직접 수정한 결과를 저장한다.
    accept/reject 뿐 아니라 자유 텍스트 수정을 허용한다."""
    json_path = os.path.join("results", os.path.basename(filename) + ".json")
    if not os.path.exists(json_path):
        abort(404)
    with open(json_path, "r", encoding="utf-8") as f:
        record = json.load(f)

    if record["blocked"]:
        return jsonify({"ok": False, "error": "blocked 문서는 검토를 적용할 수 없습니다."}), 400

    edits = request.get_json(silent=True) or {}
    edits = edits.get("edits", [])

    text = record["raw_result"]
    for edit in edits:
        type_ = edit.get("type", "")
        orig = edit.get("orig", "")
        replacement = edit.get("replacement", "")
        if not orig:
            continue
        escaped_orig = re.escape(orig)
        escaped_type = re.escape(type_)
        pattern = re.compile(
            r'@@REDACT\|' + escaped_type + r'\|' + escaped_orig + r'\|(.+?)@@',
            re.DOTALL,
        )
        text = pattern.sub(
            f"@@REDACT|{type_}|{orig}|{replacement.replace('|', chr(92) + '|')}@@", text
        )

    clean_text = clean_markers(text)
    record["raw_result"] = text
    record["clean_text"] = clean_text

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(record, f, ensure_ascii=False, indent=2)
    with open(os.path.join("results", record["txt_name"]), "w", encoding="utf-8") as f:
        f.write(clean_text)

    return jsonify({"ok": True})


@app.route("/download/<filename>")
def download(filename):
    return send_file(
        os.path.join("results", filename),
        as_attachment=True
    )


if __name__ == "__main__":
    app.run(debug=True)
