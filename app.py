from flask import Flask, render_template, request, send_file, jsonify, abort
from openai import OpenAI
import os
import re
import json
import subprocess
import datetime

# 한국 표준시(KST, UTC+9) — 배포 시각을 서버 타임존과 무관하게 일관되게 표기하기 위함
KST = datetime.timezone(datetime.timedelta(hours=9))


def get_deploy_time():
    """현재 배포된 코드(main HEAD 커밋)의 시각을 KST 'YYYY.MM.DD HH:MM' 형식으로 반환한다.
    git 정보를 얻지 못하면 app.py 파일의 수정 시각으로 대체한다."""
    repo_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        ts = subprocess.check_output(
            ["git", "-C", repo_dir, "log", "-1", "--format=%ct"],
            stderr=subprocess.DEVNULL,
        ).decode().strip()
        epoch = int(ts)
    except (subprocess.SubprocessError, ValueError, OSError):
        try:
            epoch = int(os.path.getmtime(os.path.abspath(__file__)))
        except OSError:
            return ""
    return datetime.datetime.fromtimestamp(epoch, KST).strftime("%Y.%m.%d %H:%M")

from patterns import scan_regex, force_mask_residual, MASK_TOKEN
from risk import compute_score, grade_for_score, action_for_grade, GRADE_LABEL, GRADE_THRESHOLDS

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

검열된 문서(섹션 1) 본문에는 민감정보의 "치환 표현"만 짧은 번호 태그로 표시하고,
원문/등급/점수 같은 상세 정보는 절대 본문에 넣지 않는다 — 반드시 섹션 2의 표로만 보낸다.
이렇게 분리하는 이유: 이메일 주소처럼 특수문자(@)가 포함된 원문이 본문에 그대로
섞여 들어가면 다른 표시 형식과 충돌하므로, 본문은 항상 일반 텍스트만 유지한다.

✅ 본문(섹션 1)에서 반드시 사용할 태그 형식:
<R번호>치환표현</R번호>
(번호는 1부터 시작하는 정수이며, 동일 엔티티는 문서 전체에서 동일 번호를 사용한다)

❌ 절대 사용 금지 (이 형식들을 쓰면 시스템이 작동하지 않는다):
- @@REDACT|...@@     ← 구버전 마커 형식 금지
- **[치환값]**       ← 볼드 마커 형식 금지
- [치환값]           ← 태그 없는 단순 대괄호 형식 금지 (반드시 <R번호>로 감싼다)

✅ 본문 밖, 섹션 2 표에 반드시 채워야 할 상세 정보:
| 번호 | 유형 | 등급 | 점수 | 원문 | 치환표현 | 판단 근거 |

유형코드:
- person  → 개인정보 (이름, 전화번호, 이메일, 주민번호 등)
- org     → 기업/기관명
- ip      → 지적재산 (신약명, 프로젝트명, 성능수치 등)
- auth    → 인증정보 (API Key, Password, Token 등)
- secret  → 금융정보 및 기타

등급/점수 (항목 단위 ISO 27005 평가 — 문서 전체 점수와는 별개로, 이 항목 하나만 노출됐을 때의 민감도):
- 점수는 0~100 사이 정수.
- 등급은 점수에 따라 자동 결정: 90점 이상=특급, 70~89점=1급, 40~69점=2급, 39점 이하=3급.
- API Key/비밀번호 등 인증정보, 주민번호 등은 특급~1급으로 높게 평가한다.
- 이름/연락처 등 일반 개인정보는 1급~2급, 일반적인 기업명/프로젝트명은 2급 내외로 평가한다.

━━━ 올바른 출력 예시 ━━━

입력 문서:
  프로젝트명: Project Orion-X
  담당자: 김민수 부장
  연락처: 010-4827-1934
  이메일: mskim@orionbiotech.co.kr
  소속: 오리온바이오텍 연구소
  API 키: sk-abc123xyz

섹션 1 (본문) 올바른 출력:
  프로젝트명: <R1>연구개발 프로젝트</R1>
  담당자: <R2>부장 A</R2> 부장
  연락처: <R3>[연락처]</R3>
  이메일: <R4>[이메일]</R4>
  소속: <R5>국내 기업 연구소</R5>
  API 키: <R6>[API_KEY]</R6>

섹션 2 (표) 올바른 출력:
| 번호 | 유형 | 등급 | 점수 | 원문 | 치환표현 | 판단 근거 |
|------|------|------|------|------|----------|-----------|
| 1 | ip | 2급 | 55 | Project Orion-X | 연구개발 프로젝트 | 프로젝트 코드명 |
| 2 | person | 2급 | 50 | 김민수 | 부장 A | 이름 |
| 3 | person | 1급 | 75 | 010-4827-1934 | [연락처] | 전화번호 |
| 4 | person | 1급 | 72 | mskim@orionbiotech.co.kr | [이메일] | 이메일 |
| 5 | org | 2급 | 45 | 오리온바이오텍 연구소 | 국내 기업 연구소 | 소속 기관 |
| 6 | auth | 특급 | 95 | sk-abc123xyz | [API_KEY] | API 키 |

━━━ 주의사항 ━━━
- "연락처:", "이메일:", "담당자:" 같은 레이블은 태그 밖에 그대로 둔다.
- <R번호> 태그 안에는 치환 표현만 넣는다 (레이블 제외, 원문 절대 금지).
- 동일 엔티티는 문서 전체에서 동일한 번호로 일관되게 치환한다 (등급/점수도 동일하게 유지).
- 표의 셀 값에 파이프(|) 문자가 포함되면 다른 기호(예: /)로 바꿔 표 구조가 깨지지 않게 한다.
- 아래 "사전 탐지된 정규식 매칭 항목"이 입력으로 함께 제공되면, 해당 항목들은
  반드시 누락 없이 태그로 포함시키고, 추가로 발견되는 항목도 함께 탐지한다.

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

이 3가지 점수는 섹션 4에 아래 형식의 한 줄 JSON으로 반드시 출력한다 (다른 텍스트 섞지 말 것):

RISK_JSON: {"confidentiality": <0-100 정수>, "integrity": <0-100 정수>, "availability": <0-100 정수>}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## 출력 구조 (반드시 이 순서와 형식으로)

### 1. 검열된 전체 문서
(원문 구조를 유지하되 민감정보는 <R번호>치환표현</R번호> 태그로만 표시)

### 2. 탐지된 민감정보 상세
| 번호 | 유형 | 등급 | 점수 | 원문 | 치환표현 | 판단 근거 |
|------|------|------|------|------|----------|-----------|

### 3. 검열 요약
- 총 탐지 건수:
- 개인정보:
- 금융정보:
- 인증정보:
- 기업기밀:
- 지적재산:

### 4. 위험성 평가 (ISO 27005)
RISK_JSON: {"confidentiality": 0, "integrity": 0, "availability": 0}
"""

RISK_RE = re.compile(r'RISK_JSON:\s*(\{[^\n]*\})')
TAG_RE = re.compile(r'<R(\d+)>(.*?)</R\1>', re.DOTALL)
ITEM_GRADES = ("특급", "1급", "2급", "3급")


def clean_markers(text):
    """<R번호>치환표현</R번호> → 치환표현"""
    return TAG_RE.sub(lambda m: m.group(2), text)


def parse_items(result_text):
    """섹션 2 표를 파싱해 항목별 상세 정보를 {번호: {...}} 딕셔너리로 만든다.
    줄 단위로 파이프(|)를 분리하는 관대한 방식 — 모델이 들여쓰기/말미 파이프 누락 등
    표 형식을 정확히 지키지 않아도 행을 인식할 수 있도록 한다."""
    items = {}
    for line in result_text.splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 7:
            continue
        id_str, type_, grade, score_str, orig, replaced, reason = cells[:7]
        if not id_str.isdigit() or type_ in ("유형", "") or set(type_) <= {"-"}:
            continue
        try:
            score = max(0, min(100, int(re.sub(r'[^\d-]', '', score_str) or 0)))
        except ValueError:
            score = 50
        if grade not in ITEM_GRADES:
            grade = grade_for_score(score)
        items[id_str] = {
            "id": id_str,
            "type": type_,
            "grade": grade,
            "score": score,
            "orig": orig,
            "replaced": replaced,
            "reason": reason,
        }
    return items


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


def get_section(text, n):
    """'### n. ...' 헤딩으로 시작해 다음 '## 숫자' 헤딩 전까지의 섹션 텍스트를 추출한다.
    모델이 '##'/'###' 중 어느 쪽을 쓰든 인식하도록 관대하게 매칭한다."""
    m = re.search(rf'#{{2,3}}\s*{n}[.\s][\s\S]*?(?=#{{2,3}}\s*\d|\Z)', text)
    return m.group(0) if m else ''


def extract_body(result_text):
    """검열된 본문(섹션 1)을 추출한다. 헤딩 형식에 의존하지 않고, '탐지 상세 표(섹션 2)'가
    시작되기 직전까지를 본문으로 간주한다 — 모델이 헤딩 번호/형식을 정확히 지키지 않아도
    <R번호> 태그가 든 본문이 비지 않도록 하기 위함이다."""
    cut = len(result_text)
    # 섹션 2 헤딩 또는 탐지 표(| 번호 | ...)가 나오는 가장 빠른 위치에서 자른다.
    for pat in (r'#{1,6}\s*2[.\s]', r'^\s*\|\s*번호\s*\|'):
        m = re.search(pat, result_text, re.MULTILINE)
        if m:
            cut = min(cut, m.start())
    body = result_text[:cut]
    lines = body.splitlines()

    def is_heading_noise(line):
        s = line.strip().strip("*").strip()
        return (not s
                or line.lstrip().startswith("#")
                or set(line.strip()) <= {"-", "=", "*"}
                or s.startswith("RISK_JSON")
                or ("검열된" in s and "문서" in s and "<R" not in s)
                or ("탐지된" in s and "상세" in s and "<R" not in s))

    # 앞쪽의 섹션 헤딩/구분선 줄(### 1. ..., ## 검열된 문서, ---, RISK_JSON 등)을 제거한다.
    while lines and is_heading_noise(lines[0]):
        lines.pop(0)
    # 표 직전에 남은 섹션 2 헤딩성 줄도 제거한다.
    while lines and is_heading_noise(lines[-1]):
        lines.pop()
    return "\n".join(lines).strip()


def safe_force_mask(body, grade):
    """<R번호> 태그 구간은 보존한 채, 태그 밖에 평문으로 남은 정규식 매칭 잔여 노출을 강제 마스킹한다."""
    if grade == "3급":
        return body
    placeholders = []

    def stash(m):
        placeholders.append(m.group(0))
        return f"\x00{len(placeholders) - 1}\x00"

    stashed = TAG_RE.sub(stash, body)
    masked = force_mask_residual(stashed)

    def restore(m):
        return placeholders[int(m.group(1))]

    return re.sub(r'\x00(\d+)\x00', restore, masked)


def apply_grade_rewrite(body, items):
    """각 항목 자신의 등급(섹션 2 표에서 파싱한 grade)에 따라 본문 태그의 치환 표현을 재작성한다.
    (문서 전체 등급이 아니라 항목 각각의 등급으로 결정한다. items 딕셔너리도 함께 갱신된다.)"""

    def rewrite(m):
        id_str, inner = m.group(1), m.group(2)
        item = items.get(id_str)
        if not item:
            return m.group(0)
        action = action_for_grade(item["grade"])
        if action == "publish":  # 3급: 원문 그대로 노출
            new = item["orig"]
        elif action in ("mask", "block"):  # 특급/1급: 완전 마스킹 (항목 단위에는 "차단"이 없으므로 마스킹 처리)
            new = MASK_TOKEN.get(item["type"], "[마스킹]")
        else:  # substitute (2급): 모델이 제안한 의미유지 치환 표현 그대로 사용
            new = inner
        item["replaced"] = new
        return f"<R{id_str}>{new}</R{id_str}>"

    return TAG_RE.sub(rewrite, body)


def process_file(upload_path, filename):
    """단일 파일에 대해 탐지 → 위험성평가 → 등급별 처리까지 전체 파이프라인을 수행하고
    결과를 results/ 에 저장한 뒤 요약 dict를 반환한다."""
    raw_text = extract_text(upload_path, filename)
    result_text = run_detection(upload_path, filename, raw_text)
    items = parse_items(result_text)
    risk = parse_risk(result_text)
    grade = risk["grade"]

    body = extract_body(result_text)
    body = safe_force_mask(body, grade)

    blocked = action_for_grade(grade) == "block"
    if blocked:
        display_body = ""
        items = {}
        clean_text = (
            f"[차단됨] 본 문서는 위험성 평가 결과 '{risk['grade_label']}' 등급으로 분류되어 "
            f"공개·다운로드가 금지됩니다. (민감성 점수: {risk['score']})"
        )
    else:
        display_body = apply_grade_rewrite(body, items)
        clean_text = clean_markers(display_body)

    base = os.path.basename(filename)
    txt_path = os.path.join("results", base + "_redacted.txt")
    json_path = os.path.join("results", base + ".json")

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(clean_text)

    record = {
        "filename": base,
        "body": display_body,
        "items": items,
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
    return render_template("input.html", deploy_time=get_deploy_time())


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

    resp = app.make_response(render_template(
        "output.html",
        filename=record["filename"],
        body=record["body"],
        items=record["items"],
        risk=record["risk"],
        blocked=record["blocked"],
    ))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp


@app.route("/apply_review/<filename>", methods=["POST"])
def apply_review(filename):
    """검토자가 항목별 치환 표현을 번호(id) 기준으로 직접 수정한 결과를 저장한다.
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

    body = record["body"]
    items = record["items"]
    for edit in edits:
        id_str = str(edit.get("id", ""))
        replacement = edit.get("replacement", "")
        if id_str not in items:
            continue
        items[id_str]["replaced"] = replacement
        body = re.sub(
            rf'<R{id_str}>.*?</R{id_str}>',
            lambda m, r=replacement: f"<R{id_str}>{r}</R{id_str}>",
            body,
            flags=re.DOTALL,
        )

    clean_text = clean_markers(body)
    record["body"] = body
    record["items"] = items
    record["clean_text"] = clean_text

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(record, f, ensure_ascii=False, indent=2)
    with open(os.path.join("results", record["txt_name"]), "w", encoding="utf-8") as f:
        f.write(clean_text)

    return jsonify({"ok": True})


@app.route("/download/<filename>")
def download(filename):
    resp = send_file(
        os.path.join("results", filename),
        as_attachment=True
    )
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp


if __name__ == "__main__":
    app.run(debug=True)
