from flask import Flask, render_template, request, send_file, jsonify, abort
from openai import OpenAI
import os
import re
import json
import uuid
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

from patterns import scan_regex, force_mask_residual, MASK_TOKEN, BUILTIN_PATTERNS
from risk import compute_score, grade_for_score, action_for_grade, GRADE_LABEL
from policy import load_policy, save_policy, VALID_TYPES
from export import build_exports

RESULTS_DIR = "results"

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
(번호는 1부터 시작하는 정수이며, 동일 엔티티는 문서 전체에서 동일 번호를 사용한다.
단, "동일 엔티티"란 원문 문자열이 글자 그대로 완전히 동일한 경우만을 뜻한다.
비슷하거나 같은 범주에 속하지만 원문이 서로 다른 두 대상(예: 서로 다른 두 사람의 코드네임,
서로 다른 두 프로젝트명)은 절대 같은 번호로 묶지 않고 각각 새 번호를 부여한다 —
번호를 잘못 공유하면 같은 치환 표현이 문서 여러 곳에 그대로 나타나, 원문에는 없던
"중복 표현"이 검열 결과에만 생겨나는 오류가 발생한다)

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
- 단, 원문 문자열이 다르면 절대 번호를 공유하지 않는다. 헷갈리면 새 번호를 발급한다 —
  번호 재사용은 검열 결과에 똑같은 치환 표현이 중복 등장하게 만들므로, 원문이 다른데도
  같은 번호/같은 치환 표현을 쓰는 것이 가장 흔한 실수다.
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

def build_policy_hint():
    """현재 정책의 등급 임계값과 민감 키워드 사전을 LLM 프롬프트에 주입할 안내문으로 만든다.
    관리자가 정책 설정 화면에서 바꾼 기준이 탐지·등급 판단에 즉시 반영되도록 한다."""
    pol = load_policy()
    t = pol["thresholds"]
    parts = [
        "\n\n## 적용 정책 (관리자 설정 — 반드시 우선 반영)",
        f"- 등급 임계값: 특급 {t['특급']}점 이상, 1급 {t['1급']}점 이상, "
        f"2급 {t['2급']}점 이상, 그 미만은 3급.",
    ]
    if pol["dictionary"]:
        terms = ", ".join(f"{d['term']}({d['type']})" for d in pol["dictionary"])
        parts.append(
            f"- 다음 키워드는 문맥과 무관하게 반드시 민감정보로 탐지·태그한다: {terms}"
        )
    return "\n".join(parts) + "\n"


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
    policy_hint = build_policy_hint()
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
                        {"type": "input_text", "text": PROMPT + policy_hint + hint + "\n\n## 검열 대상 문서\n" + raw_text},
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
                    {"type": "input_text", "text": PROMPT + policy_hint},
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


def disambiguate_duplicate_labels(body, items):
    """치환 표현이 동일하지만 원문이 서로 다른 항목들(모델이 같은 표현을 잘못 재사용한 경우)에
    'A'/'B'/'C' 접미사를 붙여 구분한다. (예: "black monkey" 중복 노출 방지)"""
    groups = {}
    for id_str, item in items.items():
        groups.setdefault(item["replaced"], []).append(id_str)

    for label, ids in groups.items():
        if len(ids) < 2:
            continue
        origs = {items[i]["orig"] for i in ids}
        if len(origs) < 2:
            continue  # 같은 개체의 반복 등장이므로 그대로 둔다
        for idx, id_str in enumerate(sorted(ids, key=int)):
            new_label = f"{label} {chr(ord('A') + idx)}"
            items[id_str]["replaced"] = new_label
            tag_re = re.compile(rf'(<R{id_str}>)(.*?)(</R{id_str}>)', re.DOTALL)
            body = tag_re.sub(lambda m, nl=new_label: f"{m.group(1)}{nl}{m.group(3)}", body)
    return body


def write_outputs(record):
    """record 의 clean_text 를 기반으로 txt/pdf/docx 검열본을 생성하고, record 에
    내보내기 가능한 포맷 목록(formats)을 기록한다. (차단 문서는 txt 만 생성)"""
    doc_id = record["doc_id"]
    title = record["filename"]
    clean_text = record["clean_text"]
    formats = ["txt"]
    txt_path = os.path.join(RESULTS_DIR, doc_id + "_redacted.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(clean_text)
    if not record["blocked"]:
        exports = build_exports(RESULTS_DIR, doc_id, title, clean_text, record["risk"])
        if exports.get("pdf"):
            formats.append("pdf")
        if exports.get("docx"):
            formats.append("docx")
    record["formats"] = formats


def save_record(record):
    with open(os.path.join(RESULTS_DIR, record["doc_id"] + ".json"), "w", encoding="utf-8") as f:
        json.dump(record, f, ensure_ascii=False, indent=2)


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
        display_body = disambiguate_duplicate_labels(display_body, items)
        clean_text = clean_markers(display_body)

    # 같은 이름의 파일을 반복 업로드해도 이력이 덮어쓰이지 않도록 고유 doc_id 부여
    doc_id = uuid.uuid4().hex[:12]
    record = {
        "doc_id": doc_id,
        "filename": os.path.basename(filename),
        "created_at": datetime.datetime.now(KST).strftime("%Y.%m.%d %H:%M"),
        "created_ts": datetime.datetime.now(KST).timestamp(),
        "body": display_body,
        "items": items,
        "clean_text": clean_text,
        "risk": risk,
        "blocked": blocked,
    }
    write_outputs(record)
    save_record(record)
    return record


def load_record(doc_id):
    """doc_id 에 해당하는 검열 결과 record 를 로드한다. 없으면 None."""
    json_path = os.path.join(RESULTS_DIR, os.path.basename(doc_id) + ".json")
    if not os.path.exists(json_path):
        return None
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)


def list_records():
    """results/ 의 모든 검열 결과를 최신순으로 반환한다 (이력/대시보드용)."""
    records = []
    for name in os.listdir(RESULTS_DIR):
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(RESULTS_DIR, name), "r", encoding="utf-8") as f:
                records.append(json.load(f))
        except (OSError, json.JSONDecodeError):
            continue
    records.sort(key=lambda r: r.get("created_ts", 0), reverse=True)
    return records


def _no_store(resp):
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp


@app.route("/")
def home():
    return _no_store(app.make_response(
        render_template("input.html", deploy_time=get_deploy_time(), nav="home")
    ))


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

    # 문서별 검열 목록 화면 (단일 파일도 1개짜리 목록으로 표시)
    return render_template("list.html", results=results, nav="home")


@app.route("/view/<doc_id>")
def view_result(doc_id):
    record = load_record(doc_id)
    if record is None:
        abort(404)
    return _no_store(app.make_response(render_template(
        "output.html",
        doc_id=record["doc_id"],
        filename=record["filename"],
        body=record["body"],
        items=record["items"],
        risk=record["risk"],
        blocked=record["blocked"],
        formats=record.get("formats", ["txt"]),
        nav="history",
    )))


@app.route("/apply_review/<doc_id>", methods=["POST"])
def apply_review(doc_id):
    """검토자가 수정한 검열 결과(본문 + 항목 전체 상태)를 저장하고 검열본을 재생성한다.
    항목별 치환 표현 수정·검열 방식 변경·수동 추가 항목이 모두 body/items 에 반영된 채로 들어온다."""
    record = load_record(doc_id)
    if record is None:
        abort(404)
    if record["blocked"]:
        return jsonify({"ok": False, "error": "blocked 문서는 검토를 적용할 수 없습니다."}), 400

    payload = request.get_json(silent=True) or {}
    body = payload.get("body")
    items = payload.get("items")
    if not isinstance(body, str) or not isinstance(items, dict):
        return jsonify({"ok": False, "error": "잘못된 요청 형식입니다."}), 400

    # 본문 태그의 표시값을 항목의 최종 치환 표현으로 정규화한 뒤 평문 검열본을 만든다.
    def normalize(m):
        id_str = m.group(1)
        item = items.get(id_str)
        return f"<R{id_str}>{item['replaced']}</R{id_str}>" if item else m.group(0)

    body = TAG_RE.sub(normalize, body)
    clean_text = clean_markers(body)

    record["body"] = body
    record["items"] = items
    record["clean_text"] = clean_text
    write_outputs(record)
    save_record(record)
    return jsonify({"ok": True, "formats": record["formats"]})


@app.route("/download/<doc_id>/<fmt>")
def download(doc_id, fmt):
    if fmt not in ("txt", "pdf", "docx"):
        abort(404)
    record = load_record(doc_id)
    if record is None:
        abort(404)
    path = os.path.join(RESULTS_DIR, record["doc_id"] + "_redacted." + fmt)
    if not os.path.exists(path):
        abort(404)
    download_name = os.path.splitext(record["filename"])[0] + "_검열본." + fmt
    return _no_store(send_file(path, as_attachment=True, download_name=download_name))


@app.route("/dashboard")
def dashboard():
    records = list_records()
    grade_counts = {"특급": 0, "1급": 0, "2급": 0, "3급": 0}
    score_sum = 0.0
    blocked = 0
    for r in records:
        g = r.get("risk", {}).get("grade")
        if g in grade_counts:
            grade_counts[g] += 1
        score_sum += r.get("risk", {}).get("score", 0)
        if r.get("blocked"):
            blocked += 1
    stats = {
        "total": len(records),
        "avg_score": round(score_sum / len(records)) if records else 0,
        "blocked": blocked,
        "grade_counts": grade_counts,
    }
    return _no_store(app.make_response(
        render_template("dashboard.html", records=records, stats=stats, nav="history")
    ))


@app.route("/policy")
def policy_page():
    # 항상 적용되는 기본 내장 탐지 규칙 — 정규식 대신 이해하기 쉬운 한글 이름과 예시로 보여준다.
    builtin_names = {
        "email": "이메일", "phone_kr": "전화번호", "rrn_kr": "주민등록번호",
        "api_key_openai": "OpenAI API 키", "api_key_aws": "AWS 액세스 키",
        "api_key_github": "GitHub 토큰", "credential_kv": "비밀번호/토큰",
        "card_number": "카드번호", "account_number_kr": "계좌번호", "ipv4": "IP 주소",
    }
    builtin_examples = {
        "email": "hong@example.com", "phone_kr": "010-1234-5678", "rrn_kr": "900101-1234567",
        "api_key_openai": "sk-abcd1234efgh5678ijkl", "api_key_aws": "AKIA1234567890ABCDEF",
        "api_key_github": "ghp_AbCd1234EfGh5678IjKl90", "credential_kv": "password: p@ssw0rd!",
        "card_number": "1234-5678-9012-3456", "account_number_kr": "110-234-567890",
        "ipv4": "192.168.0.1",
    }
    builtin = [
        {"type": t, "name": builtin_names.get(l, l), "example": builtin_examples.get(l, "")}
        for (t, l, p) in BUILTIN_PATTERNS
    ]
    return _no_store(app.make_response(
        render_template("policy.html", policy=load_policy(), types=VALID_TYPES,
                        builtin=builtin, nav="policy")
    ))


@app.route("/policy", methods=["POST"])
def policy_save():
    data = request.get_json(silent=True) or {}
    saved = save_policy(data)
    return jsonify({"ok": True, "policy": saved})


if __name__ == "__main__":
    app.run(debug=True)
