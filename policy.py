"""정책(Policy) 관리 모듈.

위험성 점수 가중치·등급 임계값·커스텀 탐지 정규식·민감 키워드 사전을
코드 수정 없이 UI(정책 설정 화면)에서 변경할 수 있도록 policy.json 파일로
영속화한다. risk.py / patterns.py / app.py 가 런타임에 이 값을 읽어 동작한다.

파일이 없거나 일부 키가 비어 있으면 DEFAULT_POLICY 값으로 보완한다."""
import json
import os
import re

POLICY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policy.json")

VALID_TYPES = ("person", "org", "ip", "auth", "secret")

# 분야별 적용 법령 카탈로그 — 정책 설정 화면에서 토글로 적용 여부를 고른다.
# 관리자가 켠 법령은 build_policy_hint() 를 통해 LLM 검열 기준에 주입된다.
# id 는 policy.json 에 저장되는 안정적 키이므로 변경하지 않는다.
REGULATION_SECTORS = [
    {"id": "defense", "name": "방위산업", "laws": [
        {"id": "defense_tech", "name": "방위산업기술 보호법"},
        {"id": "defense_business", "name": "방위사업법"},
        {"id": "military_secret", "name": "군사기밀 보호법"},
        {"id": "foreign_trade", "name": "대외무역법 (전략물자 수출입 고시)"},
    ]},
    {"id": "military", "name": "군", "laws": [
        {"id": "security_regulation", "name": "보안업무규정 (및 시행규칙)"},
        {"id": "military_secret_decree", "name": "군사기밀 보호법 시행령"},
        {"id": "defense_informatization", "name": "국방정보화 기반조성 및 정보자원관리에 관한 법률"},
        {"id": "military_base", "name": "군사기지 및 군사시설 보호법"},
    ]},
    {"id": "finance", "name": "금융", "laws": [
        {"id": "credit_info", "name": "신용정보의 이용 및 보호에 관한 법률"},
        {"id": "e_finance", "name": "전자금융거래법 (및 전자금융감독규정)"},
        {"id": "finance_outsourcing", "name": "금융회사의 정보처리 업무 위탁에 관한 규정"},
        {"id": "finance_privacy_guide", "name": "금융분야 개인정보보호 가이드라인"},
    ]},
    {"id": "medical", "name": "의료", "laws": [
        {"id": "medical_law", "name": "의료법"},
        {"id": "privacy_sensitive", "name": "개인정보보호법 (민감정보 규정)"},
        {"id": "bioethics", "name": "생명윤리 및 안전에 관한 법률"},
        {"id": "health_data_guide", "name": "보건의료데이터 활용 가이드라인"},
    ]},
    {"id": "public", "name": "공공기관", "laws": [
        {"id": "public_records", "name": "공공기록물 관리에 관한 법률"},
        {"id": "info_disclosure", "name": "공공기관의 정보공개에 관한 법률"},
        {"id": "e_government", "name": "전자정부법"},
        {"id": "public_security_guideline", "name": "국가·공공기관 정보보안 기본지침"},
    ]},
    {"id": "common", "name": "공통", "laws": [
        {"id": "privacy_law", "name": "개인정보보호법"},
        {"id": "ai_framework", "name": "인공지능 발전과 신뢰 기반 조성 등에 관한 기본법 (AI 기본법)"},
    ]},
]

# law id → 표시명 (LLM 안내문·검증에 사용)
LAW_NAMES = {law["id"]: law["name"] for s in REGULATION_SECTORS for law in s["laws"]}
# 공통 분야 법령은 모든 검열에 기본 적용, 그 외 분야는 기본 비활성.
DEFAULT_REGULATIONS = {
    law["id"]: (s["id"] == "common")
    for s in REGULATION_SECTORS for law in s["laws"]
}

# 기본 정책 — policy.json 이 없을 때 사용되며, 일부 키 누락 시에도 이 값으로 채운다.
DEFAULT_POLICY = {
    # 위험성 점수 가중치 (합이 1이 되도록 저장 시 정규화)
    "weights": {"confidentiality": 0.6, "integrity": 0.2, "availability": 0.2},
    # 등급 임계값 (점수가 해당 값 이상이면 그 등급). 3급은 0으로 고정(암묵).
    "thresholds": {"특급": 90, "1급": 70, "2급": 40},
    # 관리자가 추가한 결정론적 탐지 정규식 [{type,label,pattern}]
    "custom_patterns": [],
    # 항상 민감정보로 취급할 키워드 사전 [{type,term}]
    "dictionary": [],
    # 분야별 적용 법령 {law_id: bool}
    "regulations": dict(DEFAULT_REGULATIONS),
}


def _merge(base, override):
    """override 의 유효한 값으로 base 를 보완한 새 dict 를 반환한다."""
    out = json.loads(json.dumps(base))
    if not isinstance(override, dict):
        return out
    if isinstance(override.get("weights"), dict):
        for k in ("confidentiality", "integrity", "availability"):
            try:
                out["weights"][k] = float(override["weights"][k])
            except (KeyError, TypeError, ValueError):
                pass
    if isinstance(override.get("thresholds"), dict):
        for k in ("특급", "1급", "2급"):
            try:
                out["thresholds"][k] = int(override["thresholds"][k])
            except (KeyError, TypeError, ValueError):
                pass
    if isinstance(override.get("custom_patterns"), list):
        cleaned = []
        for p in override["custom_patterns"]:
            if not isinstance(p, dict):
                continue
            type_ = p.get("type")
            pattern = (p.get("pattern") or "").strip()
            if type_ not in VALID_TYPES or not pattern:
                continue
            try:
                re.compile(pattern)
            except re.error:
                continue  # 잘못된 정규식은 무시
            cleaned.append({
                "type": type_,
                "label": (p.get("label") or "custom").strip(),
                "pattern": pattern,
            })
        out["custom_patterns"] = cleaned
    if isinstance(override.get("dictionary"), list):
        cleaned = []
        for d in override["dictionary"]:
            if not isinstance(d, dict):
                continue
            type_ = d.get("type")
            term = (d.get("term") or "").strip()
            if type_ not in VALID_TYPES or not term:
                continue
            cleaned.append({"type": type_, "term": term})
        out["dictionary"] = cleaned
    if isinstance(override.get("regulations"), dict):
        for law_id in LAW_NAMES:
            if law_id in override["regulations"]:
                out["regulations"][law_id] = bool(override["regulations"][law_id])
    return out


def load_policy():
    """policy.json 을 읽어 기본값과 병합한 정책 dict 를 반환한다."""
    try:
        with open(POLICY_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        data = {}
    return _merge(DEFAULT_POLICY, data)


def save_policy(data):
    """입력 정책을 검증·정규화한 뒤 policy.json 에 저장하고, 저장된 정책을 반환한다."""
    merged = _merge(DEFAULT_POLICY, data)
    # 가중치 정규화 (합이 0이면 기본값으로 복구)
    w = merged["weights"]
    total = w["confidentiality"] + w["integrity"] + w["availability"]
    if total <= 0:
        merged["weights"] = dict(DEFAULT_POLICY["weights"])
    else:
        for k in w:
            w[k] = round(w[k] / total, 4)
    with open(POLICY_PATH, "w", encoding="utf-8") as f:
        json.dump(merged, f, ensure_ascii=False, indent=2)
    return merged
