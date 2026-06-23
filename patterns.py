"""정규식 기반 1차 탐지 DB. LLM 탐지를 보완하는 결정론적(deterministic) 패턴 매칭.

기본 내장 패턴 외에, 정책(policy.json)에 등록된 관리자 커스텀 정규식·키워드 사전도
함께 적용한다 — '정책 설정' 화면에서 코드 수정 없이 탐지 규칙을 추가할 수 있다."""
import re

from policy import load_policy

# (유형코드, 패턴명, 정규식)
BUILTIN_PATTERNS = [
    ("person", "email", re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')),
    ("person", "phone_kr", re.compile(r'01[016789]-?\d{3,4}-?\d{4}')),
    ("person", "rrn_kr", re.compile(r'\b\d{6}-?[1-4]\d{6}\b')),
    ("auth", "api_key_openai", re.compile(r'sk-[A-Za-z0-9]{16,}')),
    ("auth", "api_key_aws", re.compile(r'AKIA[0-9A-Z]{16}')),
    ("auth", "api_key_github", re.compile(r'gh[pousr]_[A-Za-z0-9]{30,}')),
    ("auth", "credential_kv", re.compile(r'(?i)(?:password|passwd|secret|token)\s*[:=]\s*\S+')),
    ("secret", "card_number", re.compile(r'\b(?:\d{4}[- ]?){3}\d{4}\b')),
    ("secret", "account_number_kr", re.compile(r'\b\d{2,6}-\d{2,6}-\d{2,8}\b')),
    ("secret", "ipv4", re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')),
]

# 하위 호환: 기존 코드가 REGEX_PATTERNS 를 참조할 수 있으므로 별칭 유지
REGEX_PATTERNS = BUILTIN_PATTERNS

# 유형별 마스킹 토큰 (1급 = 완전 마스킹용)
MASK_TOKEN = {
    "person": "[개인정보 마스킹]",
    "org": "[기관정보 마스킹]",
    "ip": "[기밀정보 마스킹]",
    "auth": "[인증정보 마스킹]",
    "secret": "[금융정보 마스킹]",
}


def _effective_patterns():
    """내장 패턴 + 정책에 등록된 커스텀 정규식 + 키워드 사전(리터럴 매칭)을 합쳐
    (유형, 이름, 컴파일된 정규식) 리스트로 반환한다."""
    patterns = list(BUILTIN_PATTERNS)
    pol = load_policy()
    for p in pol.get("custom_patterns", []):
        try:
            patterns.append((p["type"], p.get("label", "custom"), re.compile(p["pattern"])))
        except (re.error, KeyError):
            continue
    for d in pol.get("dictionary", []):
        try:
            patterns.append((d["type"], "dictionary", re.compile(re.escape(d["term"]))))
        except (re.error, KeyError):
            continue
    return patterns


def scan_regex(text):
    """텍스트에서 정규식 패턴과 일치하는 항목을 모두 찾아 반환한다."""
    hits = []
    seen = set()
    for type_, label, pattern in _effective_patterns():
        for m in pattern.finditer(text):
            value = m.group(0)
            key = (type_, value)
            if key in seen:
                continue
            seen.add(key)
            hits.append({"type": type_, "label": label, "value": value})
    return hits


def force_mask_residual(text, allow_publish=False):
    """LLM이 마커로 감싸지 못해 평문으로 남은 정규식 패턴 매칭값을 강제로 마스킹한다.
    (예: '@'가 포함된 이메일이 마커 파싱에서 빠지는 경우의 안전망)"""
    if allow_publish:
        return text
    for type_, _label, pattern in _effective_patterns():
        token = MASK_TOKEN.get(type_, "[마스킹]")
        text = pattern.sub(token, text)
    return text
