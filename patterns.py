"""정규식 기반 1차 탐지 DB. LLM 탐지를 보완하는 결정론적(deterministic) 패턴 매칭."""
import re

# (유형코드, 패턴명, 정규식)
REGEX_PATTERNS = [
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

# 유형별 마스킹 토큰 (1급 = 완전 마스킹용)
MASK_TOKEN = {
    "person": "[개인정보 마스킹]",
    "org": "[기관정보 마스킹]",
    "ip": "[기밀정보 마스킹]",
    "auth": "[인증정보 마스킹]",
    "secret": "[금융정보 마스킹]",
}


def scan_regex(text):
    """텍스트에서 정규식 패턴과 일치하는 항목을 모두 찾아 반환한다."""
    hits = []
    seen = set()
    for type_, label, pattern in REGEX_PATTERNS:
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
    for type_, _label, pattern in REGEX_PATTERNS:
        token = MASK_TOKEN.get(type_, "[마스킹]")
        text = pattern.sub(token, text)
    return text
