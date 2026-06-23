"""ISO 27005 기반 위험성 평가 등급 체계.
기밀성(Confidentiality) / 무결성(Integrity) / 가용성(Availability) 점수를 가중 합산하여
0~100점의 민감성 점수를 산출하고, 점수에 따라 4단계 등급으로 분류한다.

가중치와 등급 임계값은 정책(policy.json)에서 런타임에 읽어오므로, 관리자가
'정책 설정' 화면에서 코드 수정 없이 조정할 수 있다."""
from policy import load_policy

# 등급별 처리 방침 (고정)
GRADE_ACTION = {
    "특급": "block",       # 자료 자체 공개 금지
    "1급": "mask",         # 완전 마스킹
    "2급": "substitute",   # 의미가 유지되는 표현으로 치환 (OpenAI 활용)
    "3급": "publish",      # 그대로 공개
}

GRADE_LABEL = {
    "특급": "1급비밀 (공개금지)",
    "1급": "1급 (마스킹)",
    "2급": "2급 (의미유지 치환)",
    "3급": "3급 (공개가능)",
}


def current_thresholds():
    """정책의 임계값을 (등급, 임계값) 내림차순 리스트로 반환한다 (3급=0 고정)."""
    t = load_policy()["thresholds"]
    return [
        ("특급", t["특급"]),
        ("1급", t["1급"]),
        ("2급", t["2급"]),
        ("3급", 0),
    ]


def compute_score(confidentiality, integrity, availability):
    w = load_policy()["weights"]
    score = (
        confidentiality * w["confidentiality"]
        + integrity * w["integrity"]
        + availability * w["availability"]
    )
    return round(max(0, min(100, score)), 1)


def grade_for_score(score):
    for grade, threshold in current_thresholds():
        if score >= threshold:
            return grade
    return "3급"


def action_for_grade(grade):
    return GRADE_ACTION.get(grade, "substitute")
