"""ISO 27005 기반 위험성 평가 등급 체계.
기밀성(Confidentiality) / 무결성(Integrity) / 가용성(Availability) 점수를 가중 합산하여
0~100점의 민감성 점수를 산출하고, 점수에 따라 4단계 등급으로 분류한다."""

# 가중치: DLP 맥락에서는 기밀성(노출 시 피해)이 가장 중요하므로 60%를 부여
CIA_WEIGHTS = {"confidentiality": 0.6, "integrity": 0.2, "availability": 0.2}

# 점수 임계값 (이상일 때 해당 등급) — 내림차순으로 평가
GRADE_THRESHOLDS = [
    ("특급", 90),
    ("1급", 70),
    ("2급", 40),
    ("3급", 0),
]

# 등급별 처리 방침
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


def compute_score(confidentiality, integrity, availability):
    score = (
        confidentiality * CIA_WEIGHTS["confidentiality"]
        + integrity * CIA_WEIGHTS["integrity"]
        + availability * CIA_WEIGHTS["availability"]
    )
    return round(max(0, min(100, score)), 1)


def grade_for_score(score):
    for grade, threshold in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "3급"


def action_for_grade(grade):
    return GRADE_ACTION.get(grade, "substitute")
