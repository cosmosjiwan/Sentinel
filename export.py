"""검열본 내보내기 — 검열 결과를 PDF/DOCX 문서로 변환한다.

- 원본이 .docx 이면 원본 파일의 XML(단락·run·표·머리글/바닥글)을 직접 편집해
  글꼴·굵기·색상·문단 스타일·표 구조 등 서식과 레이아웃을 유지한 채 민감정보만
  치환/마스킹한다. (build_docx_from_original)
- 그 외 포맷(.pdf/.txt 등)이나 서식 보존 실패 시에는 검열된 평문 본문을 단락 구조를
  유지한 '배포 가능한 검열본 문서'로 재구성한다. (build_pdf / build_docx)

한글은 reportlab 내장 CID 폰트(HYSMyeongJo-Medium)로 렌더하므로 별도 폰트 파일이
필요 없다."""
import os

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_LEFT
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable
from reportlab.lib import colors

from docx import Document
from docx.shared import Pt, RGBColor

from patterns import residual_mask_patterns

_FONT = "HYSMyeongJo-Medium"
_FONT_REGISTERED = False


def _ensure_font():
    global _FONT_REGISTERED
    if not _FONT_REGISTERED:
        pdfmetrics.registerFont(UnicodeCIDFont(_FONT))
        _FONT_REGISTERED = True


def _xml_escape(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def build_pdf(path, title, clean_text, risk):
    """검열본 PDF 를 생성한다 (제목 + 위험성 요약 헤더 + 본문 단락)."""
    _ensure_font()
    doc = SimpleDocTemplate(
        path, pagesize=A4,
        leftMargin=22 * mm, rightMargin=22 * mm,
        topMargin=20 * mm, bottomMargin=18 * mm,
        title=title, author="Sentinel DLP",
    )
    h_title = ParagraphStyle("title", fontName=_FONT, fontSize=16, leading=22,
                             spaceAfter=4, textColor=colors.HexColor("#16181d"))
    h_meta = ParagraphStyle("meta", fontName=_FONT, fontSize=9.5, leading=15,
                            textColor=colors.HexColor("#6b7280"))
    body = ParagraphStyle("body", fontName=_FONT, fontSize=11, leading=19,
                          alignment=TA_LEFT, spaceAfter=8,
                          textColor=colors.HexColor("#16181d"))

    flow = [
        Paragraph(_xml_escape(title), h_title),
        Paragraph(
            f"Sentinel DLP 검열본 &nbsp;·&nbsp; 민감성 점수 "
            f"{int(round(risk.get('score', 0)))}/100 &nbsp;·&nbsp; "
            f"{_xml_escape(risk.get('grade_label', ''))}",
            h_meta,
        ),
        Spacer(1, 6),
        HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#e2e5ee")),
        Spacer(1, 12),
    ]
    for line in clean_text.split("\n"):
        line = line.strip()
        if line:
            flow.append(Paragraph(_xml_escape(line), body))
        else:
            flow.append(Spacer(1, 6))
    doc.build(flow)
    return path


def build_docx(path, title, clean_text, risk):
    """검열본 DOCX 를 생성한다."""
    d = Document()
    d.add_heading(title, level=0)
    meta = d.add_paragraph()
    run = meta.add_run(
        f"Sentinel DLP 검열본 · 민감성 점수 "
        f"{int(round(risk.get('score', 0)))}/100 · {risk.get('grade_label', '')}"
    )
    run.font.size = Pt(9)
    run.font.color.rgb = RGBColor(0x6B, 0x72, 0x80)
    for line in clean_text.split("\n"):
        line = line.strip()
        d.add_paragraph(line if line else "")
    d.save(path)
    return path


def _iter_all_paragraphs(container):
    """문서 본문·표(중첩 포함)의 모든 단락을 순회한다."""
    for p in container.paragraphs:
        yield p
    for table in container.tables:
        for row in table.rows:
            for cell in row.cells:
                yield from _iter_all_paragraphs(cell)


def _iter_doc_paragraphs(doc):
    """본문 + 각 섹션의 머리글/바닥글까지 포함해 모든 단락을 순회한다."""
    yield from _iter_all_paragraphs(doc)
    for section in doc.sections:
        for attr in ("header", "footer", "first_page_header", "first_page_footer",
                     "even_page_header", "even_page_footer"):
            try:
                hf = getattr(section, attr)
            except Exception:
                continue
            if hf is not None:
                yield from _iter_all_paragraphs(hf)


def _replace_in_paragraph(paragraph, pairs):
    """run(서식 조각) 경계를 보존하며 단락 텍스트에서 orig→replaced 치환을 수행한다.
    치환 텍스트는 매칭이 시작된 run 의 서식을 그대로 물려받고, 매칭에 걸쳐 사라지는
    나머지 run 의 해당 구간만 비워 원본 서식(굵게·색상·글꼴 등)을 최대한 유지한다."""
    runs = paragraph.runs
    if not runs:
        return
    full = "".join(r.text for r in runs)
    if not full:
        return

    # 모든 pair 의 매칭 구간을 수집한 뒤, 겹치지 않게 (앞선 위치 우선, 동률이면 더 긴 것) 선택
    spans = []
    for old, new in pairs:
        if not old:
            continue
        start = full.find(old)
        while start != -1:
            spans.append((start, start + len(old), new))
            start = full.find(old, start + len(old))
    if not spans:
        return
    spans.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    chosen = []
    last_end = -1
    for s, e, new in spans:
        if s >= last_end:
            chosen.append((s, e, new))
            last_end = e
    if not chosen:
        return

    # 문자 위치 → 소속 run 인덱스 매핑
    owner = []
    for ri, r in enumerate(runs):
        owner.extend([ri] * len(r.text))

    new_run_text = ["" for _ in runs]
    i, n = 0, len(full)
    span_idx = 0
    cur = chosen[0]
    while i < n:
        if cur and i == cur[0]:
            s, e, new = cur
            new_run_text[owner[s]] += new  # 치환 텍스트는 매칭 시작 run 서식 상속
            i = e
            span_idx += 1
            cur = chosen[span_idx] if span_idx < len(chosen) else None
        else:
            new_run_text[owner[i]] += full[i]
            i += 1
    for ri, r in enumerate(runs):
        if r.text != new_run_text[ri]:
            r.text = new_run_text[ri]


def _mask_runs_residual(runs, patterns_tokens):
    """정규식 안전망 — 항목 치환에서 누락된 구조적 비밀정보(이메일·주민번호·카드·키 등)를
    run 단위로 강제 마스킹한다."""
    for r in runs:
        t = r.text
        if not t:
            continue
        nt = t
        for pattern, token in patterns_tokens:
            nt = pattern.sub(token, nt)
        if nt != t:
            r.text = nt


def build_docx_from_original(src_path, out_path, items, grade, risk=None):
    """원본 DOCX 의 서식·레이아웃을 유지한 채, 탐지된 민감정보만 치환/마스킹한 검열본을
    생성한다. 원본 XML(단락·run·표·머리글/바닥글)을 직접 편집하므로 글꼴·굵기·색상·
    문단 스타일·표 구조가 보존된다."""
    doc = Document(src_path)
    pairs = [
        (it.get("orig"), it.get("replaced"))
        for it in items.values()
        if it.get("orig") and it.get("replaced") is not None and it["orig"] != it["replaced"]
    ]
    # 더 긴 원문을 먼저 치환해 짧은 문자열이 긴 민감정보 내부를 잘못 매칭하지 않도록 한다.
    pairs.sort(key=lambda p: len(p[0]), reverse=True)
    # 3급(공개) 문서는 잔여 정규식 마스킹을 적용하지 않는다 (평문 출력 정책과 일치).
    residual = None if grade == "3급" else residual_mask_patterns()

    for p in _iter_doc_paragraphs(doc):
        if pairs:
            _replace_in_paragraph(p, pairs)
        if residual:
            _mask_runs_residual(p.runs, residual)

    if risk is not None:
        try:
            doc.core_properties.title = os.path.basename(out_path)
            doc.core_properties.comments = (
                f"Sentinel DLP 검열본 · 민감성 점수 "
                f"{int(round(risk.get('score', 0)))}/100 · {risk.get('grade_label', '')}"
            )
        except Exception:
            pass

    doc.save(out_path)
    return out_path


def build_exports(results_dir, doc_id, title, clean_text, risk,
                  original_path=None, items=None, grade=None):
    """txt 는 호출부에서 이미 저장되므로, pdf/docx 만 생성하고 경로를 반환한다.

    원본이 .docx 이면 서식을 보존한 검열본을 우선 생성하고, 실패 시(또는 다른 포맷이면)
    평문 기반 검열본으로 대체한다."""
    pdf_path = os.path.join(results_dir, doc_id + "_redacted.pdf")
    docx_path = os.path.join(results_dir, doc_id + "_redacted.docx")
    try:
        build_pdf(pdf_path, title, clean_text, risk)
    except Exception:
        pdf_path = None

    docx_ok = False
    if (original_path and original_path.lower().endswith(".docx")
            and os.path.exists(original_path)):
        try:
            build_docx_from_original(original_path, docx_path, items or {}, grade, risk)
            docx_ok = True
        except Exception:
            docx_ok = False
    if not docx_ok:
        try:
            build_docx(docx_path, title, clean_text, risk)
        except Exception:
            docx_path = None
    return {"pdf": pdf_path, "docx": docx_path}
