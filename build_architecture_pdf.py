# -*- coding: utf-8 -*-
"""
build_architecture_pdf.py
Generates a comprehensive, deep technical architecture and key features PDF
for AI-NIDS (AI-Powered Network Intrusion Detection System).
"""

import os
import sys
import shutil
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable, Preformatted
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY

# Target Output Paths
OUTPUT_DIR_DOCS = os.path.join(os.path.dirname(__file__), 'docs')
os.makedirs(OUTPUT_DIR_DOCS, exist_ok=True)
PDF_PATH_DOCS = os.path.join(OUTPUT_DIR_DOCS, 'AI_NIDS_Deep_Dive_Architecture_Guide.pdf')
PDF_PATH_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'AI_NIDS_Deep_Dive_Architecture_Guide.pdf'))

# Professional Color Palette
NAVY_PRIMARY = colors.HexColor('#0B132B')     # Deep Midnight Navy
NAVY_SECONDARY = colors.HexColor('#1C2541')   # Dark Slate Blue
TEAL_ACCENT = colors.HexColor('#008080')      # Cyber Teal
CYAN_ACCENT = colors.HexColor('#0284C7')      # Electric Cyan
TEXT_DARK = colors.HexColor('#1F2937')        # High Contrast Charcoal
TEXT_MUTED = colors.HexColor('#4B5563')       # Neutral Gray
BG_LIGHT = colors.HexColor('#F8FAFC')         # Card / Row background
BG_CALLOUT = colors.HexColor('#F0F9FF')       # Callout background
BORDER_LIGHT = colors.HexColor('#CBD5E1')     # Subtle border
BORDER_ACCENT = colors.HexColor('#0284C7')    # Active border
COLOR_ALERT = colors.HexColor('#DC2626')       # Red
COLOR_SUCCESS = colors.HexColor('#16A34A')     # Green


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas for dynamic total page count, running headers, and running footers.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        # Cover / First page running headers are suppressed
        if self._pageNumber == 1:
            self.saveState()
            self.setStrokeColor(BORDER_LIGHT)
            self.setLineWidth(0.6)
            self.line(40, 40, 572, 40)
            self.setFont('Helvetica', 8)
            self.setFillColor(TEXT_MUTED)
            self.drawString(40, 28, 'AI-NIDS Production Architecture Reference Guide')
            page_str = f"Page {self._pageNumber} of {page_count}"
            self.setFont('Helvetica-Bold', 8)
            self.setFillColor(CYAN_ACCENT)
            self.drawRightString(572, 28, page_str)
            self.restoreState()
            return

        self.saveState()

        # Running Header
        self.setFont('Helvetica-Bold', 8)
        self.setFillColor(TEAL_ACCENT)
        self.drawString(40, 755, 'AI-NIDS: AI-POWERED NETWORK INTRUSION DETECTION SYSTEM')
        self.setFont('Helvetica', 8)
        self.setFillColor(TEXT_MUTED)
        self.drawRightString(572, 755, 'SYSTEM ARCHITECTURE & KEY FEATURES DEEP DIVE')

        # Header Rule
        self.setStrokeColor(BORDER_LIGHT)
        self.setLineWidth(0.6)
        self.line(40, 748, 572, 748)

        # Footer Rule
        self.line(40, 40, 572, 40)

        # Running Footer
        self.setFont('Helvetica', 8)
        self.setFillColor(TEXT_MUTED)
        self.drawString(40, 28, 'Production Security Architecture & ML Engineering Reference')
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.setFont('Helvetica-Bold', 8)
        self.setFillColor(CYAN_ACCENT)
        self.drawRightString(572, 28, page_str)

        self.restoreState()


def create_callout(text, title="KEY ARCHITECTURAL INSIGHT", bg_color=BG_CALLOUT, border_color=BORDER_ACCENT, width=532):
    title_p = Paragraph(f"<b>{title}</b>", ParagraphStyle(
        'CalloutTitle', fontName='Helvetica-Bold', fontSize=8.5, leading=11, textColor=border_color
    ))
    body_p = Paragraph(text, ParagraphStyle(
        'CalloutBody', fontName='Helvetica', fontSize=8, leading=11.5, textColor=TEXT_DARK
    ))
    t = Table([[title_p], [body_p]], colWidths=[width - 16])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), bg_color),
        ('BOX', (0,0), (-1,-1), 1, border_color),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    return t


def generate_pdf():
    doc = SimpleDocTemplate(
        PDF_PATH_DOCS,
        pagesize=letter,
        leftMargin=38,
        rightMargin=38,
        topMargin=38,
        bottomMargin=38
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=19,
        leading=23,
        textColor=NAVY_PRIMARY,
        alignment=TA_CENTER
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=13.5,
        textColor=TEAL_ACCENT,
        alignment=TA_CENTER
    )
    badge_style = ParagraphStyle(
        'DocBadge',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=10.5,
        textColor=colors.white,
        alignment=TA_CENTER
    )
    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=15,
        textColor=NAVY_PRIMARY,
        spaceBefore=8,
        spaceAfter=3,
        keepWithNext=True
    )
    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9.5,
        leading=13,
        textColor=NAVY_SECONDARY,
        spaceBefore=7,
        spaceAfter=2,
        keepWithNext=True
    )
    h3_style = ParagraphStyle(
        'Heading3_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11.5,
        textColor=TEAL_ACCENT,
        spaceBefore=5,
        spaceAfter=2,
        keepWithNext=True
    )
    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.8,
        leading=11.2,
        textColor=TEXT_DARK,
        alignment=TA_JUSTIFY,
        spaceAfter=3
    )
    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.8,
        leading=11.2,
        textColor=TEXT_DARK,
        leftIndent=12,
        firstLineIndent=-8,
        spaceAfter=2.5
    )
    code_style = ParagraphStyle(
        'CodeBlock',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=6.5,
        leading=7.8,
        textColor=NAVY_PRIMARY
    )
    table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7,
        leading=9.5,
        textColor=TEXT_DARK
    )
    table_cell_bold = ParagraphStyle(
        'TableCellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7,
        leading=9.5,
        textColor=NAVY_PRIMARY
    )
    table_cell_header = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=10,
        textColor=colors.white,
        alignment=TA_CENTER
    )

    story = []

    # =========================================================
    # PAGE 1: TITLE, EXECUTIVE SUMMARY & SYSTEM ARCHITECTURE
    # =========================================================
    story.append(Paragraph("AI-NIDS: AI-Powered Network Intrusion Detection System", title_style))
    story.append(Spacer(1, 3))
    story.append(Paragraph("Comprehensive Architectural Blueprint & Deep Feature Engineering Guide", subtitle_style))
    story.append(Spacer(1, 6))

    # Technology Badges Table
    badge_data = [[
        Paragraph("<b>Python 3.10+</b>", badge_style),
        Paragraph("<b>Flask & Socket.IO</b>", badge_style),
        Paragraph("<b>Scikit-Learn ML</b>", badge_style),
        Paragraph("<b>MaxMind GeoIP2</b>", badge_style),
        Paragraph("<b>Leaflet.js SOC Map</b>", badge_style),
        Paragraph("<b>Open Source Architecture</b>", badge_style),
    ]]
    badge_table = Table(badge_data, colWidths=[86, 96, 94, 88, 94, 78])
    badge_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,0), NAVY_PRIMARY),
        ('BACKGROUND', (1,0), (1,0), NAVY_SECONDARY),
        ('BACKGROUND', (2,0), (2,0), TEAL_ACCENT),
        ('BACKGROUND', (3,0), (3,0), CYAN_ACCENT),
        ('BACKGROUND', (4,0), (4,0), NAVY_SECONDARY),
        ('BACKGROUND', (5,0), (5,0), NAVY_PRIMARY),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
    ]))
    story.append(badge_table)
    story.append(Spacer(1, 6))

    exec_text = (
        "<b>AI-NIDS</b> is an intelligent, real-time Network Intrusion Detection System engineered to defend "
        "enterprise network infrastructure against volumetric distributed denial-of-service (DDoS) floods, stealth "
        "reconnaissance port scans, TCP SYN saturation, and zero-day protocol anomalies. Combining supervised "
        "machine learning (<b>RandomForestClassifier</b>) with unsupervised outlier modeling (<b>IsolationForest</b>) "
        "and a dynamic ensemble scoring pipeline, AI-NIDS delivers line-speed classification with sub-second incident alerting."
    )
    story.append(create_callout(exec_text, title="EXECUTIVE SYSTEM OVERVIEW", bg_color=BG_LIGHT, border_color=TEAL_ACCENT, width=536))
    story.append(Spacer(1, 6))

    story.append(Paragraph("1. System Architecture & Dual-Pipeline Data Flow", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.8, color=TEAL_ACCENT, spaceBefore=1, spaceAfter=4))

    story.append(Paragraph(
        "Modern corporate and cloud networks cannot rely solely on legacy signature-based intrusion detection systems (such as Snort "
        "or Suricata) because static rules cannot identify zero-day polymorphic exploits, packet obfuscation, or distributed volumetric "
        "attacks that mimic legitimate connection handshakes. AI-NIDS operates directly on statistical network flow representations "
        "extracted over bidirectional conversation windows, passing flows through dual parallel inference pipelines.",
        body_style
    ))

    # Architecture ASCII Diagram Card
    arch_diagram = (
        "+-----------------------------------------------------------------------------------+\n"
        "|                             Network Flow Telemetry                                |\n"
        "|               (Real-Time PCAP Sniffing / Socket Stream / Simulation)              |\n"
        "+-----------------------------------------+-----------------------------------------+\n"
        "                                          |\n"
        "                                          v\n"
        "+-----------------------------------------------------------------------------------+\n"
        "|                Feature Extraction (15 Core Statistical Flow Metrics)              |\n"
        "|                     StandardScaler Transformation & Z-Score Normalization         |\n"
        "+-----------------------------------------+-----------------------------------------+\n"
        "                                          |\n"
        "                    +---------------------+---------------------+\n"
        "                    |                                           |\n"
        "                    v                                           v\n"
        "        +-----------------------+                   +-----------------------+\n"
        "        |  Random Forest (RF)   |                   | Isolation Forest (IF) |\n"
        "        |   Supervised Scoring  |                   |  Unsupervised Anomaly |\n"
        "        |     Output: P(RF)     |                   |     Output: S(IF)     |\n"
        "        +-----------+-----------+                   +-----------+-----------+\n"
        "                    |                                           |\n"
        "                    +---------------------+---------------------+\n"
        "                                          |\n"
        "                                          v\n"
        "+-----------------------------------------------------------------------------------+\n"
        "|                                   Ensemble Scorer                                 |\n"
        "|                             S = α · P(RF) + β · S(IF)                             |\n"
        "+-----------------------------------------+-----------------------------------------+\n"
        "                                          |\n"
        "                         [ S >= Threshold (T) or Signature ]\n"
        "                                          |\n"
        "                    +---------------------+---------------------+\n"
        "                    |                                           |\n"
        "          [ MALICIOUS ATTACK ]                               [ BENIGN ]\n"
        "                    |                                           |\n"
        "        +-----------+-----------+                               v\n"
        "        | - WebSocket Broadcast |                         Logged to nids.db\n"
        "        | - Leaflet Map Marker  |                         Telemetry Store\n"
        "        | - SMTP Alert Email    |\n"
        "        | - nids.db Audit Log   |\n"
        "        +-----------------------+\n"
    )

    diagram_table = Table([[Preformatted(arch_diagram, code_style)]], colWidths=[536])
    diagram_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), BG_LIGHT),
        ('BOX', (0,0), (-1,-1), 0.75, BORDER_LIGHT),
        ('TOPPADDING', (0,0), (-1,-1), 2),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(diagram_table)
    story.append(Spacer(1, 4))

    story.append(Paragraph(
        "&bull;&nbsp;<b>Flow Aggregation:</b> Raw packets are grouped into bidirectional flows with IP, port, and duration telemetry.<br/>"
        "&bull;&nbsp;<b>Feature Normalization:</b> 15 statistical metrics are extracted and standardized through <code>StandardScaler</code>.<br/>"
        "&bull;&nbsp;<b>Dual Parallel Inference:</b> Supervised Random Forest and unsupervised Isolation Forest execute simultaneously.<br/>"
        "&bull;&nbsp;<b>Ensemble Synthesis:</b> Scores are blended via $S = \\alpha \\cdot P(\\text{RF}) + \\beta \\cdot S(\\text{IF})$ against threshold $T$.<br/>"
        "&bull;&nbsp;<b>Real-Time Dispatch:</b> Malicious flows trigger Leaflet map markers, WebSocket broadcast, and SMTP alert emails.",
        body_style
    ))

    # =========================================================
    # PAGE 2: HYBRID AI DETECTION ENGINE (DEEP DIVE)
    # =========================================================
    story.append(PageBreak())
    story.append(Paragraph("2. Hybrid AI Detection Engine (Deep Mathematical Breakdown)", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.8, color=TEAL_ACCENT, spaceBefore=1, spaceAfter=6))

    story.append(Paragraph(
        "The core innovation of AI-NIDS is its <b>hybrid AI detection engine</b>. Purely supervised systems fail when confronted "
        "with zero-day exploits or evolving adversarial patterns because no training sample exists. Conversely, purely unsupervised systems "
        "suffer from excessive false positive rates in dynamic enterprise environments. AI-NIDS reconciles this trade-off by coupling "
        "supervised precision with unsupervised outlier sensitivity.",
        body_style
    ))

    story.append(Paragraph("2.1 Supervised Random Forest Classifier", h2_style))
    story.append(Paragraph(
        "The supervised tier employs a <b>Random Forest Classifier</b> composed of an ensemble of decorrelated decision trees trained "
        "using bootstrap aggregating (bagging) and random feature subspace selection on the benchmark <b>CIC-IDS2017</b> dataset. "
        "Each tree splits nodes by minimizing Gini Impurity: "
        "$$I_G(p) = 1 - \\sum_{i=1}^{C} p_i^2$$ "
        "where $C=2$ corresponds to the binary classification space (Normal Traffic vs. Malicious Attack).",
        body_style
    ))
    story.append(Paragraph(
        "During real-time evaluation, the Random Forest outputs an attack probability $P(\\text{RF}) \\in [0, 1]$ computed as the "
        "arithmetic mean of class probability distributions across all individual estimators: "
        "$$P(\\text{RF}) = \\frac{1}{B} \\sum_{b=1}^{B} p_b(\\text{Attack} \\mid x)$$ "
        "Random Forest provides exceptional tabular feature resilience, invariance to monotonic transformations, and immune resistance "
        "to vanishing gradient issues common in deep neural networks.",
        body_style
    ))

    story.append(Paragraph("2.2 Unsupervised Isolation Forest Anomaly Engine", h2_style))
    story.append(Paragraph(
        "The unsupervised tier utilizes an <b>Isolation Forest (iForest)</b> to detect zero-day volumetric anomalies and abnormal connection "
        "behavior without requiring prior labeled instances. Isolation Forest operates on two fundamental quantitative observations: "
        "(1) anomalies are minority instances in the network stream, and (2) anomalies possess attribute values distinctly divergent from nominal flows.",
        body_style
    ))
    story.append(Paragraph(
        "The algorithm constructs recursive isolation trees ($iTrees$) by randomly selecting a feature and a random split point between "
        "the feature's minimum and maximum values. Anomalous flows are isolated near the root of the tree with very short path lengths $h(x)$. "
        "The raw anomaly score $s(x, n)$ is defined as: "
        "$$s(x, n) = 2^{-\\frac{E(h(x))}{c(n)}}$$ "
        "where $E(h(x))$ is the average path length across all isolation trees, and $c(n)$ is the average path length of unsuccessful searches in a Binary Search Tree: "
        "$$c(n) = 2 \\left(\\ln(n - 1) + 0.5772156649\\right) - \\frac{2(n - 1)}{n}$$",
        body_style
    ))
    story.append(Paragraph(
        "To ensure mathematical compatibility with the supervised probability $P(\\text{RF})$, AI-NIDS dynamically calibrates and normalizes "
        "the raw decision function to a bounded interval $[0, 1]$: "
        "$$S(\\text{IF}) = \\frac{\\text{score}_{\\text{raw}}(x) - s_{\\min}}{s_{\\max} - s_{\\min}}$$",
        body_style
    ))

    story.append(Paragraph("2.3 Ensemble Scorer & Dynamic Threshold Decision Logic", h2_style))
    story.append(Paragraph(
        "The predictions from both tiers are synthesized inside the <b>Ensemble Scorer</b> using a convex linear combination: "
        "$$S(x) = \\alpha \\cdot P(\\text{RF}) + \\beta \\cdot S(\\text{IF})$$ "
        "subject to the constraint $\\alpha + \\beta = 1.0$ (production baseline: $\\alpha = 0.70, \\beta = 0.30$).",
        body_style
    ))

    decision_box = (
        "<b>Dual-Layer Final Classification Rule:</b><br/>"
        "$$\\text{Decision}(x) = \\begin{cases} "
        "\\mathbf{ATTACK} \\text{ (Malicious Incident)}, & \\text{if } S(x) \\ge T \\text{ or } \\text{SignatureRule}(x) = \\text{TRUE} \\\\ "
        "\\mathbf{BENIGN} \\text{ (Normal Traffic)}, & \\text{otherwise} "
        "\\end{cases}$$"
    )
    story.append(create_callout(decision_box, title="ENSEMBLE DECISION FORMULATION", bg_color=BG_LIGHT, border_color=NAVY_PRIMARY))
    story.append(Spacer(1, 6))

    story.append(Paragraph(
        "The classification threshold $T$ (default $0.50$) is completely dynamic. Security Operations Center (SOC) engineers can slide $T$ "
        "downward (e.g., $T=0.35$) in high-threat postures to maximize detection recall, or adjust $T$ upward (e.g., $T=0.65$) during high-load "
        "periods to virtually eliminate false positive analyst alerts.",
        body_style
    ))

    # =========================================================
    # PAGE 3: FEATURE EXTRACTION & STANDARDIZATION PIPELINE
    # =========================================================
    story.append(PageBreak())
    story.append(Paragraph("3. Feature Extraction & Standardization Pipeline", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.8, color=TEAL_ACCENT, spaceBefore=1, spaceAfter=6))

    story.append(Paragraph(
        "AI-NIDS extracts 15 core statistical network flow metrics from streaming packet telemetry. These features capture "
        "volumetric magnitude, temporal frequency, directional asymmetry, and transport-layer control flags:",
        body_style
    ))

    # Feature Table (All 15 Canonical Features)
    feature_headers = [
        Paragraph("<b>#</b>", table_cell_header),
        Paragraph("<b>Canonical Feature Name</b>", table_cell_header),
        Paragraph("<b>Unit / Type</b>", table_cell_header),
        Paragraph("<b>Security & Forensic Significance</b>", table_cell_header),
    ]
    feature_rows = [
        [Paragraph("1", table_cell_bold), Paragraph("Flow Duration", table_cell), Paragraph("Microseconds (μs)", table_cell), Paragraph("Identifies persistent sessions vs. ultra-fast SYN / probe bursts.", table_cell)],
        [Paragraph("2", table_cell_bold), Paragraph("Total Fwd Packets", table_cell), Paragraph("Integer Count", table_cell), Paragraph("Measures client-to-server transmission volume; flags flooding.", table_cell)],
        [Paragraph("3", table_cell_bold), Paragraph("Total Backward Packets", table_cell), Paragraph("Integer Count", table_cell), Paragraph("Measures server-to-client responses; detects half-open or unacknowledged flows.", table_cell)],
        [Paragraph("4", table_cell_bold), Paragraph("Total Length of Fwd Packets", table_cell), Paragraph("Bytes", table_cell), Paragraph("Cumulative forward data volume; differentiates payload attacks from header probes.", table_cell)],
        [Paragraph("5", table_cell_bold), Paragraph("Total Length of Bwd Packets", table_cell), Paragraph("Bytes", table_cell), Paragraph("Cumulative response volume; detects large exfiltration or amplification echoes.", table_cell)],
        [Paragraph("6", table_cell_bold), Paragraph("Fwd Packet Length Mean", table_cell), Paragraph("Bytes / Packet", table_cell), Paragraph("Average forward payload size; small packets indicate scanning/SYN floods.", table_cell)],
        [Paragraph("7", table_cell_bold), Paragraph("Bwd Packet Length Mean", table_cell), Paragraph("Bytes / Packet", table_cell), Paragraph("Average response size; flags anomalous server error responses or empty ACK payloads.", table_cell)],
        [Paragraph("8", table_cell_bold), Paragraph("Flow IAT Mean", table_cell), Paragraph("Microseconds (μs)", table_cell), Paragraph("Mean packet inter-arrival time; microsecond intervals characterize bot-driven floods.", table_cell)],
        [Paragraph("9", table_cell_bold), Paragraph("Fwd IAT Mean", table_cell), Paragraph("Microseconds (μs)", table_cell), Paragraph("Mean interval between forward packets; reveals automated rapid-fire attack scripts.", table_cell)],
        [Paragraph("10", table_cell_bold), Paragraph("Bwd IAT Mean", table_cell), Paragraph("Microseconds (μs)", table_cell), Paragraph("Mean interval between backward responses; detects server processing degradation.", table_cell)],
        [Paragraph("11", table_cell_bold), Paragraph("Fwd PSH Flags", table_cell), Paragraph("Binary / Count", table_cell), Paragraph("Push flag frequency forward; identifies interactive exploit delivery.", table_cell)],
        [Paragraph("12", table_cell_bold), Paragraph("Bwd PSH Flags", table_cell), Paragraph("Binary / Count", table_cell), Paragraph("Push flag frequency backward; flags immediate data return requests.", table_cell)],
        [Paragraph("13", table_cell_bold), Paragraph("Fwd URG Flags", table_cell), Paragraph("Binary / Count", table_cell), Paragraph("Urgent pointer assertions forward; flags abnormal protocol manipulations.", table_cell)],
        [Paragraph("14", table_cell_bold), Paragraph("Bwd URG Flags", table_cell), Paragraph("Binary / Count", table_cell), Paragraph("Urgent pointer assertions backward; flags non-standard TCP responses.", table_cell)],
        [Paragraph("15", table_cell_bold), Paragraph("Flow Rate & Volumetric Ratios", table_cell), Paragraph("Packets/s, Bytes/s", table_cell), Paragraph("Derived packet and byte velocity indicators detecting volumetric rate spikes.", table_cell)],
    ]

    feat_table = Table([feature_headers] + feature_rows, colWidths=[20, 142, 95, 275])
    feat_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY_PRIMARY),
        ('ALIGN', (0,0), (0,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER_LIGHT),
        ('TOPPADDING', (0,0), (-1,-1), 2.8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.8),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, BG_LIGHT]),
    ]))
    story.append(feat_table)
    story.append(Spacer(1, 8))

    scaling_box = (
        "<b>StandardScaler Normalization & Canonical Order Enforcement:</b><br/>"
        "All 15 extracted flow attributes are strictly normalized using scikit-learn's <code>StandardScaler</code>: "
        "$$z_j = \\frac{x_j - \\mu_j}{\\sigma_j}$$ "
        "where $\\mu_j$ and $\\sigma_j$ are precomputed feature mean and standard deviation vectors persisted in "
        "<code>models/scaler.joblib</code>. The inference engine strictly checks feature count and column order on "
        "every flow, preventing positional drift and training-serving skew."
    )
    story.append(create_callout(scaling_box, title="FEATURE STANDARDIZATION & INTEGRITY GUARANTEE", bg_color=BG_CALLOUT, border_color=BORDER_ACCENT))

    # =========================================================
    # PAGE 4: KEY OPERATIONAL FEATURES DEEP DIVE
    # =========================================================
    story.append(PageBreak())
    story.append(Paragraph("4. Key Operational Features Deep Dive", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.8, color=TEAL_ACCENT, spaceBefore=1, spaceAfter=6))

    story.append(Paragraph("4.1 Live Interactive SOC Dashboard & Telemetry", h2_style))
    story.append(Paragraph(
        "&bull;&nbsp;<b>Real-Time GeoIP Threat Mapping:</b> Powered by Leaflet.js cartography and MaxMind GeoLite2 City databases "
        "(<code>GeoLite2-City.mmdb</code>). Inbound public IP addresses are resolved to geographical coordinates (latitude, longitude, "
        "city, country). Malicious origin nodes are rendered with animated radar pulse indicators and threat severity tags.<br/>"
        "&bull;&nbsp;<b>WebSocket-Powered Live Telemetry:</b> Leverages Flask-SocketIO to push real-time flow telemetry, model decisions, "
        "and confidence scores directly to analyst consoles with sub-100ms latency, eliminating HTTP polling overhead.<br/>"
        "&bull;&nbsp;<b>Dynamic Simulation Controls:</b> Analysts can tune playback velocity (1x, 2x, 5x, 10x) and adjust ensemble "
        "weights ($\\alpha, \\beta$) and decision threshold ($T$) on the fly using responsive sliders without server downtime.",
        body_style
    ))

    story.append(Paragraph("4.2 Automated Incident Alerting & Stakeholder Subscriptions", h2_style))
    story.append(Paragraph(
        "&bull;&nbsp;<b>Instant SMTP Alert Dispatch:</b> High-confidence attacks automatically generate structured HTML security warning "
        "emails dispatched to network administrators with RFC 5322 priority headers (<code>X-Priority: 1</code>). Emails contain attacking IP, "
        "port, protocol, timestamp, ensemble score, and geographic location.<br/>"
        "&bull;&nbsp;<b>Self-Service Notification Portal:</b> Stakeholders (security analysts, IT engineers, sysadmins) can subscribe "
        "or unsubscribe their email addresses directly through the web portal without administrative overhead.",
        body_style
    ))

    story.append(Paragraph("4.3 Node & Security Policy Control (Active Defense)", h2_style))
    story.append(Paragraph(
        "&bull;&nbsp;<b>Remote Node Tracking & Auto-Discovery:</b> Continuous auto-discovery and state tracking of active gateway, "
        "client, and server IP addresses.<br/>"
        "&bull;&nbsp;<b>Protocol Firewall Policies:</b> Granular switches allow operators to toggle IPv4 traffic inspection, enable TCP flow filters, "
        "and enforce aggressive SYN flood protection policies.<br/>"
        "&bull;&nbsp;<b>System Power Killswitch:</b> A master operational toggle enables instant pausing and resuming of all packet inspection workers.",
        body_style
    ))

    story.append(Paragraph("4.4 Forensic Analytics, Model Evaluation & Explainability", h2_style))
    story.append(Paragraph(
        "&bull;&nbsp;<b>Real-Time Confusion Matrix & Curves:</b> Interactive display of True Positives, False Positives, True Negatives, False Negatives, "
        "along with dynamic ROC-AUC and Precision-Recall evaluation curves.<br/>"
        "&bull;&nbsp;<b>SHAP Visual Explainability:</b> Integrates SHAP (SHapley Additive exPlanations) TreeExplainer to break down exactly which flow features "
        "(e.g., elevated `Total Fwd Packets` or compressed `Flow IAT Mean`) drove the model's malicious classification.<br/>"
        "&bull;&nbsp;<b>One-Click Forensic Export:</b> Enables instantaneous export of logged incidents to CSV (<code>ai_nids_attack_logs.csv</code>) "
        "for SIEM ingestion, compliance reporting, and external audit review.",
        body_style
    ))

    # =========================================================
    # PAGE 5: REST API REFERENCE & QUICK START GUIDE
    # =========================================================
    story.append(PageBreak())
    story.append(Paragraph("5. REST API & WebSocket Endpoint Reference", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.8, color=TEAL_ACCENT, spaceBefore=1, spaceAfter=6))

    api_headers = [
        Paragraph("<b>Method</b>", table_cell_header),
        Paragraph("<b>Endpoint Route</b>", table_cell_header),
        Paragraph("<b>Auth Scope</b>", table_cell_header),
        Paragraph("<b>Description & Operational Scope</b>", table_cell_header),
    ]
    api_rows = [
        [Paragraph("GET", table_cell_bold), Paragraph("/", table_cell), Paragraph("Public", table_cell), Paragraph("Home page & system capability overview.", table_cell)],
        [Paragraph("GET", table_cell_bold), Paragraph("/prediction", table_cell), Paragraph("Operator", table_cell), Paragraph("Live threat monitor & interactive Leaflet GeoIP attack map.", table_cell)],
        [Paragraph("GET", table_cell_bold), Paragraph("/analysis", table_cell), Paragraph("Operator", table_cell), Paragraph("Model evaluation, ROC/PR curves, confusion matrix, and feature importances.", table_cell)],
        [Paragraph("GET/POST", table_cell_bold), Paragraph("/admin", table_cell), Paragraph("Admin Only", table_cell), Paragraph("System administration, node tracking, firewall toggles, and security policies.", table_cell)],
        [Paragraph("POST", table_cell_bold), Paragraph("/api/test_email", table_cell), Paragraph("Admin Only", table_cell), Paragraph("Test SMTP alert delivery to specified recipient email address.", table_cell)],
        [Paragraph("GET/POST", table_cell_bold), Paragraph("/api/subscribers", table_cell), Paragraph("Operator", table_cell), Paragraph("View subscriber list or register a new email for security incident alerts.", table_cell)],
        [Paragraph("POST", table_cell_bold), Paragraph("/api/subscribers/delete", table_cell), Paragraph("Admin Only", table_cell), Paragraph("Remove an email address from the security notification pipeline.", table_cell)],
        [Paragraph("POST", table_cell_bold), Paragraph("/api/settings", table_cell), Paragraph("Operator", table_cell), Paragraph("Update α, β model weighting factors and classification threshold (T).", table_cell)],
        [Paragraph("GET", table_cell_bold), Paragraph("/api/live_stats", table_cell), Paragraph("Operator", table_cell), Paragraph("Live packet counts, session telemetry, and GeoIP markers.", table_cell)],
        [Paragraph("GET", table_cell_bold), Paragraph("/api/metrics_data", table_cell), Paragraph("Operator", table_cell), Paragraph("Confusion matrix, ROC, PR curve data for forensic view.", table_cell)],
        [Paragraph("GET", table_cell_bold), Paragraph("/download_logs", table_cell), Paragraph("Operator", table_cell), Paragraph("Export full incident logs as CSV (ai_nids_attack_logs.csv).", table_cell)],
    ]

    api_table = Table([api_headers] + api_rows, colWidths=[48, 118, 68, 298])
    api_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY_PRIMARY),
        ('ALIGN', (0,0), (0,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER_LIGHT),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, BG_LIGHT]),
    ]))
    story.append(api_table)
    story.append(Spacer(1, 8))

    story.append(Paragraph("6. Quick Start & Deployment Guide", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.8, color=TEAL_ACCENT, spaceBefore=1, spaceAfter=6))

    install_commands = (
        "# 1. Prerequisites: Python 3.10+ and Git\n"
        "# 2. Clone the official repository:\n"
        "git clone https://github.com/pamuriravindrareddy/AI-NIDS.git\n"
        "cd AI-NIDS\n\n"
        "# 3. Install required Python packages:\n"
        "pip install -r requirements.txt\n"
        "# (Or manual install: pip install flask flask-socketio scikit-learn pandas numpy geoip2 joblib)\n\n"
        "# 4. Launch the AI-NIDS application:\n"
        "python app.py\n\n"
        "# 5. Access the Web Application:\n"
        "# Open browser and navigate to: http://localhost:5000\n"
        "# Default Credentials: Username: admin | Password: admin\n"
    )

    install_table = Table([[Preformatted(install_commands, code_style)]], colWidths=[532])
    install_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), BG_LIGHT),
        ('BOX', (0,0), (-1,-1), 0.75, BORDER_LIGHT),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(install_table)
    story.append(Spacer(1, 6))

    security_notice = (
        "<b>Production Security Hardening:</b> Upon initial deployment to an enterprise network, immediately access "
        "<b>/admin</b> to rotate default administrative credentials. Configure the <code>FLASK_SECRET</code> environment "
        "variable with a cryptographically secure random key to safeguard session cookies against tampering."
    )
    story.append(create_callout(security_notice, title="SECURITY HARDENING RECOMMENDATION", bg_color=BG_CALLOUT, border_color=BORDER_ACCENT))

    # Build Document using NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[OK] Generated PDF successfully at: {PDF_PATH_DOCS}")

    # Copy to root directory for easy user access
    shutil.copyfile(PDF_PATH_DOCS, PDF_PATH_ROOT)
    print(f"[OK] Copied PDF successfully to: {PDF_PATH_ROOT}")


if __name__ == '__main__':
    generate_pdf()
