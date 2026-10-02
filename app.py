from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from analyzer.detector import detect_threats
from analyzer.features import summarize_events, top_source_ips
from analyzer.parser import load_logs
from analyzer.scorer import score_findings


st.set_page_config(
    page_title="LogSentinel | Security Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ============================================================================
# LogSentinel visual system
# Matches the clean purple / white language of the HR Attrition dashboard.
# ============================================================================
st.markdown(
    """
    <style>
    :root {
        --purple: #7C3AED;
        --purple-light: #A78BFA;
        --purple-pale: #F3EEFF;
        --text: #2E1065;
        --muted: #766B96;
        --canvas: #F8F7FC;
        --surface: #FFFFFF;
        --border: #E5E5EA;
        --grid: #EEEEF3;
    }

    .stApp {
        background: #F8F7FC !important;
        color: #2E1065 !important;
    }

    .block-container {
        max-width: 1450px !important;
        padding: 1.25rem 2rem 2.5rem !important;
    }

    /* ---- Global typography ---- */
    h1, h2, h3, p, label {
        color: #2E1065;
    }

    h1, h2, h3 {
        font-weight: 600 !important;
    }

    [data-testid="stCaptionContainer"] p,
    .stCaption,
    [data-testid="stMarkdownContainer"] p {
        color: #5B4B7A !important;
    }

    [data-testid="stMarkdownContainer"] strong,
    [data-testid="stMarkdownContainer"] b {
        color: #2E1065 !important;
    }

    [data-testid="stMetricLabel"] {
        color: #5B4B7A !important;
    }

    [data-testid="stMetricValue"] {
        color: #2E1065 !important;
    }

    hr {
        border-color: #E5E5EA !important;
    }

    /* ---- Header ---- */
    .brand {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 2px 0 8px;
    }

    .brand-icon {
        width: 42px;
        height: 42px;
        flex: 0 0 42px;
        display: flex;
        align-items: center;
        justify-content: center;
        background: #F3EEFF;
        border: 1px solid #E6DDFC;
        border-radius: 8px;
        font-size: 21px;
    }

    .brand-name {
        color: #2E1065;
        font-size: 1.65rem;
        font-weight: 600;
        line-height: 1.15;
    }

    .brand-desc {
        color: #5B4B7A;
        font-size: 0.82rem;
        margin-top: 3px;
    }

    .status {
        margin-left: auto;
        padding: 6px 10px;
        border: 1px solid #DDD6FE;
        border-radius: 999px;
        background: #F3EEFF;
        color: #7C3AED;
        font-size: 0.7rem;
        font-weight: 600;
        white-space: nowrap;
    }

    /* ---- Controls ---- */
    div[data-testid="stExpander"] {
        background: #FFFFFF !important;
        border: 1px solid #E5E5EA !important;
        border-radius: 7px !important;
        margin: 10px 0 14px !important;
    }

    div[data-testid="stExpander"] details summary {
        color: #2E1065 !important;
    }

    div[data-testid="stExpander"] details summary p {
        color: #2E1065 !important;
        font-weight: 600 !important;
    }

    /* Force native uploader into light styling */
    section[data-testid="stFileUploaderDropzone"] {
        background: #FBFAFE !important;
        border: 1px dashed #CFC4E8 !important;
        border-radius: 7px !important;
    }

    section[data-testid="stFileUploaderDropzone"] * {
        color: #5B438F !important;
    }

    section[data-testid="stFileUploaderDropzone"] button {
        background: #FFFFFF !important;
        color: #5B21B6 !important;
        border: 1px solid #CFC4E8 !important;
        border-radius: 6px !important;
    }

    .columns-box {
        background: #F8F6FD;
        border: 1px solid #E5DFF2;
        border-radius: 6px;
        padding: 9px 11px;
        color: #5B438F;
        font-family: monospace;
        font-size: 0.72rem;
        line-height: 1.55;
    }

    .notice {
        background: #F8F6FD;
        border-left: 3px solid #7C3AED;
        border-radius: 4px;
        padding: 9px 11px;
        color: #5B4B7A;
        font-size: 0.72rem;
        line-height: 1.45;
    }

    /* ---- Sections ---- */
    .section {
        color: #2E1065;
        font-size: 1.05rem;
        font-weight: 600;
        margin: 18px 0 9px;
    }

    .section-sub {
        color: #5B4B7A;
        font-size: 0.75rem;
        margin: -4px 0 9px;
    }

    /* ---- KPI responsive grid ---- */
    .kpi-grid {
        display: grid;
        grid-template-columns: repeat(5, minmax(0, 1fr));
        gap: 10px;
    }

    .kpi {
        background: #FFFFFF;
        border: 1px solid #E5E5EA;
        border-radius: 7px;
        padding: 11px 13px;
        min-width: 0;
    }

    .kpi-label {
        color: #5B4B7A;
        font-size: 0.68rem;
        font-weight: 600;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }

    .kpi-value {
        color: #2E1065;
        font-size: 1.35rem;
        font-weight: 600;
        line-height: 1.15;
        margin-top: 5px;
    }

    .kpi-note {
        color: #5B4B7A;
        font-size: 0.64rem;
        margin-top: 3px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }

    /* ---- Insight grid ---- */
    .insight-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 10px;
    }

    .insight {
        background: #FFFFFF;
        border: 1px solid #E5E5EA;
        border-radius: 7px;
        padding: 11px 13px;
    }

    .insight-title {
        color: #2E1065;
        font-size: 0.75rem;
        font-weight: 600;
        margin-bottom: 4px;
    }

    .insight-text {
        color: #5B4B7A;
        font-size: 0.7rem;
        line-height: 1.42;
    }

    /* ---- Charts / table ---- */
    div[data-testid="stPlotlyChart"] {
        background: #FFFFFF !important;
        border: 1px solid #E5E5EA !important;
        border-radius: 7px !important;
        padding: 2px !important;
    }

    div[data-testid="stPlotlyChart"] .modebar {
        opacity: 0.5 !important;
    }

    @media (max-width: 768px) {
        div[data-testid="stPlotlyChart"] .modebar {
            display: none !important;
        }
    }

    div[data-testid="stDataFrame"] {
        border: 1px solid #E5E5EA !important;
        border-radius: 7px !important;
        overflow: hidden;
    }

    .footer {
        color: #9A8DB8;
        text-align: center;
        font-size: 0.66rem;
        padding-top: 22px;
    }

    /* ---- Mobile ---- */
    @media (max-width: 768px) {
        .block-container {
            padding: 0.75rem 0.75rem 1.75rem !important;
        }

        .brand {
            padding-top: 2px;
            gap: 9px;
        }

        .brand-icon {
            width: 36px;
            height: 36px;
            flex-basis: 36px;
            font-size: 18px;
            border-radius: 7px;
        }

        .brand-name {
            font-size: 1.28rem;
        }

        .brand-desc {
            font-size: 0.7rem;
            max-width: 255px;
        }

        .status {
            display: none;
        }

        .kpi-grid {
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 7px;
        }

        .kpi {
            padding: 10px 11px;
            min-height: 67px;
        }

        .kpi-label {
            font-size: 0.61rem;
        }

        .kpi-value {
            font-size: 1.15rem;
        }

        .kpi-note {
            font-size: 0.58rem;
        }

        .insight-grid {
            grid-template-columns: 1fr;
            gap: 7px;
        }

        .section {
            margin-top: 14px;
            font-size: 0.98rem;
        }

        .section-sub {
            font-size: 0.68rem;
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)

default_path = Path(__file__).parent / "data" / "sample_auth_logs.csv"

# ============================================================================
# Header
# ============================================================================
st.markdown(
    """
    <div class="brand">
        <div class="brand-icon">🛡️</div>
        <div>
            <div class="brand-name">LogSentinel</div>
            <div class="brand-desc">Security Log Analysis & Threat Detection · Day 01 / 100</div>
        </div>
        <div class="status">● ANALYTICS ONLINE</div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ============================================================================
# Compact data controls — avoids the large mobile sidebar overlay
# ============================================================================
with st.expander("⚙️  Data & detection controls", expanded=False):
    control_left, control_right = st.columns([1.25, 1])

    with control_left:
        uploaded = st.file_uploader(
            "Authentication log CSV",
            type=["csv"],
            help="CSV should contain timestamp, source_ip, username and event_type.",
        )

    with control_right:
        st.markdown("**Required columns**")
        st.markdown(
            """
            <div class="columns-box">
            timestamp<br>
            source_ip<br>
            username<br>
            event_type
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height:7px'></div>", unsafe_allow_html=True)
    st.markdown(
        """
        <div class="notice">
        <strong>Defensive analytics only.</strong>
        LogSentinel analyzes synthetic authentication data and does not perform
        authentication attempts, scanning, blocking, exploitation, or password collection.
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.caption("Rule-based detection · Explainable risk scoring")

# ============================================================================
# Load + analyze
# ============================================================================
try:
    df = load_logs(uploaded if uploaded is not None else default_path)
except Exception as exc:
    st.error(str(exc))
    st.stop()

summary = summarize_events(df)
findings = score_findings(detect_threats(df))

high_count = int((findings["severity"] == "HIGH").sum()) if not findings.empty else 0
medium_count = int((findings["severity"] == "MEDIUM").sum()) if not findings.empty else 0
low_count = int((findings["severity"] == "LOW").sum()) if not findings.empty else 0
avg_risk = float(findings["risk_score"].mean()) if not findings.empty else 0.0

# ============================================================================
# Security overview
# ============================================================================
st.markdown("### Security overview")

kpis = [
    ("Total events", f"{summary['total_events']:,}", "Authentication activity"),
    ("Failed logins", f"{summary['failed_logins']:,}", "Authentication failures"),
    ("Successful logins", f"{summary['successful_logins']:,}", "Accepted authentications"),
    ("Unique IPs", f"{summary['unique_ips']:,}", "Observed source addresses"),
    ("Security alerts", f"{len(findings):,}", f"{high_count} high severity"),
]

# Native Streamlit columns are deliberately used here instead of custom HTML.
# This avoids mobile rendering issues and keeps the cards responsive.
kpi_cols = st.columns(5, gap="small")
for col, (label, value, note) in zip(kpi_cols, kpis):
    with col:
        with st.container(border=True):
            st.caption(label)
            st.markdown(f"### {value}")
            st.caption(note)

# ============================================================================
# Analyst summary
# ============================================================================
st.markdown("### Analyst summary")

insights = [
    ("Threat posture", f"{high_count} high · {medium_count} medium · {low_count} low severity findings."),
    ("Average alert risk", f"{avg_risk:.1f} / 100 across detected findings."),
    (
        "Detection approach",
        "Frequency, account targeting, event sequences and timestamps are correlated using explainable rules.",
    ),
]

insight_cols = st.columns(3, gap="small")
for col, (title, body) in zip(insight_cols, insights):
    with col:
        with st.container(border=True):
            st.markdown(f"**{title}**")
            st.caption(body)

# ============================================================================
# Threat analysis
# ============================================================================
st.markdown('<div class="section">Threat analysis</div>', unsafe_allow_html=True)
st.markdown('<div class="section-sub">Detection distribution and authentication activity.</div>', unsafe_allow_html=True)

left, right = st.columns(2)

with left:
    st.markdown("**Threat distribution**")
    if findings.empty:
        st.success("No detections for the current dataset.")
    else:
        counts = findings["threat"].value_counts().reset_index()
        counts.columns = ["threat", "count"]
        fig = px.bar(
            counts,
            x="threat",
            y="count",
            text="count",
            template="plotly_white",
            color="threat",
            color_discrete_sequence=["#7C3AED", "#A78BFA", "#C4B5FD", "#DDD6FE"],
        )
        fig.update_layout(
            showlegend=False,
            margin=dict(l=10, r=10, t=8, b=28),
            height=280,
            xaxis_title=None,
            yaxis_title="Detections",
            font=dict(color="#2E1065", size=11),
            title_font=dict(color="#2E1065", size=11),
            plot_bgcolor="#FFFFFF",
            paper_bgcolor="#FFFFFF",
            hovermode="x unified",
        )
        fig.update_xaxes(
            showgrid=False,
            zeroline=False,
            tickfont=dict(color="#5B4B7A", size=11),
            title_font=dict(color="#2E1065", size=11),
            linecolor="#C9C2D8",
        )
        fig.update_yaxes(
            showgrid=True,
            gridcolor="#E7E3EE",
            zeroline=False,
            tickfont=dict(color="#5B4B7A", size=11),
            title_font=dict(color="#2E1065", size=11),
            linecolor="#C9C2D8",
        )
        fig.update_traces(
            textposition="outside",
            cliponaxis=False,
            textfont=dict(color="#2E1065", size=11),
        )
        st.plotly_chart(fig, use_container_width=True)

with right:
    st.markdown("**Top source IPs**")
    ips = top_source_ips(df)
    fig = px.bar(
        ips,
        x="events",
        y="source_ip",
        orientation="h",
        text="events",
        template="plotly_white",
    )
    fig.update_layout(
        margin=dict(l=10, r=12, t=8, b=28),
        height=280,
        xaxis_title="Events",
        yaxis_title=None,
        font=dict(color="#2E1065", size=11),
        plot_bgcolor="#FFFFFF",
        paper_bgcolor="#FFFFFF",
        hovermode="y",
    )
    fig.update_xaxes(
        showgrid=True,
        gridcolor="#E7E3EE",
        zeroline=False,
        tickfont=dict(color="#5B4B7A", size=11),
        title_font=dict(color="#2E1065", size=11),
        linecolor="#C9C2D8",
    )
    fig.update_yaxes(
        showgrid=False,
        zeroline=False,
        tickfont=dict(color="#5B4B7A", size=11),
        title_font=dict(color="#2E1065", size=11),
        linecolor="#C9C2D8",
    )
    fig.update_traces(
        marker_color="#7C3AED",
        textposition="outside",
        cliponaxis=False,
        textfont=dict(color="#2E1065", size=11),
    )
    st.plotly_chart(
        fig,
        use_container_width=True,
        config={"displaylogo": False, "responsive": True, "modeBarButtonsToRemove": ["lasso2d", "select2d"]},
    )

st.markdown("**Authentication activity**")
timeline = (
    df.set_index("timestamp")
    .resample("30min")
    .size()
    .reset_index(name="events")
)

fig = px.line(timeline, x="timestamp", y="events", markers=True, template="plotly_white")
fig.update_layout(
    margin=dict(l=10, r=10, t=8, b=28),
    height=280,
    xaxis_title=None,
    yaxis_title="Events",
    font=dict(color="#2E1065", size=11),
    plot_bgcolor="#FFFFFF",
    paper_bgcolor="#FFFFFF",
    hovermode="x unified",
)
fig.update_xaxes(showgrid=False, zeroline=False)
fig.update_yaxes(showgrid=True, gridcolor="#EEEEF3", zeroline=False)
fig.update_traces(line=dict(color="#7C3AED", width=2.5), marker=dict(size=6))
st.plotly_chart(
    fig,
    use_container_width=True,
    config={"displaylogo": False, "responsive": True, "modeBarButtonsToRemove": ["lasso2d", "select2d"]},
)

# ============================================================================
# Security findings
# ============================================================================
st.markdown('<div class="section">Security findings</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="section-sub">Evidence generated by the detection rules. Risk scores are transparent and explainable.</div>',
    unsafe_allow_html=True,
)

if findings.empty:
    st.success("No findings in the current dataset.")
else:
    display = findings.copy()
    display["timestamp"] = display["timestamp"].astype(str)

    st.dataframe(
        display[
            [
                "timestamp",
                "source_ip",
                "username",
                "threat",
                "severity",
                "risk_score",
                "evidence",
            ]
        ],
        use_container_width=True,
        hide_index=True,
        column_config={
            "timestamp": st.column_config.TextColumn("Timestamp"),
            "source_ip": st.column_config.TextColumn("Source IP"),
            "username": st.column_config.TextColumn("Username"),
            "threat": st.column_config.TextColumn("Threat"),
            "severity": st.column_config.TextColumn("Severity"),
            "risk_score": st.column_config.ProgressColumn(
                "Risk score", min_value=0, max_value=100, format="%d"
            ),
            "evidence": st.column_config.TextColumn("Evidence", width="large"),
        },
    )

st.markdown(
    """
    <div class="footer">
        LogSentinel v1.0 · Synthetic authentication dataset · Defensive security research
        <br>Python · Pandas · Plotly · Streamlit
    </div>
    """,
    unsafe_allow_html=True,
)
