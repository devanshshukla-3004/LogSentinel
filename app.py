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

# ---------------------------------------------------------------------------
# Shared visual system — intentionally aligned with the HR Attrition project
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    :root {
        --purple: #7C3AED;
        --purple-light: #C4B5FD;
        --purple-pale: #F3EEFF;
        --text: #2E1065;
        --muted: #7C6FA8;
        --canvas: #F8F7FC;
        --surface: #FFFFFF;
        --border: #E5E5EA;
        --grid: #EEEEF3;
        --danger: #7C3AED;
    }

    .stApp {
        background: var(--canvas);
        color: var(--text);
    }

    .block-container {
        max-width: 1500px;
        padding-top: 1.5rem;
        padding-bottom: 2.5rem;
    }

    /* Typography */
    h1, h2, h3 {
        color: var(--text) !important;
        font-weight: 600 !important;
    }

    h1 {
        font-size: 1.7rem !important;
        margin-bottom: 0.15rem !important;
    }

    p, label, .stMarkdown, [data-testid="stCaptionContainer"] {
        color: var(--text);
    }

    [data-testid="stCaptionContainer"] p {
        color: var(--muted) !important;
    }

    hr {
        border-color: var(--border) !important;
    }

    /* Sidebar — explicit colors prevent dark-mode/browser inheritance */
    [data-testid="stSidebar"] {
        background: #FFFFFF !important;
        border-right: 1px solid var(--border);
    }

    [data-testid="stSidebar"] * {
        color: var(--text);
    }

    [data-testid="stSidebar"] [data-testid="stCaptionContainer"] p,
    [data-testid="stSidebar"] small {
        color: var(--muted) !important;
    }

    [data-testid="stSidebar"] .stFileUploaderDropzone {
        background: #FBFAFE !important;
        border: 1px dashed #CFC4E8 !important;
        border-radius: 6px !important;
    }

    [data-testid="stSidebar"] .stFileUploaderDropzone > div {
        color: var(--muted) !important;
    }

    [data-testid="stSidebar"] button {
        border-radius: 6px !important;
    }

    /* Header */
    .brand-row {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 2px;
    }

    .brand-icon {
        width: 42px;
        height: 42px;
        border-radius: 6px;
        background: var(--purple-pale);
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 22px;
        flex: 0 0 auto;
    }

    .brand-title {
        color: var(--text);
        font-size: 1.7rem;
        font-weight: 600;
        line-height: 1.15;
    }

    .brand-subtitle {
        color: var(--muted);
        font-size: 0.86rem;
        margin-top: 3px;
    }

    .online-badge {
        margin-left: auto;
        color: var(--purple);
        background: var(--purple-pale);
        border: 1px solid #DDD6FE;
        border-radius: 999px;
        padding: 6px 10px;
        font-size: 0.72rem;
        font-weight: 600;
        white-space: nowrap;
    }

    /* Section headings */
    .section-title {
        color: var(--text);
        font-size: 1.05rem;
        font-weight: 600;
        margin: 18px 0 10px;
    }

    .section-caption {
        color: var(--muted);
        font-size: 0.78rem;
        margin-top: -5px;
        margin-bottom: 10px;
    }

    /* KPI cards */
    .kpi {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 6px;
        padding: 12px 14px;
        min-height: 78px;
    }

    .kpi-label {
        color: var(--muted);
        font-size: 0.72rem;
        font-weight: 600;
    }

    .kpi-value {
        color: var(--text);
        font-size: 1.45rem;
        font-weight: 600;
        line-height: 1.2;
        margin-top: 5px;
    }

    .kpi-note {
        color: var(--muted);
        font-size: 0.68rem;
        margin-top: 2px;
    }

    /* Small insight cards */
    .insight {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 6px;
        padding: 12px 14px;
        min-height: 82px;
    }

    .insight-title {
        color: var(--text);
        font-size: 0.78rem;
        font-weight: 600;
        margin-bottom: 4px;
    }

    .insight-text {
        color: var(--muted);
        font-size: 0.72rem;
        line-height: 1.45;
    }

    /* Dataset info in sidebar */
    .column-box {
        background: #F8F6FD;
        border: 1px solid #E5DFF2;
        border-radius: 6px;
        padding: 9px 10px;
        font-family: monospace;
        font-size: 0.72rem;
        line-height: 1.65;
        color: #5B438F !important;
    }

    .safe-box {
        background: #F8F6FD;
        border-left: 3px solid var(--purple);
        border-radius: 4px;
        padding: 10px 11px;
        color: var(--muted) !important;
        font-size: 0.72rem;
        line-height: 1.45;
    }

    /* Streamlit-native metrics / charts */
    [data-testid="stMetric"] {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 6px;
        padding: 12px 14px;
    }

    [data-testid="stMetricLabel"] {
        color: var(--muted) !important;
    }

    [data-testid="stMetricValue"] {
        color: var(--text) !important;
        font-weight: 600 !important;
    }

    div[data-testid="stPlotlyChart"] {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 6px;
        padding: 3px;
    }

    div[data-testid="stDataFrame"] {
        border: 1px solid var(--border);
        border-radius: 6px;
        overflow: hidden;
    }

    .footer {
        color: #9A8DB8;
        text-align: center;
        font-size: 0.68rem;
        padding-top: 22px;
    }

    /* Mobile */
    @media (max-width: 768px) {
        .block-container {
            padding: 1rem 0.8rem 2rem;
        }

        .brand-title {
            font-size: 1.35rem;
        }

        .brand-subtitle {
            font-size: 0.74rem;
        }

        .brand-icon {
            width: 36px;
            height: 36px;
            font-size: 18px;
        }

        .online-badge {
            display: none;
        }

        .section-title {
            margin-top: 14px;
        }

        .kpi {
            padding: 10px 11px;
            min-height: 70px;
        }

        .kpi-value {
            font-size: 1.2rem;
        }

        .kpi-label {
            font-size: 0.64rem;
        }

        .insight {
            min-height: 0;
            margin-bottom: 8px;
        }

        div[data-testid="stPlotlyChart"] {
            padding: 1px;
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)

default_path = Path(__file__).parent / "data" / "sample_auth_logs.csv"

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("## Analyst Console")
    st.caption("Load an authentication log and inspect security signals.")

    uploaded = st.file_uploader(
        "Authentication log CSV",
        type=["csv"],
        help="CSV should contain timestamp, source_ip, username and event_type.",
    )

    st.markdown("**Required columns**")
    st.markdown(
        """
        <div class="column-box">
        timestamp<br>
        source_ip<br>
        username<br>
        event_type
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)

    st.markdown(
        """
        <div class="safe-box">
        <strong>Defensive analytics only.</strong><br>
        LogSentinel analyzes synthetic authentication data. It does not perform
        authentication attempts, scanning, blocking, exploitation, or password collection.
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
    st.caption("Rule-based detection · Explainable risk scoring")

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.markdown(
    """
    <div class="brand-row">
        <div class="brand-icon">🛡️</div>
        <div>
            <div class="brand-title">LogSentinel</div>
            <div class="brand-subtitle">
                Security Log Analysis & Threat Detection · Day 01 / 100
            </div>
        </div>
        <div class="online-badge">● ANALYTICS ONLINE</div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.divider()

# ---------------------------------------------------------------------------
# Load + analyze
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------
st.markdown('<div class="section-title">Security overview</div>', unsafe_allow_html=True)

kpis = [
    ("Total events", f"{summary['total_events']:,}", "Authentication activity"),
    ("Failed logins", f"{summary['failed_logins']:,}", "Authentication failures"),
    ("Successful logins", f"{summary['successful_logins']:,}", "Accepted authentications"),
    ("Unique IPs", f"{summary['unique_ips']:,}", "Observed source addresses"),
    ("Security alerts", f"{len(findings):,}", f"{high_count} high severity"),
]

cols = st.columns(5)
for col, (label, value, note) in zip(cols, kpis):
    with col:
        st.markdown(
            f"""
            <div class="kpi">
                <div class="kpi-label">{label}</div>
                <div class="kpi-value">{value}</div>
                <div class="kpi-note">{note}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

# ---------------------------------------------------------------------------
# Analyst summary
# ---------------------------------------------------------------------------
st.markdown('<div class="section-title">Analyst summary</div>', unsafe_allow_html=True)

insights = [
    (
        "Threat posture",
        f"{high_count} high · {medium_count} medium · {low_count} low severity findings.",
    ),
    (
        "Average alert risk",
        f"{avg_risk:.1f} / 100 across detected findings.",
    ),
    (
        "Detection approach",
        "Frequency, account targeting, event sequences and timestamps are correlated using explainable rules.",
    ),
]

cols = st.columns(3)
for col, (title, body) in zip(cols, insights):
    with col:
        st.markdown(
            f"""
            <div class="insight">
                <div class="insight-title">{title}</div>
                <div class="insight-text">{body}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------
st.markdown('<div class="section-title">Threat analysis</div>', unsafe_allow_html=True)

left, right = st.columns(2)

with left:
    st.markdown("**Threat distribution**")
    st.caption("Detected threat categories in the current dataset.")
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
            color_discrete_sequence=["#7C3AED", "#C4B5FD", "#A78BFA", "#DDD6FE"],
        )
        fig.update_layout(
            showlegend=False,
            margin=dict(l=10, r=10, t=12, b=10),
            height=320,
            xaxis_title=None,
            yaxis_title="Detections",
            font=dict(color="#2E1065"),
        )
        fig.update_traces(textposition="outside", cliponaxis=False)
        st.plotly_chart(fig, use_container_width=True)

with right:
    st.markdown("**Top source IPs**")
    st.caption("Sources generating the most authentication events.")
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
        margin=dict(l=10, r=10, t=12, b=10),
        height=320,
        xaxis_title="Events",
        yaxis_title=None,
        font=dict(color="#2E1065"),
    )
    fig.update_traces(marker_color="#7C3AED", textposition="outside", cliponaxis=False)
    st.plotly_chart(fig, use_container_width=True)

st.markdown("**Authentication activity**")
st.caption("Event volume aggregated into 30-minute windows.")

timeline = (
    df.set_index("timestamp")
    .resample("30min")
    .size()
    .reset_index(name="events")
)

fig = px.line(
    timeline,
    x="timestamp",
    y="events",
    markers=True,
    template="plotly_white",
)
fig.update_layout(
    margin=dict(l=10, r=10, t=12, b=10),
    height=300,
    xaxis_title=None,
    yaxis_title="Events",
    font=dict(color="#2E1065"),
)
fig.update_traces(line=dict(color="#7C3AED", width=2.5), marker=dict(size=6))
st.plotly_chart(fig, use_container_width=True)

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
st.markdown('<div class="section-title">Security findings</div>', unsafe_allow_html=True)
st.caption("Evidence generated by the detection rules. Risk scores are transparent and explainable.")

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
                "Risk score",
                min_value=0,
                max_value=100,
                format="%d",
            ),
            "evidence": st.column_config.TextColumn("Evidence", width="large"),
        },
    )

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------
st.markdown(
    """
    <div class="footer">
        LogSentinel v1.0 · Synthetic authentication dataset · Defensive security research
        <br>
        Python · Pandas · Plotly · Streamlit
    </div>
    """,
    unsafe_allow_html=True,
)
