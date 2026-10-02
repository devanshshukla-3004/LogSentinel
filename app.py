from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from analyzer.detector import detect_threats
from analyzer.features import summarize_events, top_source_ips
from analyzer.parser import load_logs
from analyzer.scorer import score_findings


# ─────────────────────────────────────────────────────────────────────────────
# Page configuration
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="LogSentinel | Security Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# Enterprise light theme
# ─────────────────────────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
        :root {
            --purple: #7C3AED;
            --purple-soft: #C4B5FD;
            --text: #2E1065;
            --muted: #7C6FA8;
            --border: #E5E5EA;
            --surface: #FFFFFF;
            --canvas: #F8F7FC;
            --grid: #EEEEF3;
            --high: #7C3AED;
            --medium: #A78BFA;
            --low: #C4B5FD;
            --success: #7C3AED;
        }

        .stApp {
            background: #F8F7FC;
            color: #2E1065;
        }

        h1, h2, h3 {
            color: #2E1065;
            font-weight: 600;
        }

        hr {
            border-color: #E5E5EA;
        }

        [data-testid="stMetric"] {
            background: #FFFFFF;
            border: 1px solid #E5E5EA;
            border-radius: 6px;
            padding: 12px 14px;
        }

        [data-testid="stMetricLabel"] {
            color: #7C6FA8;
        }

        [data-testid="stMetricValue"] {
            color: #2E1065;
            font-weight: 600;
        }

        div[data-testid="stPlotlyChart"] {
            background: #FFFFFF;
            border: 1px solid #E5E5EA;
            border-radius: 6px;
            padding: 4px;
        }

        .block-container {
            max-width: 1500px;
            padding-top: 2rem;
            padding-bottom: 3rem;
        }

        [data-testid="stSidebar"] {
            background: #FFFFFF;
            border-right: 1px solid var(--border);
        }

        [data-testid="stSidebar"] h2,
        [data-testid="stSidebar"] h3 {
            color: var(--text);
        }

        .hero {
            background: transparent;
            border: 0;
            border-radius: 0;
            padding: 0 0 8px;
            margin-bottom: 12px;
        }

        .hero-row {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .shield {
            width: 48px;
            height: 48px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #F1ECFF;
            border-radius: 6px;
            font-size: 25px;
        }

        .hero-title {
            color: var(--navy);
            font-size: 1.7rem;
            font-weight: 600;
            line-height: 1.1;
            margin: 0;
        }

        .hero-subtitle {
            color: var(--muted);
            font-size: 14px;
            margin-top: 6px;
        }

        .status-pill {
            margin-left: auto;
            background: #F5F3FF;
            color: var(--purple);
            border: 1px solid #DDD6FE;
            border-radius: 999px;
            padding: 7px 12px;
            font-size: 12px;
            font-weight: 650;
            white-space: nowrap;
        }

        .section-label {
            color: var(--navy);
            font-size: 18px;
            font-weight: 700;
            margin: 8px 0 12px;
        }

        .metric-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 16px 18px;
            min-height: 0;
            box-shadow: none;
        }

        .metric-label {
            color: var(--muted);
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: .04em;
        }

        .metric-value {
            color: var(--navy);
            font-size: 25px;
            font-weight: 750;
            margin-top: 6px;
        }

        .metric-note {
            color: var(--muted);
            font-size: 11px;
            margin-top: 2px;
        }

        .insight-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 14px 16px;
            height: 100%;
        }

        .insight-title {
            color: var(--navy);
            font-size: 13px;
            font-weight: 700;
            margin-bottom: 5px;
        }

        .insight-text {
            color: var(--muted);
            font-size: 12px;
            line-height: 1.45;
        }

        .footer {
            color: #98A2B3;
            text-align: center;
            font-size: 11px;
            padding-top: 24px;
        }

        div[data-testid="stDataFrame"] {
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
        }

        .stAlert {
            border-radius: 10px;
        }

        button[kind="secondary"] {
            border-radius: 8px;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

default_path = Path(__file__).parent / "data" / "sample_auth_logs.csv"

# ─────────────────────────────────────────────────────────────────────────────
# Header
# ─────────────────────────────────────────────────────────────────────────────
st.markdown(
    """
    <div class="hero">
        <div class="hero-row">
            <div class="shield">🛡️</div>
            <div>
                <div class="hero-title">LogSentinel</div>
                <div class="hero-subtitle">
                    Security Log Analysis & Threat Detection Engine · Day 01 / 100
                </div>
            </div>
            <div class="status-pill">● ANALYTICS ONLINE</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ─────────────────────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## Analyst Console")
    st.caption("Configure the dataset used by the detection engine.")

    uploaded = st.file_uploader(
        "Authentication log CSV",
        type=["csv"],
        help="Upload a CSV containing timestamp, source_ip, username and event_type.",
    )

    st.divider()

    st.markdown("**Expected columns**")
    st.code("timestamp\\nsource_ip\\nusername\\nevent_type", language="text")

    st.info(
        "Defensive analytics only. LogSentinel uses synthetic authentication data "
        "and does not perform authentication attempts, blocking, scanning, or exploitation."
    )

    st.divider()
    st.caption("Rule-based detection · Explainable risk scoring")

# ─────────────────────────────────────────────────────────────────────────────
# Data loading and analysis
# ─────────────────────────────────────────────────────────────────────────────
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

# ─────────────────────────────────────────────────────────────────────────────
# KPI cards
# ─────────────────────────────────────────────────────────────────────────────
st.markdown('<div class="section-label">Security overview</div>', unsafe_allow_html=True)

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
            <div class="metric-card">
                <div class="metric-label">{label}</div>
                <div class="metric-value">{value}</div>
                <div class="metric-note">{note}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

st.write("")

# ─────────────────────────────────────────────────────────────────────────────
# Analyst insights
# ─────────────────────────────────────────────────────────────────────────────
insight_cols = st.columns(3)
with insight_cols[0]:
    st.markdown(
        f"""
        <div class="insight-card">
            <div class="insight-title">Threat posture</div>
            <div class="insight-text">
                {high_count} high, {medium_count} medium and {low_count} low severity
                findings were identified in the current dataset.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with insight_cols[1]:
    st.markdown(
        f"""
        <div class="insight-card">
            <div class="insight-title">Average alert risk</div>
            <div class="insight-text">
                {avg_risk:.1f} / 100 across detected findings, using transparent
                rule-based scoring.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with insight_cols[2]:
    st.markdown(
        """
        <div class="insight-card">
            <div class="insight-title">Detection approach</div>
            <div class="insight-text">
                Correlates authentication frequency, usernames, event sequences
                and timestamps to surface suspicious behavior.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.write("")

# ─────────────────────────────────────────────────────────────────────────────
# Charts
# ─────────────────────────────────────────────────────────────────────────────
left, right = st.columns(2)

with left:
    st.markdown('<div class="section-label">Threat distribution</div>', unsafe_allow_html=True)
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
            margin=dict(l=10, r=10, t=10, b=10),
            height=330,
            xaxis_title=None,
            yaxis_title="Detections",
        )
        fig.update_traces(textposition="outside", cliponaxis=False)
        st.plotly_chart(fig, use_container_width=True)

with right:
    st.markdown('<div class="section-label">Top source IPs</div>', unsafe_allow_html=True)
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
        margin=dict(l=10, r=10, t=10, b=10),
        height=330,
        xaxis_title="Events",
        yaxis_title=None,
    )
    fig.update_traces(marker_color="#7C3AED", textposition="outside", cliponaxis=False)
    st.plotly_chart(fig, use_container_width=True)

st.markdown('<div class="section-label">Authentication activity</div>', unsafe_allow_html=True)

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
    margin=dict(l=10, r=10, t=10, b=10),
    height=320,
    xaxis_title=None,
    yaxis_title="Events",
)
fig.update_traces(line=dict(color="#7C3AED", width=2.5), marker=dict(size=6))
st.plotly_chart(fig, use_container_width=True)

# ─────────────────────────────────────────────────────────────────────────────
# Findings table
# ─────────────────────────────────────────────────────────────────────────────
st.markdown('<div class="section-label">Security findings</div>', unsafe_allow_html=True)

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

# ─────────────────────────────────────────────────────────────────────────────
# Footer
# ─────────────────────────────────────────────────────────────────────────────
st.markdown(
    """
    <div class="footer">
        LogSentinel v1.0 · Synthetic authentication dataset · Defensive security research
        <br>
        Built with Python · Pandas · Plotly · Streamlit
    </div>
    """,
    unsafe_allow_html=True,
)
