from pathlib import Path
import pandas as pd
import plotly.express as px
import streamlit as st

from analyzer.detector import detect_threats
from analyzer.features import summarize_events, top_source_ips
from analyzer.parser import load_logs
from analyzer.scorer import score_findings

st.set_page_config(page_title='LogSentinel', page_icon='🛡️', layout='wide')
st.title('🛡️ LogSentinel')
st.caption('Security Log Analysis & Threat Detection Engine · Day 01/100')

default_path = Path(__file__).parent / 'data' / 'sample_auth_logs.csv'

with st.sidebar:
    st.header('Data source')
    uploaded = st.file_uploader('Upload authentication CSV', type=['csv'])
    st.divider()
    st.markdown('Expected columns: timestamp, source_ip, username, event_type')
    st.info('Synthetic data only. Defensive analytics; no blocking actions.')

try:
    df = load_logs(uploaded if uploaded is not None else default_path)
except Exception as exc:
    st.error(str(exc))
    st.stop()

summary = summarize_events(df)
findings = score_findings(detect_threats(df))

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric('Total events', f"{summary['total_events']:,}")
c2.metric('Failed logins', f"{summary['failed_logins']:,}")
c3.metric('Successful logins', f"{summary['successful_logins']:,}")
c4.metric('Unique IPs', f"{summary['unique_ips']:,}")
c5.metric('Alerts', f"{len(findings):,}")

left, right = st.columns(2)
with left:
    st.subheader('Threat distribution')
    if findings.empty:
        st.success('No detections for the current dataset.')
    else:
        counts = findings['threat'].value_counts().reset_index()
        counts.columns = ['threat', 'count']
        st.plotly_chart(px.bar(counts, x='threat', y='count', text='count'), use_container_width=True)

with right:
    st.subheader('Top source IPs')
    ips = top_source_ips(df)
    st.plotly_chart(px.bar(ips, x='events', y='source_ip', orientation='h', text='events'), use_container_width=True)

st.subheader('Authentication activity')
timeline = df.set_index('timestamp').resample('30min').size().reset_index(name='events')
st.plotly_chart(px.line(timeline, x='timestamp', y='events', markers=True), use_container_width=True)

st.subheader('Security findings')
if findings.empty:
    st.success('No findings.')
else:
    display = findings.copy()
    display['timestamp'] = display['timestamp'].astype(str)
    st.dataframe(display[['timestamp', 'source_ip', 'username', 'threat', 'severity', 'risk_score', 'evidence']], use_container_width=True, hide_index=True)

st.caption('LogSentinel v1.0 · Synthetic authentication dataset · Defensive research project')