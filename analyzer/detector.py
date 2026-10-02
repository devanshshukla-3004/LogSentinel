from __future__ import annotations
import pandas as pd

DEFAULT_WINDOW_MINUTES = 10

def _window(df, ip, end_time, minutes):
    start = end_time - pd.Timedelta(minutes=minutes)
    return df[(df['source_ip'] == ip) & (df['timestamp'] >= start) & (df['timestamp'] <= end_time)]

def detect_threats(df: pd.DataFrame, window_minutes: int = DEFAULT_WINDOW_MINUTES, brute_force_threshold: int = 5, repeated_failure_threshold: int = 3, spray_user_threshold: int = 5) -> pd.DataFrame:
    findings = []
    for ip, group in df.groupby('source_ip'):
        group = group.sort_values('timestamp')
        for _, event in group.iterrows():
            t = event['timestamp']
            w = _window(df, ip, t, window_minutes)
            failures = w[w['event_type'] == 'FAILED_LOGIN']
            successes = w[w['event_type'] == 'SUCCESSFUL_LOGIN']
            if len(failures) >= brute_force_threshold:
                findings.append({'timestamp': t, 'source_ip': ip, 'username': event['username'], 'threat': 'Brute-force burst', 'severity': 'HIGH', 'evidence': f'{len(failures)} failed logins within {window_minutes} minutes'})
            distinct_users = failures['username'].nunique()
            if distinct_users >= spray_user_threshold:
                findings.append({'timestamp': t, 'source_ip': ip, 'username': event['username'], 'threat': 'Password spraying', 'severity': 'HIGH', 'evidence': f'Failures against {distinct_users} distinct users within {window_minutes} minutes'})
            if len(failures) >= repeated_failure_threshold and len(successes) >= 1:
                findings.append({'timestamp': t, 'source_ip': ip, 'username': event['username'], 'threat': 'Failure → success sequence', 'severity': 'HIGH', 'evidence': f'{len(failures)} failures followed by a successful authentication in the window'})
    for _, event in df.iterrows():
        hour = event['timestamp'].hour
        if hour < 6 or hour >= 23:
            findings.append({'timestamp': event['timestamp'], 'source_ip': event['source_ip'], 'username': event['username'], 'threat': 'Off-hours authentication', 'severity': 'LOW', 'evidence': f"Authentication occurred at {hour:02d}:00 UTC"})
    result = pd.DataFrame(findings)
    if result.empty:
        return pd.DataFrame(columns=['timestamp', 'source_ip', 'username', 'threat', 'severity', 'evidence'])
    return result.drop_duplicates().sort_values('timestamp').reset_index(drop=True)
