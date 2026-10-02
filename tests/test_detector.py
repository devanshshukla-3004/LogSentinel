import pandas as pd
from analyzer.detector import detect_threats

def test_bruteforce_detection():
    base = pd.Timestamp('2026-10-01T10:00:00Z')
    df = pd.DataFrame([{'timestamp': base + pd.Timedelta(minutes=i), 'source_ip': '10.0.0.50', 'username': 'admin', 'event_type': 'FAILED_LOGIN'} for i in range(5)])
    assert 'Brute-force burst' in set(detect_threats(df)['threat'])

def test_password_spraying_detection():
    base = pd.Timestamp('2026-10-01T10:00:00Z')
    df = pd.DataFrame([{'timestamp': base + pd.Timedelta(minutes=i), 'source_ip': '10.0.0.60', 'username': f'user{i}', 'event_type': 'FAILED_LOGIN'} for i in range(5)])
    assert 'Password spraying' in set(detect_threats(df)['threat'])

def test_failure_then_success_detection():
    base = pd.Timestamp('2026-10-01T10:00:00Z')
    rows = [{'timestamp': base + pd.Timedelta(minutes=i), 'source_ip': '10.0.0.70', 'username': 'admin', 'event_type': 'FAILED_LOGIN'} for i in range(3)]
    rows.append({'timestamp': base + pd.Timedelta(minutes=4), 'source_ip': '10.0.0.70', 'username': 'admin', 'event_type': 'SUCCESSFUL_LOGIN'})
    assert 'Failure → success sequence' in set(detect_threats(pd.DataFrame(rows))['threat'])
