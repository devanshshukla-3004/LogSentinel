from __future__ import annotations
from pathlib import Path
import pandas as pd

REQUIRED_COLUMNS = {'timestamp', 'source_ip', 'username', 'event_type'}

def load_logs(source: str | Path) -> pd.DataFrame:
    df = pd.read_csv(source)
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(f'Missing required columns: {sorted(missing)}')
    df = df.copy()
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
    if df['timestamp'].isna().any():
        raise ValueError('One or more timestamps could not be parsed.')
    for column in ('source_ip', 'username', 'event_type'):
        df[column] = df[column].astype(str).str.strip()
    df['event_type'] = df['event_type'].str.upper()
    allowed = {'FAILED_LOGIN', 'SUCCESSFUL_LOGIN'}
    bad = set(df['event_type']) - allowed
    if bad:
        raise ValueError(f'Unsupported event_type values: {sorted(bad)}')
    return df.sort_values('timestamp').reset_index(drop=True)
