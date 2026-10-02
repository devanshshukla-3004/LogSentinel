from __future__ import annotations
import pandas as pd

def summarize_events(df: pd.DataFrame) -> dict:
    return {
        'total_events': int(len(df)),
        'failed_logins': int((df['event_type'] == 'FAILED_LOGIN').sum()),
        'successful_logins': int((df['event_type'] == 'SUCCESSFUL_LOGIN').sum()),
        'unique_ips': int(df['source_ip'].nunique()),
        'unique_users': int(df['username'].nunique()),
    }

def top_source_ips(df: pd.DataFrame, limit: int = 10) -> pd.DataFrame:
    return (df.groupby('source_ip').size().reset_index(name='events').sort_values('events', ascending=False).head(limit))
