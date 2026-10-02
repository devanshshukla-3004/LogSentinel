import pandas as pd

SEVERITY_POINTS = {'LOW': 15, 'MEDIUM': 40, 'HIGH': 75}

def score_findings(findings: pd.DataFrame) -> pd.DataFrame:
    out = findings.copy()
    out['risk_score'] = out['severity'].map(SEVERITY_POINTS).fillna(0).astype(int)
    return out
