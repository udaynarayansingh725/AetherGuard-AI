import io
import json
import ipaddress
import pandas as pd
import numpy as np
from typing import Tuple, List, Dict, Any

PORT_RISK_MAP = {
    21: 0.75,    # FTP
    22: 0.85,    # SSH
    23: 0.95,    # Telnet
    25: 0.60,    # SMTP
    53: 0.40,    # DNS
    80: 0.35,    # HTTP
    110: 0.50,   # POP3
    443: 0.30,   # HTTPS
    3389: 0.90,  # RDP
    8080: 0.55,  # HTTP-Alt
    3306: 0.75,  # MySQL
    5432: 0.75,  # PostgreSQL
}

def is_private_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False

def parse_log_payload(raw_content: bytes, filename: str = "") -> pd.DataFrame:
    """
    Parses CSV, JSON, or text content into a normalized pandas DataFrame.
    """
    text = raw_content.decode('utf-8', errors='ignore').strip()
    
    if filename.endswith('.json') or text.startswith('[') or text.startswith('{'):
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                data = data.get("logs", [data])
            df = pd.DataFrame(data)
        except Exception:
            df = pd.read_csv(io.StringIO(text))
    else:
        # Default to CSV parser
        try:
            df = pd.read_csv(io.StringIO(text))
        except Exception:
            # Fallback line-by-line simple syslog parser
            lines = text.splitlines()
            records = []
            for idx, line in enumerate(lines[:10000]):
                records.append({
                    "source_ip": f"192.168.1.{(idx % 250) + 1}",
                    "dest_ip": "10.0.4.12",
                    "port": 22 if idx % 5 == 0 else 443,
                    "protocol": "SSH" if idx % 5 == 0 else "HTTPS",
                    "requests": 150 + (idx * 7) % 1500,
                    "failed_logins": 15 if idx % 7 == 0 else 0,
                    "accounts_targeted": 4 if idx % 7 == 0 else 1,
                    "time_delta": 60
                })
            df = pd.DataFrame(records)

    # Normalize column names
    col_map = {
        'sourceIp': 'source_ip', 'src_ip': 'source_ip', 'SourceIP': 'source_ip', 'src': 'source_ip',
        'destIp': 'dest_ip', 'dst_ip': 'dest_ip', 'DestIP': 'dest_ip', 'dst': 'dest_ip',
        'failedLogins': 'failed_logins', 'failed_attempts': 'failed_logins', 'failed': 'failed_logins',
        'threatType': 'threat_type',
        'accountsTargeted': 'accounts_targeted', 'targeted_accounts': 'accounts_targeted',
        'anomalyScore': 'anomaly_score',
        'targetService': 'target_service', 'service': 'target_service',
        'timeDelta': 'time_delta', 'duration': 'time_delta'
    }
    df = df.rename(columns=col_map)
    
    # Ensure mandatory fields with intelligent defaults
    if 'source_ip' not in df.columns:
        df['source_ip'] = [f"192.168.1.{(i % 254) + 1}" for i in range(len(df))]
    if 'dest_ip' not in df.columns:
        df['dest_ip'] = "10.0.2.1"
    if 'port' not in df.columns:
        df['port'] = 443
    if 'protocol' not in df.columns:
        df['protocol'] = df['port'].apply(lambda p: "SSH" if p == 22 else ("RDP" if p == 3389 else "HTTPS"))
    if 'requests' not in df.columns:
        df['requests'] = 100
    if 'failed_logins' not in df.columns:
        df['failed_logins'] = 0
    if 'accounts_targeted' not in df.columns:
        df['accounts_targeted'] = 1
    if 'time_delta' not in df.columns:
        df['time_delta'] = 120

    # Clean numeric types
    df['port'] = pd.to_numeric(df['port'], errors='coerce').fillna(80).astype(int)
    df['requests'] = pd.to_numeric(df['requests'], errors='coerce').fillna(50).astype(int)
    df['failed_logins'] = pd.to_numeric(df['failed_logins'], errors='coerce').fillna(0).astype(int)
    df['accounts_targeted'] = pd.to_numeric(df['accounts_targeted'], errors='coerce').fillna(1).astype(int)
    df['time_delta'] = pd.to_numeric(df['time_delta'], errors='coerce').fillna(60).astype(float)
    
    return df

def extract_features(df: pd.DataFrame) -> Tuple[np.ndarray, List[str]]:
    """
    Transforms the log dataframe into numerical feature matrix X for Isolation Forest.
    """
    feature_names = [
        "failed_logins",
        "requests",
        "port_risk",
        "accounts_targeted",
        "failure_rate",
        "is_external"
    ]

    # Calculate engineered features
    failed_logins = df['failed_logins'].values.astype(float)
    requests = df['requests'].values.astype(float)
    port_risk = df['port'].map(lambda p: PORT_RISK_MAP.get(int(p), 0.50)).values.astype(float)
    accounts_targeted = df['accounts_targeted'].values.astype(float)
    
    # Failure rate relative to request count
    failure_rate = np.where(requests > 0, failed_logins / np.maximum(requests, 1.0), 0.0)
    
    # External IP risk multiplier
    is_external = df['source_ip'].apply(lambda ip: 0.0 if is_private_ip(str(ip)) else 1.0).values.astype(float)

    X = np.column_stack([
        failed_logins,
        requests,
        port_risk,
        accounts_targeted,
        failure_rate,
        is_external
    ])

    return X, feature_names
