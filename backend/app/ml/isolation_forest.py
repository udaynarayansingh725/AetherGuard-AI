import numpy as np
import pandas as pd
from datetime import datetime
from typing import Dict, Any, List, Tuple
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .feature_extractor import extract_features, PORT_RISK_MAP
from ..schemas.models import Threat

class ThreatDetector:
    def __init__(self, contamination: float = 0.05, n_estimators: int = 100):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=42,
            n_jobs=-1
        )
        self.is_fitted = False
        self._initialize_baseline_model()

    def _initialize_baseline_model(self):
        """Pre-fits the Isolation Forest with a baseline distribution of normal network telemetry."""
        np.random.seed(42)
        n_samples = 2500
        
        # 95% normal traffic
        normal_failed_logins = np.random.choice([0, 1, 2], size=n_samples, p=[0.85, 0.12, 0.03])
        normal_requests = np.random.exponential(scale=150, size=n_samples) + 10
        normal_ports = np.random.choice([80, 443, 8080], size=n_samples, p=[0.45, 0.50, 0.05])
        normal_port_risk = np.array([PORT_RISK_MAP.get(p, 0.35) for p in normal_ports])
        normal_accounts = np.ones(n_samples)
        normal_failure_rate = normal_failed_logins / normal_requests
        normal_external = np.random.choice([0.0, 1.0], size=n_samples, p=[0.7, 0.3])

        X_baseline = np.column_stack([
            normal_failed_logins,
            normal_requests,
            normal_port_risk,
            normal_accounts,
            normal_failure_rate,
            normal_external
        ])

        # Seed 5% anomalies
        n_anom = int(n_samples * 0.05)
        anom_failed = np.random.randint(50, 200, size=n_anom)
        anom_req = np.random.randint(500, 15000, size=n_anom)
        anom_port_risk = np.random.choice([0.85, 0.90, 0.95], size=n_anom)
        anom_accounts = np.random.randint(3, 25, size=n_anom)
        anom_failure_rate = anom_failed / np.maximum(anom_req, 1)
        anom_external = np.ones(n_anom)

        X_anom = np.column_stack([
            anom_failed,
            anom_req,
            anom_port_risk,
            anom_accounts,
            anom_failure_rate,
            anom_external
        ])

        X_all = np.vstack([X_baseline, X_anom])
        X_scaled = self.scaler.fit_transform(X_all)
        self.model.fit(X_scaled)
        self.is_fitted = True

    def classify_threat(self, row: pd.Series, score: float) -> Tuple[str, str, str]:
        """
        Classifies threat type, severity risk level, and target service.
        """
        failed = row.get('failed_logins', 0)
        req = row.get('requests', 0)
        port = int(row.get('port', 80))
        accounts = row.get('accounts_targeted', 1)

        # Risk level
        if score >= 0.85:
            risk = "Critical"
        elif score >= 0.75:
            risk = "High"
        elif score >= 0.55:
            risk = "Medium"
        else:
            risk = "Low"

        # Threat type heuristics
        if failed >= 20 and port in [22, 21, 3389]:
            threat_type = "Brute Force"
            service = "OpenSSH 8.9" if port == 22 else ("vsftpd" if port == 21 else "WinRDP")
        elif req >= 8000:
            threat_type = "DoS-like Pattern"
            service = "Nginx Gateway" if port in [80, 443] else "Application Server"
        elif accounts >= 4 and failed >= 10:
            threat_type = "Abnormal Login"
            service = "Enterprise Directory / LDAP"
        elif port in [80, 443, 8080] and failed >= 5:
            threat_type = "Suspicious IP Behaviour"
            service = "Apache Tomcat / API"
        elif req >= 2000 and failed == 0:
            threat_type = "Port Scanning"
            service = "Subnet Sweep"
        else:
            threat_type = "Suspicious Outlier" if risk in ["Critical", "High"] else "Normal Baseline"
            service = "Internal Cluster"

        return threat_type, risk, service

    def analyze_logs(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Runs Isolation Forest anomaly detection on input log DataFrame.
        """
        X, feature_names = extract_features(df)
        X_scaled = self.scaler.transform(X)
        
        # Decision function: lower scores indicate greater anomaly deviation
        raw_scores = self.model.decision_function(X_scaled)
        predictions = self.model.predict(X_scaled) # -1 for anomaly, 1 for inlier
        
        # Map raw decision score into normalized [0.0, 1.0] anomaly metric
        # raw_scores typically range from [-0.3, +0.3]
        anomaly_scores = np.clip(0.5 - (raw_scores * 1.8), 0.05, 0.99)
        anomaly_scores = np.round(anomaly_scores, 2)
        
        df_results = df.copy()
        df_results['anomaly_score'] = anomaly_scores
        df_results['is_anomaly'] = predictions == -1

        # Calculate feature correlations / importance for explainability
        feature_importance = {}
        for idx, feat in enumerate(feature_names):
            if np.std(X[:, idx]) > 0:
                corr = np.corrcoef(X[:, idx], anomaly_scores)[0, 1]
                feature_importance[feat] = round(float(max(corr, 0.05)), 2)
            else:
                feature_importance[feat] = 0.10

        # Normalize feature importance weights to sum to 1.0
        tot = sum(feature_importance.values()) or 1.0
        feature_importance = {k: round(v / tot, 2) for k, v in feature_importance.items()}

        # Build list of detected threat records
        threats: List[Threat] = []
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Focus on anomalies or high scores
        anomalous_rows = df_results[df_results['anomaly_score'] >= 0.50].sort_values(
            by='anomaly_score', ascending=False
        )

        for i, (_, row) in enumerate(anomalous_rows.head(25).iterrows()):
            score = float(row['anomaly_score'])
            threat_type, risk, target_service = self.classify_threat(row, score)
            
            t_id = f"THR-{9100 + i}"
            threats.append(Threat(
                id=t_id,
                sourceIp=str(row['source_ip']),
                destIp=str(row['dest_ip']),
                port=int(row['port']),
                protocol=str(row['protocol']),
                requests=int(row['requests']),
                failedLogins=int(row['failed_logins']),
                anomalyScore=score,
                threatType=threat_type,
                risk=risk,
                timestamp=now_str,
                status="Active" if risk in ["Critical", "High"] else "Investigating",
                accountsTargeted=int(row.get('accounts_targeted', 1)),
                country="INTERNAL" if str(row['source_ip']).startswith("10.") else "EXT-WAN",
                targetService=target_service
            ))

        critical_count = int(np.sum(anomaly_scores >= 0.85))
        anomalies_count = int(np.sum(predictions == -1))

        return {
            "model_used": f"IsolationForest (contamination={self.contamination}, n_estimators={self.n_estimators})",
            "processed_rows": len(df),
            "anomalies_detected": anomalies_count,
            "critical_risks": critical_count,
            "feature_importance": feature_importance,
            "threats": threats
        }

# Global singleton detector
detector = ThreatDetector()
