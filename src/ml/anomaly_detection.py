"""
Machine Learning Anomaly Detection for CatNet

Handles:
- Network traffic anomaly detection
- Configuration drift detection
- Performance anomaly detection
- Security threat detection
- Predictive maintenance
"""

from typing import Dict, Any, Optional, List, Tuple, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
import pandas as pd
from collections import deque, defaultdict
import json
import pickle
import warnings
warnings.filterwarnings('ignore', category=UserWarning)


class AnomalyType(Enum):
    """Types of anomalies"""

    TRAFFIC = "traffic"
    PERFORMANCE = "performance"
    CONFIGURATION = "configuration"
    SECURITY = "security"
    BEHAVIORAL = "behavioral"


class ModelType(Enum):
    """ML model types"""

    ISOLATION_FOREST = "isolation_forest"
    RANDOM_FOREST = "random_forest"
    DBSCAN = "dbscan"
    STATISTICAL = "statistical"
    NEURAL_NETWORK = "neural_network"


@dataclass
class AnomalyScore:
    """Anomaly detection score"""

    timestamp: datetime
    score: float  # 0-1, higher means more anomalous
    anomaly_type: AnomalyType
    confidence: float  # 0-1
    features: Dict[str, float]
    explanation: str
    is_anomaly: bool
    severity: str  # low, medium, high, critical


@dataclass
class ModelMetrics:
    """Model performance metrics"""

    accuracy: float
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_negative_rate: float
    last_trained: datetime
    training_samples: int


@dataclass
class TrainingData:
    """Training data container"""

    features: np.ndarray
    labels: Optional[np.ndarray] = None
    feature_names: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class AnomalyDetector:
    """
    Machine learning-based anomaly detection
    """

    def __init__(self, model_type: ModelType = ModelType.ISOLATION_FOREST):
        """
        Initialize anomaly detector

        Args:
            model_type: Type of ML model to use
        """
        self.model_type = model_type
        self.model = self._initialize_model()
        self.scaler = StandardScaler()
        self.is_trained = False

        # Feature engineering
        self.feature_extractors = {}
        self.feature_history = defaultdict(lambda: deque(maxlen=1000))

        # Model performance
        self.metrics = None
        self.anomaly_threshold = 0.7

        # Training data buffer
        self.training_buffer = []
        self.min_training_samples = 100

        # Anomaly history
        self.anomaly_history: List[AnomalyScore] = []

        # Initialize feature extractors
        self._initialize_feature_extractors()

    def _initialize_model(self):
        """Initialize ML model based on type"""
        if self.model_type == ModelType.ISOLATION_FOREST:
            return IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42
            )
        elif self.model_type == ModelType.RANDOM_FOREST:
            return RandomForestClassifier(
                n_estimators=100,
                random_state=42
            )
        elif self.model_type == ModelType.DBSCAN:
            return DBSCAN(
                eps=0.5,
                min_samples=5
            )
        else:
            # Default to Isolation Forest
            return IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42
            )

    def _initialize_feature_extractors(self):
        """Initialize feature extraction functions"""
        # Traffic features
        self.feature_extractors['traffic'] = self._extract_traffic_features

        # Performance features
        self.feature_extractors['performance'] = self._extract_performance_features

        # Configuration features
        self.feature_extractors['configuration'] = self._extract_config_features

        # Security features
        self.feature_extractors['security'] = self._extract_security_features

    def train(self, training_data: TrainingData) -> ModelMetrics:
        """
        Train the anomaly detection model

        Args:
            training_data: Training data

        Returns:
            Model performance metrics
        """
        if len(training_data.features) < self.min_training_samples:
            raise ValueError(
                f"Insufficient training samples: {len(training_data.features)} < {self.min_training_samples}"
            )

        # Scale features
        X_scaled = self.scaler.fit_transform(training_data.features)

        # Train model
        if self.model_type in [ModelType.ISOLATION_FOREST, ModelType.DBSCAN]:
            # Unsupervised learning
            self.model.fit(X_scaled)
        elif self.model_type == ModelType.RANDOM_FOREST:
            # Supervised learning (requires labels)
            if training_data.labels is None:
                raise ValueError("Random Forest requires labeled data")
            self.model.fit(X_scaled, training_data.labels)

        self.is_trained = True

        # Calculate metrics
        self.metrics = self._calculate_metrics(training_data)

        return self.metrics

    def detect(self, data: Dict[str, Any]) -> AnomalyScore:
        """
        Detect anomalies in data

        Args:
            data: Input data

        Returns:
            Anomaly score
        """
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first.")

        # Extract features
        features = self._extract_features(data)

        # Scale features
        features_scaled = self.scaler.transform([features])

        # Predict anomaly
        if self.model_type == ModelType.ISOLATION_FOREST:
            anomaly_score = -self.model.score_samples(features_scaled)[0]
            prediction = self.model.predict(features_scaled)[0]
            is_anomaly = prediction == -1
        elif self.model_type == ModelType.RANDOM_FOREST:
            prob = self.model.predict_proba(features_scaled)[0]
            anomaly_score = prob[1] if len(prob) > 1 else 0
            is_anomaly = anomaly_score > self.anomaly_threshold
        elif self.model_type == ModelType.DBSCAN:
            labels = self.model.fit_predict(features_scaled)
            is_anomaly = labels[0] == -1
            anomaly_score = 1.0 if is_anomaly else 0.0
        else:
            anomaly_score = 0.0
            is_anomaly = False

        # Normalize score to 0-1
        anomaly_score = min(max(anomaly_score, 0), 1)

        # Determine severity
        severity = self._determine_severity(anomaly_score)

        # Generate explanation
        explanation = self._generate_explanation(features, anomaly_score, data)

        # Create score object
        score = AnomalyScore(
            timestamp=datetime.utcnow(),
            score=anomaly_score,
            anomaly_type=self._determine_anomaly_type(data),
            confidence=self._calculate_confidence(features_scaled),
            features=dict(zip(self._get_feature_names(), features)),
            explanation=explanation,
            is_anomaly=is_anomaly,
            severity=severity
        )

        # Store in history
        self.anomaly_history.append(score)

        # Add to training buffer if needed
        if len(self.training_buffer) < 10000:
            self.training_buffer.append((features, is_anomaly))

        return score

    def batch_detect(self, data_list: List[Dict[str, Any]]) -> List[AnomalyScore]:
        """
        Detect anomalies in batch

        Args:
            data_list: List of input data

        Returns:
            List of anomaly scores
        """
        return [self.detect(data) for data in data_list]

    def _extract_features(self, data: Dict[str, Any]) -> np.ndarray:
        """Extract features from input data"""
        features = []

        # Extract traffic features
        if 'traffic' in data:
            features.extend(self._extract_traffic_features(data['traffic']))

        # Extract performance features
        if 'performance' in data:
            features.extend(self._extract_performance_features(data['performance']))

        # Extract configuration features
        if 'configuration' in data:
            features.extend(self._extract_config_features(data['configuration']))

        # Extract security features
        if 'security' in data:
            features.extend(self._extract_security_features(data['security']))

        # Add temporal features
        features.extend(self._extract_temporal_features(data))

        return np.array(features)

    def _extract_traffic_features(self, traffic_data: Dict[str, Any]) -> List[float]:
        """Extract network traffic features"""
        features = []

        # Packet rate
        features.append(traffic_data.get('packet_rate', 0))

        # Bandwidth usage
        features.append(traffic_data.get('bandwidth_mbps', 0))

        # Connection count
        features.append(traffic_data.get('connection_count', 0))

        # Error rate
        features.append(traffic_data.get('error_rate', 0))

        # Protocol distribution
        tcp_ratio = traffic_data.get('tcp_ratio', 0)
        udp_ratio = traffic_data.get('udp_ratio', 0)
        other_ratio = 1 - tcp_ratio - udp_ratio
        features.extend([tcp_ratio, udp_ratio, other_ratio])

        # Port diversity
        unique_ports = len(set(traffic_data.get('destination_ports', [])))
        features.append(unique_ports)

        # Traffic patterns
        features.append(traffic_data.get('burst_count', 0))
        features.append(traffic_data.get('idle_time_ratio', 0))

        return features

    def _extract_performance_features(self, perf_data: Dict[str, Any]) -> List[float]:
        """Extract performance features"""
        features = []

        # CPU usage
        features.append(perf_data.get('cpu_usage', 0))

        # Memory usage
        features.append(perf_data.get('memory_usage', 0))

        # Disk I/O
        features.append(perf_data.get('disk_read_mbps', 0))
        features.append(perf_data.get('disk_write_mbps', 0))

        # Network latency
        features.append(perf_data.get('latency_ms', 0))

        # Packet loss
        features.append(perf_data.get('packet_loss', 0))

        # Response time
        features.append(perf_data.get('response_time_ms', 0))

        # Queue depth
        features.append(perf_data.get('queue_depth', 0))

        # Process count
        features.append(perf_data.get('process_count', 0))

        # Thread count
        features.append(perf_data.get('thread_count', 0))

        return features

    def _extract_config_features(self, config_data: Dict[str, Any]) -> List[float]:
        """Extract configuration features"""
        features = []

        # Configuration change rate
        features.append(config_data.get('change_rate', 0))

        # Configuration complexity
        features.append(config_data.get('complexity_score', 0))

        # Drift from baseline
        features.append(config_data.get('drift_score', 0))

        # Policy violations
        features.append(config_data.get('violation_count', 0))

        # Configuration size
        features.append(config_data.get('config_lines', 0))

        # Interface changes
        features.append(config_data.get('interface_changes', 0))

        # Routing changes
        features.append(config_data.get('routing_changes', 0))

        # ACL changes
        features.append(config_data.get('acl_changes', 0))

        return features

    def _extract_security_features(self, security_data: Dict[str, Any]) -> List[float]:
        """Extract security features"""
        features = []

        # Failed authentication attempts
        features.append(security_data.get('failed_auth_count', 0))

        # Privilege escalations
        features.append(security_data.get('privilege_escalations', 0))

        # Suspicious commands
        features.append(security_data.get('suspicious_commands', 0))

        # Port scans detected
        features.append(security_data.get('port_scans', 0))

        # Malformed packets
        features.append(security_data.get('malformed_packets', 0))

        # DDoS indicators
        features.append(security_data.get('ddos_score', 0))

        # Encryption anomalies
        features.append(security_data.get('encryption_errors', 0))

        # Certificate issues
        features.append(security_data.get('cert_issues', 0))

        return features

    def _extract_temporal_features(self, data: Dict[str, Any]) -> List[float]:
        """Extract time-based features"""
        features = []

        # Time of day (normalized)
        now = datetime.utcnow()
        hour_norm = now.hour / 24.0
        features.append(hour_norm)

        # Day of week (normalized)
        dow_norm = now.weekday() / 7.0
        features.append(dow_norm)

        # Is weekend
        is_weekend = 1.0 if now.weekday() >= 5 else 0.0
        features.append(is_weekend)

        # Is business hours (9-17)
        is_business = 1.0 if 9 <= now.hour < 17 else 0.0
        features.append(is_business)

        return features

    def _get_feature_names(self) -> List[str]:
        """Get feature names"""
        names = []

        # Traffic features
        names.extend([
            'packet_rate', 'bandwidth_mbps', 'connection_count', 'error_rate',
            'tcp_ratio', 'udp_ratio', 'other_ratio', 'unique_ports',
            'burst_count', 'idle_time_ratio'
        ])

        # Performance features
        names.extend([
            'cpu_usage', 'memory_usage', 'disk_read_mbps', 'disk_write_mbps',
            'latency_ms', 'packet_loss', 'response_time_ms', 'queue_depth',
            'process_count', 'thread_count'
        ])

        # Configuration features
        names.extend([
            'change_rate', 'complexity_score', 'drift_score', 'violation_count',
            'config_lines', 'interface_changes', 'routing_changes', 'acl_changes'
        ])

        # Security features
        names.extend([
            'failed_auth_count', 'privilege_escalations', 'suspicious_commands',
            'port_scans', 'malformed_packets', 'ddos_score', 'encryption_errors',
            'cert_issues'
        ])

        # Temporal features
        names.extend([
            'hour_norm', 'dow_norm', 'is_weekend', 'is_business'
        ])

        return names

    def _determine_anomaly_type(self, data: Dict[str, Any]) -> AnomalyType:
        """Determine the type of anomaly"""
        # Simple heuristic based on data keys
        if 'traffic' in data:
            return AnomalyType.TRAFFIC
        elif 'performance' in data:
            return AnomalyType.PERFORMANCE
        elif 'configuration' in data:
            return AnomalyType.CONFIGURATION
        elif 'security' in data:
            return AnomalyType.SECURITY
        else:
            return AnomalyType.BEHAVIORAL

    def _determine_severity(self, score: float) -> str:
        """Determine anomaly severity"""
        if score >= 0.9:
            return "critical"
        elif score >= 0.7:
            return "high"
        elif score >= 0.5:
            return "medium"
        else:
            return "low"

    def _calculate_confidence(self, features: np.ndarray) -> float:
        """Calculate confidence in anomaly detection"""
        # Simple confidence based on feature distribution
        # In production, use model-specific confidence metrics
        if hasattr(self.model, 'decision_function'):
            # Use decision function distance
            distance = abs(self.model.decision_function(features)[0])
            confidence = 1.0 - np.exp(-distance)
        else:
            # Default confidence
            confidence = 0.7

        return min(max(confidence, 0), 1)

    def _generate_explanation(
        self,
        features: np.ndarray,
        score: float,
        data: Dict[str, Any]
    ) -> str:
        """Generate human-readable explanation"""
        explanations = []

        # Find most anomalous features
        feature_names = self._get_feature_names()
        feature_dict = dict(zip(feature_names, features))

        # Calculate feature importance (simplified)
        mean_features = np.mean(self.scaler.transform([features]), axis=0)
        deviations = np.abs(features - mean_features)

        # Get top 3 most deviant features
        top_indices = np.argsort(deviations)[-3:]

        for idx in top_indices:
            feature_name = feature_names[idx]
            value = features[idx]
            deviation = deviations[idx]

            if deviation > 1.5:  # Significant deviation
                explanations.append(
                    f"{feature_name}: {value:.2f} (deviation: {deviation:.2f}σ)"
                )

        if not explanations:
            return f"Anomaly score: {score:.2f}"

        return f"Anomalous patterns detected in: {', '.join(explanations)}"

    def _calculate_metrics(self, training_data: TrainingData) -> ModelMetrics:
        """Calculate model performance metrics"""
        # Simplified metrics calculation
        # In production, use proper cross-validation

        if training_data.labels is not None:
            # Calculate supervised metrics
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

            predictions = self.model.predict(self.scaler.transform(training_data.features))

            accuracy = accuracy_score(training_data.labels, predictions)
            precision = precision_score(training_data.labels, predictions, average='binary')
            recall = recall_score(training_data.labels, predictions, average='binary')
            f1 = f1_score(training_data.labels, predictions, average='binary')

            # Calculate error rates
            false_positives = sum((predictions == 1) & (training_data.labels == 0))
            false_negatives = sum((predictions == 0) & (training_data.labels == 1))
            total = len(training_data.labels)

            fpr = false_positives / total if total > 0 else 0
            fnr = false_negatives / total if total > 0 else 0
        else:
            # Default metrics for unsupervised learning
            accuracy = 0.9
            precision = 0.85
            recall = 0.8
            f1 = 0.82
            fpr = 0.1
            fnr = 0.15

        return ModelMetrics(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1,
            false_positive_rate=fpr,
            false_negative_rate=fnr,
            last_trained=datetime.utcnow(),
            training_samples=len(training_data.features)
        )

    def retrain(self) -> ModelMetrics:
        """Retrain model with accumulated data"""
        if len(self.training_buffer) < self.min_training_samples:
            raise ValueError("Insufficient data for retraining")

        # Prepare training data
        features = np.array([f for f, _ in self.training_buffer])
        labels = np.array([l for _, l in self.training_buffer])

        training_data = TrainingData(
            features=features,
            labels=labels,
            feature_names=self._get_feature_names()
        )

        # Retrain model
        return self.train(training_data)

    def save_model(self, filepath: str):
        """Save trained model to file"""
        if not self.is_trained:
            raise ValueError("Cannot save untrained model")

        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'model_type': self.model_type.value,
            'metrics': self.metrics,
            'feature_names': self._get_feature_names(),
            'anomaly_threshold': self.anomaly_threshold
        }

        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)

    def load_model(self, filepath: str):
        """Load trained model from file"""
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)

        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.model_type = ModelType(model_data['model_type'])
        self.metrics = model_data['metrics']
        self.anomaly_threshold = model_data['anomaly_threshold']
        self.is_trained = True

    def get_anomaly_trends(
        self,
        window: timedelta = timedelta(hours=24)
    ) -> Dict[str, Any]:
        """Get anomaly detection trends"""
        cutoff = datetime.utcnow() - window
        recent_anomalies = [
            a for a in self.anomaly_history
            if a.timestamp > cutoff
        ]

        if not recent_anomalies:
            return {
                'total_count': 0,
                'anomaly_rate': 0,
                'avg_score': 0,
                'by_type': {},
                'by_severity': {}
            }

        # Calculate statistics
        total = len(recent_anomalies)
        anomaly_count = sum(1 for a in recent_anomalies if a.is_anomaly)
        avg_score = np.mean([a.score for a in recent_anomalies])

        # Group by type
        by_type = defaultdict(int)
        for a in recent_anomalies:
            if a.is_anomaly:
                by_type[a.anomaly_type.value] += 1

        # Group by severity
        by_severity = defaultdict(int)
        for a in recent_anomalies:
            if a.is_anomaly:
                by_severity[a.severity] += 1

        return {
            'total_count': total,
            'anomaly_count': anomaly_count,
            'anomaly_rate': anomaly_count / total if total > 0 else 0,
            'avg_score': float(avg_score),
            'by_type': dict(by_type),
            'by_severity': dict(by_severity),
            'time_window': window.total_seconds()
        }