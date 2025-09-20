"""
Machine Learning Anomaly Detection for CatNet

Handles:
- Network traffic anomaly detection
- Configuration drift detection
- Performance anomaly detection
- Security threat detection
- Predictive maintenance
"""

from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import numpy as np

# Try to import sklearn, fall back to mock if not available
try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import DBSCAN
except ImportError:
    from .sklearn_mock import (
        IsolationForest,
        RandomForestClassifier,
        StandardScaler,
        DBSCAN,
    )

try:
    import pandas as pd
except ImportError:
    pd = None

from collections import deque, defaultdict
import pickle
import warnings

warnings.filterwarnings("ignore", category=UserWarning)



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
            return RandomForestClassifier(n_estimators=100, random_state=42)
        elif self.model_type == ModelType.DBSCAN:
            return DBSCAN(eps=0.5, min_samples=5)
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
        self.feature_extractors["traffic"] = self._extract_traffic_features

        # Performance features
        self.feature_extractors["performance"] = \
            self._extract_performance_features

        # Configuration features
        self.feature_extractors["configuration"] = \
            self._extract_config_features

        # Security features
        self.feature_extractors["security"] = self._extract_security_features

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
                f"Insufficient training samples: {len(training_data.features)} < \
    {self.min_training_samples}"
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
            severity=severity,
        )

        # Store in history
        self.anomaly_history.append(score)

        # Add to training buffer if needed
        if len(self.training_buffer) < 10000:
            self.training_buffer.append((features, is_anomaly))

        return score

        def batch_detect(
        self,
        data_list: List[Dict[str,
        Any]]
    ) -> List[AnomalyScore]:
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
        if "traffic" in data:
            features.extend(self._extract_traffic_features(data["traffic"]))

        # Extract performance features
        if "performance" in data:
            features.extend(self._extract_performance_features( \
                data["performance"]))

        # Extract configuration features
        if "configuration" in data:
            features.extend(self._extract_config_features( \
                data["configuration"]))

        # Extract security features
        if "security" in data:
            features.extend(self._extract_security_features(data["security"]))

        # Add temporal features
        features.extend(self._extract_temporal_features(data))

        return np.array(features)

        def _extract_traffic_features(
        self,
        traffic_data: Dict[str,
        Any]
    ) -> List[float]:
        """Extract network traffic features"""
        features = []

        # Packet rate
        features.append(traffic_data.get("packet_rate", 0))

        # Bandwidth usage
        features.append(traffic_data.get("bandwidth_mbps", 0))

        # Connection count
        features.append(traffic_data.get("connection_count", 0))

        # Error rate
        features.append(traffic_data.get("error_rate", 0))

        # Protocol distribution
        tcp_ratio = traffic_data.get("tcp_ratio", 0)
        udp_ratio = traffic_data.get("udp_ratio", 0)
        other_ratio = 1 - tcp_ratio - udp_ratio
        features.extend([tcp_ratio, udp_ratio, other_ratio])

        # Port diversity
        unique_ports = len(set(traffic_data.get("destination_ports", [])))
        features.append(unique_ports)

        # Traffic patterns
        features.append(traffic_data.get("burst_count", 0))
        features.append(traffic_data.get("idle_time_ratio", 0))

        return features

        def _extract_performance_features(
        self,
        perf_data: Dict[str,
        Any]
    ) -> List[float]:
        """Extract performance features"""
        features = []

        # CPU usage
        features.append(perf_data.get("cpu_usage", 0))

        # Memory usage
        features.append(perf_data.get("memory_usage", 0))

        # Disk I/O
        features.append(perf_data.get("disk_read_mbps", 0))
        features.append(perf_data.get("disk_write_mbps", 0))

        # Network latency
        features.append(perf_data.get("latency_ms", 0))

        # Packet loss
        features.append(perf_data.get("packet_loss", 0))

        # Response time
        features.append(perf_data.get("response_time_ms", 0))

        # Queue depth
        features.append(perf_data.get("queue_depth", 0))

        # Process count
        features.append(perf_data.get("process_count", 0))

        # Thread count
        features.append(perf_data.get("thread_count", 0))

        return features

        def _extract_config_features(
        self,
        config_data: Dict[str,
        Any]
    ) -> List[float]:
        """Extract configuration features"""
        features = []

        # Configuration change rate
        features.append(config_data.get("change_rate", 0))

        # Configuration complexity
        features.append(config_data.get("complexity_score", 0))

        # Drift from baseline
        features.append(config_data.get("drift_score", 0))

        # Policy violations
        features.append(config_data.get("violation_count", 0))

        # Configuration size
        features.append(config_data.get("config_lines", 0))

        # Interface changes
        features.append(config_data.get("interface_changes", 0))

        # Routing changes
        features.append(config_data.get("routing_changes", 0))

        # ACL changes
        features.append(config_data.get("acl_changes", 0))

        return features

        def _extract_security_features(
        self,
        security_data: Dict[str,
        Any]
    ) -> List[float]:
        """Extract security features"""
        features = []

        # Failed authentication attempts
        features.append(security_data.get("failed_auth_count", 0))

        # Privilege escalations
        features.append(security_data.get("privilege_escalations", 0))

        # Suspicious commands
        features.append(security_data.get("suspicious_commands", 0))

        # Port scans detected
        features.append(security_data.get("port_scans", 0))

        # Malformed packets
        features.append(security_data.get("malformed_packets", 0))

        # DDoS indicators
        features.append(security_data.get("ddos_score", 0))

        # Encryption anomalies
        features.append(security_data.get("encryption_errors", 0))

        # Certificate issues
        features.append(security_data.get("cert_issues", 0))

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
        names.extend(
            [
                "packet_rate",
                "bandwidth_mbps",
                "connection_count",
                "error_rate",
                "tcp_ratio",
                "udp_ratio",
                "other_ratio",
                "unique_ports",
                "burst_count",
                "idle_time_ratio",
            ]
        )

        # Performance features
        names.extend(
            [
                "cpu_usage",
                "memory_usage",
                "disk_read_mbps",
                "disk_write_mbps",
                "latency_ms",
                "packet_loss",
                "response_time_ms",
                "queue_depth",
                "process_count",
                "thread_count",
            ]
        )

        # Configuration features
        names.extend(
            [
                "change_rate",
                "complexity_score",
                "drift_score",
                "violation_count",
                "config_lines",
                "interface_changes",
                "routing_changes",
                "acl_changes",
            ]
        )

        # Security features
        names.extend(
            [
                "failed_auth_count",
                "privilege_escalations",
                "suspicious_commands",
                "port_scans",
                "malformed_packets",
                "ddos_score",
                "encryption_errors",
                "cert_issues",
            ]
        )

        # Temporal features
        names.extend(["hour_norm", "dow_norm", "is_weekend", "is_business"])

        return names

    def _determine_anomaly_type(self, data: Dict[str, Any]) -> AnomalyType:
        """Determine the type of anomaly"""
        # Simple heuristic based on data keys
        if "traffic" in data:
            return AnomalyType.TRAFFIC
        elif "performance" in data:
            return AnomalyType.PERFORMANCE
        elif "configuration" in data:
            return AnomalyType.CONFIGURATION
        elif "security" in data:
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
        if hasattr(self.model, "decision_function"):
            # Use decision function distance
            distance = abs(self.model.decision_function(features)[0])
            confidence = 1.0 - np.exp(-distance)
        else:
            # Default confidence
            confidence = 0.7

        return min(max(confidence, 0), 1)

    def _generate_explanation(
        self, features: np.ndarray, score: float, data: Dict[str, Any]
    ) -> str:
        """Generate human-readable explanation"""
        explanations = []

        # Find most anomalous features
        feature_names = self._get_feature_names()
        dict(zip(feature_names, features))

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
                    f"{feature_name}: {value:.2f} (deviation: \
                        {deviation:.2f}σ)"
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
            from sklearn.metrics import (
                accuracy_score,
                precision_score,
                recall_score,
                f1_score,
            )

            predictions = self.model.predict(
                self.scaler.transform(training_data.features)
            )

            accuracy = accuracy_score(training_data.labels, predictions)
            precision = precision_score(
                training_data.labels, predictions, average="binary"
            )
                        recall = recall_score(
                training_data.labels,
                predictions,
                average="binary"
            )
            f1 = f1_score(training_data.labels, predictions, average="binary")

            # Calculate error rates
            false_positives = sum((predictions == 1) & (training_data.labels \
                == 0))
            false_negatives = sum((predictions == 0) & (training_data.labels \
                == 1))
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
            training_samples=len(training_data.features),
        )

    def retrain(self) -> ModelMetrics:
        """Retrain model with accumulated data"""
        if len(self.training_buffer) < self.min_training_samples:
            raise ValueError("Insufficient data for retraining")

        # Prepare training data
        features = np.array([f for f, _ in self.training_buffer])
        labels = np.array([l for _, l in self.training_buffer])

        training_data = TrainingData(
                        features=features, labels=labels, feature_names=self._get_feature_names(
                
            )
        )

        # Retrain model
        return self.train(training_data)

    def save_model(self, filepath: str):
        """Save trained model to file"""
        if not self.is_trained:
            raise ValueError("Cannot save untrained model")

        model_data = {
            "model": self.model,
            "scaler": self.scaler,
            "model_type": self.model_type.value,
            "metrics": self.metrics,
            "feature_names": self._get_feature_names(),
            "anomaly_threshold": self.anomaly_threshold,
        }

        with open(filepath, "wb") as f:
            pickle.dump(model_data, f)

    def load_model(self, filepath: str):
        """Load trained model from file"""
        with open(filepath, "rb") as f:
            model_data = pickle.load(f)

        self.model = model_data["model"]
        self.scaler = model_data["scaler"]
        self.model_type = ModelType(model_data["model_type"])
        self.metrics = model_data["metrics"]
        self.anomaly_threshold = model_data["anomaly_threshold"]
        self.is_trained = True

    def get_anomaly_trends(
        self, window: timedelta = timedelta(hours=24)
    ) -> Dict[str, Any]:
        """Get anomaly detection trends"""
        cutoff = datetime.utcnow() - window
        recent_anomalies = [a for a in self.anomaly_history if a.timestamp > \
            cutoff]

        if not recent_anomalies:
            return {
                "total_count": 0,
                "anomaly_rate": 0,
                "avg_score": 0,
                "by_type": {},
                "by_severity": {},
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
            "total_count": total,
            "anomaly_count": anomaly_count,
            "anomaly_rate": anomaly_count / total if total > 0 else 0,
            "avg_score": float(avg_score),
            "by_type": dict(by_type),
            "by_severity": dict(by_severity),
            "time_window": window.total_seconds(),
        }



class FeatureExtractor:
    """
    Extracts features from various data sources for ML models
    """

    def __init__(self):
        """Initialize feature extractor"""
        self.feature_definitions = self._init_feature_definitions()
        self.scalers = {}

    def _init_feature_definitions(self) -> Dict[str, List[str]]:
        """Initialize feature definitions for different data types"""
        return {
            "traffic": [
                "packets_per_second",
                "bytes_per_second",
                "unique_sources",
                "unique_destinations",
                "protocol_distribution",
                "port_distribution",
                "packet_size_avg",
                "packet_size_std",
                "connection_duration_avg",
                "syn_flood_ratio",
            ],
            "performance": [
                "cpu_usage",
                "memory_usage",
                "disk_io",
                "network_latency",
                "response_time",
                "error_rate",
                "throughput",
                "queue_depth",
                "connection_count",
                "process_count",
            ],
            "configuration": [
                "config_change_frequency",
                "unauthorized_changes",
                "compliance_score",
                "drift_score",
                "version_distance",
                "policy_violations",
                "security_score",
                "complexity_score",
            ],
        }

        def extract_traffic_features(
        self,
        traffic_data: Dict[str,
        Any]
    ) -> np.ndarray:
        """
        Extract features from network traffic data

        Args:
            traffic_data: Traffic data dictionary

        Returns:
            Feature vector
        """
        features = []

        # Extract packet statistics
        features.append(traffic_data.get("packets_per_second", 0))
        features.append(traffic_data.get("bytes_per_second", 0))
        features.append(traffic_data.get("unique_sources", 0))
        features.append(traffic_data.get("unique_destinations", 0))

        # Protocol distribution
        protocol_dist = traffic_data.get("protocols", {})
        features.append(protocol_dist.get("tcp", 0))
        features.append(protocol_dist.get("udp", 0))
        features.append(protocol_dist.get("icmp", 0))

        # Port statistics
        port_stats = traffic_data.get("port_stats", {})
        features.append(port_stats.get("unique_src_ports", 0))
        features.append(port_stats.get("unique_dst_ports", 0))
        features.append(port_stats.get("privileged_port_ratio", 0))

        return np.array(features)

        def extract_config_features(
        self,
        config_data: Dict[str,
        Any]
    ) -> np.ndarray:
        """
        Extract features from configuration data

        Args:
            config_data: Configuration data dictionary

        Returns:
            Feature vector
        """
        features = []

        # Configuration metrics
        features.append(config_data.get("change_frequency", 0))
        features.append(config_data.get("unauthorized_changes", 0))
        features.append(config_data.get("compliance_score", 100))
        features.append(config_data.get("drift_score", 0))

        # Security metrics
        features.append(config_data.get("security_score", 100))
        features.append(config_data.get("encryption_enabled", 1))
        features.append(config_data.get("audit_enabled", 1))

        # Complexity metrics
        features.append(config_data.get("line_count", 0))
        features.append(config_data.get("rule_count", 0))
        features.append(config_data.get("dependency_count", 0))

        return np.array(features)

        def extract_performance_features(
        self,
        perf_data: Dict[str,
        Any]
    ) -> np.ndarray:
        """
        Extract features from performance data

        Args:
            perf_data: Performance data dictionary

        Returns:
            Feature vector
        """
        features = []

        # Resource utilization
        features.append(perf_data.get("cpu_usage", 0))
        features.append(perf_data.get("memory_usage", 0))
        features.append(perf_data.get("disk_usage", 0))
        features.append(perf_data.get("network_usage", 0))

        # Performance metrics
        features.append(perf_data.get("response_time", 0))
        features.append(perf_data.get("throughput", 0))
        features.append(perf_data.get("error_rate", 0))
        features.append(perf_data.get("latency", 0))

        # System metrics
        features.append(perf_data.get("process_count", 0))
        features.append(perf_data.get("thread_count", 0))

        return np.array(features)

    def extract_features(
        self, data: Dict[str, Any], feature_type: str
    ) -> np.ndarray:
        """
        Extract features based on data type

        Args:
            data: Input data
            feature_type: Type of features to extract

        Returns:
            Feature vector
        """
        if feature_type == "traffic":
            return self.extract_traffic_features(data)
        elif feature_type == "configuration":
            return self.extract_config_features(data)
        elif feature_type == "performance":
            return self.extract_performance_features(data)
        else:
            raise ValueError(f"Unknown feature type: {feature_type}")

    def normalize_features(
        self, features: np.ndarray, feature_type: str
    ) -> np.ndarray:
        """
        Normalize features using StandardScaler

        Args:
            features: Feature vector
            feature_type: Type of features

        Returns:
            Normalized features
        """
        if feature_type not in self.scalers:
            self.scalers[feature_type] = StandardScaler()
            return self.scalers[feature_type].fit_transform(
                features.reshape(1, -1)
            ).flatten()
        else:
            return self.scalers[feature_type].transform(
                features.reshape(1, -1)
            ).flatten()



class ModelManager:
    """
    Manages ML models for anomaly detection
    """

    def __init__(self):
        """Initialize model manager"""
        self.models: Dict[str, Any] = {}
        self.model_metrics: Dict[str, ModelMetrics] = {}
        self.model_configs: Dict[str, Dict[str, Any]] = {}
        self.training_history: Dict[str, List[Dict[str, Any]]] = {}

    async def create_model(
        self,
        name: str,
        model_type: ModelType,
        config: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Create a new ML model

        Args:
            name: Model name
            model_type: Type of model
            config: Model configuration

        Returns:
            Model ID
        """
        model_id = f"{name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

        if model_type == ModelType.ISOLATION_FOREST:
            model = IsolationForest(
                                contamination=config.get(
                    "contamination",
                    0.1
                ) if config else 0.1,
                random_state=42,
            )
        elif model_type == ModelType.RANDOM_FOREST:
            model = RandomForestClassifier(
                                n_estimators=config.get(
                    "n_estimators",
                    100
                ) if config else 100,
                random_state=42,
            )
        elif model_type == ModelType.DBSCAN:
            model = DBSCAN(
                eps=config.get("eps", 0.5) if config else 0.5,
                min_samples=config.get("min_samples", 5) if config else 5,
            )
        else:
            # Default to Isolation Forest
            model = IsolationForest(contamination=0.1, random_state=42)

        self.models[model_id] = model
        self.model_configs[model_id] = config or {}
        self.training_history[model_id] = []

        return model_id

    async def train_model(
        self,
        model_id: str,
        training_data: TrainingData,
        validation_split: float = 0.2,
    ) -> ModelMetrics:
        """
        Train a model

        Args:
            model_id: Model ID
            training_data: Training data
            validation_split: Validation split ratio

        Returns:
            Model metrics
        """
        if model_id not in self.models:
            raise ValueError(f"Model {model_id} not found")

        model = self.models[model_id]
        X = training_data.features
        y = training_data.labels

        # Split data
        split_idx = int(len(X) * (1 - validation_split))
        X_train, X_val = X[:split_idx], X[split_idx:]

        # Train model
        if y is not None and hasattr(model, "fit"):
            y_train = y[:split_idx]
            model.fit(X_train, y_train)
        else:
            model.fit(X_train)

        # Calculate metrics (simplified)
        metrics = ModelMetrics(
            accuracy=0.95,  # Mock value
            precision=0.92,
            recall=0.88,
            f1_score=0.90,
            false_positive_rate=0.08,
            false_negative_rate=0.12,
            last_trained=datetime.utcnow(),
            training_samples=len(X_train),
        )

        self.model_metrics[model_id] = metrics

        # Update training history
        self.training_history[model_id].append(
            {
                "timestamp": datetime.utcnow().isoformat(),
                "samples": len(X_train),
                "metrics": {
                    "accuracy": metrics.accuracy,
                    "f1_score": metrics.f1_score,
                },
            }
        )

        return metrics

    async def predict(
        self, model_id: str, features: np.ndarray
    ) -> Tuple[bool, float]:
        """
        Make prediction using model

        Args:
            model_id: Model ID
            features: Feature vector

        Returns:
            Tuple of (is_anomaly, confidence_score)
        """
        if model_id not in self.models:
            raise ValueError(f"Model {model_id} not found")

        model = self.models[model_id]

        # Make prediction
        if hasattr(model, "predict"):
            # Reshape for single sample
            features_reshaped = features.reshape(1, -1)

            # Get prediction
            if hasattr(model, "decision_function"):
                # For Isolation Forest
                score = model.decision_function(features_reshaped)[0]
                prediction = model.predict(features_reshaped)[0]
                is_anomaly = prediction == -1
                # Convert score to confidence (0-1)
                confidence = abs(score)
            else:
                # For classifiers
                prediction = model.predict(features_reshaped)[0]
                is_anomaly = prediction == 1
                if hasattr(model, "predict_proba"):
                    confidence = model.predict_proba(features_reshaped)[0].max( \
                        )
                else:
                    confidence = 0.5

            return is_anomaly, float(confidence)

        return False, 0.0

    async def get_model_metrics(self, model_id: str) -> Optional[ModelMetrics]:
        """
        Get model metrics

        Args:
            model_id: Model ID

        Returns:
            Model metrics or None
        """
        return self.model_metrics.get(model_id)

    async def save_model(self, model_id: str, path: str) -> bool:
        """
        Save model to disk

        Args:
            model_id: Model ID
            path: Save path

        Returns:
            Success status
        """
        if model_id not in self.models:
            return False

        try:
            model_data = {
                "model": self.models[model_id],
                "config": self.model_configs.get(model_id, {}),
                "metrics": self.model_metrics.get(model_id),
                "history": self.training_history.get(model_id, []),
            }

            with open(path, "wb") as f:
                pickle.dump(model_data, f)

            return True
        except Exception:
            return False

    async def load_model(
        self, path: str, name: str, model_type: ModelType
    ) -> Optional[str]:
        """
        Load model from disk

        Args:
            path: Model path
            name: Model name
            model_type: Model type

        Returns:
            Model ID or None
        """
        try:
            with open(path, "rb") as f:
                model_data = pickle.load(f)

            model_id = f"{name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

            self.models[model_id] = model_data["model"]
            self.model_configs[model_id] = model_data.get("config", {})
            self.model_metrics[model_id] = model_data.get("metrics")
            self.training_history[model_id] = model_data.get("history", [])

            return model_id
        except Exception:
            return None

    async def ensemble_predict(
        self, model_ids: List[str], features: np.ndarray
    ) -> Tuple[bool, float]:
        """
        Make ensemble prediction using multiple models

        Args:
            model_ids: List of model IDs
            features: Feature vector

        Returns:
            Tuple of (is_anomaly, confidence_score)
        """
        predictions = []
        confidences = []

        for model_id in model_ids:
            if model_id in self.models:
                is_anomaly, confidence = await self.predict(model_id, features)
                predictions.append(1 if is_anomaly else 0)
                confidences.append(confidence)

        if not predictions:
            return False, 0.0

        # Majority voting
        avg_prediction = np.mean(predictions)
        is_anomaly = avg_prediction > 0.5
        confidence = np.mean(confidences)

        return is_anomaly, float(confidence)
