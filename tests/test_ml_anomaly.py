import pytest
import numpy as np
from datetime import datetime, timedelta
from src.ml.anomaly_detection import (
    AnomalyDetector,
    ModelType,
    TrainingData,
    AnomalyScore,
    ModelManager,
    FeatureExtractor,
)


class TestFeatureExtractor:
    def test_extract_traffic_features(self):
        extractor = FeatureExtractor()

        traffic_data = {
            "packet_count": 1000,
            "byte_count": 50000,
            "flow_count": 50,
            "error_rate": 0.02,
            "protocol_distribution": {"TCP": 0.7, "UDP": 0.2, "ICMP": 0.1},
            "port_distribution": {"80": 0.3,
                                  "443": 0.4
                                  "22": 0.1
                                  "other": 0.2}

            "avg_packet_size": 500,
            "packet_rate": 100,
        }

        features = extractor.extract_traffic_features(traffic_data)

        assert len(features) == 8
        assert features[0] == 1000  # packet_count
        assert features[1] == 50000  # byte_count
        assert features[2] == 50  # flow_count
        assert features[3] == 0.02  # error_rate

    def test_extract_config_features(self):
        extractor = FeatureExtractor()

        config_data = {
            "line_count": 500,
            "interface_count": 24,
            "acl_count": 10,
            "route_count": 100,
            "vlan_count": 20,
            "has_encryption": True,
            "has_aaa": True,
            "has_logging": True,
            "complexity_score": 0.75,
        }

        features = extractor.extract_config_features(config_data)

        assert len(features) == 9
        assert features[0] == 500  # line_count
        assert features[5] == 1  # has_encryption (True -> 1)
        assert features[8] == 0.75  # complexity_score

    def test_extract_performance_features(self):
        extractor = FeatureExtractor()

        perf_data = {
            "cpu_usage": 45.5,
            "memory_usage": 62.3,
            "interface_utilization": 78.9,
            "packet_loss": 0.001,
            "latency": 25.5,
            "jitter": 2.3,
            "temperature": 42.0,
        }

        features = extractor.extract_performance_features(perf_data)

        assert len(features) == 7
        assert features[0] == 45.5  # cpu_usage
        assert features[4] == 25.5  # latency


class TestAnomalyDetector:
    def test_initialization(self):
        detector = AnomalyDetector(ModelType.ISOLATION_FOREST)

        assert detector.model_type == ModelType.ISOLATION_FOREST
        assert detector.model is not None
        assert not detector.is_trained

    def test_train_isolation_forest(self):
        detector = AnomalyDetector(ModelType.ISOLATION_FOREST)

        # Create training data
        np.random.seed(42)
        normal_data = np.random.randn(100, 5)

        training_data = TrainingData(
            data=normal_data.tolist(),
            feature_names=["f1", "f2", "f3", "f4", "f5"],
            timestamps=[datetime.now()] * 100,
            labels=[0] * 100,  # All normal
        )

        metrics = detector.train(training_data)

        assert detector.is_trained
        assert metrics.accuracy > 0
        assert metrics.training_time > 0
        assert metrics.feature_importance is not None

    def test_detect_anomaly(self):
        detector = AnomalyDetector(ModelType.ISOLATION_FOREST)

        # Train model
        np.random.seed(42)
        normal_data = np.random.randn(100, 5)

        training_data = TrainingData(
            data=normal_data.tolist(),
            feature_names=["f1", "f2", "f3", "f4", "f5"],
            timestamps=[datetime.now()] * 100,
            labels=[0] * 100,
        )

        detector.train(training_data)

        # Test normal data
        normal_sample = {
            "packet_count": 1000,
            "byte_count": 50000,
            "flow_count": 50,
            "error_rate": 0.02,
            "protocol_distribution": {"TCP": 0.7},
        }

        score = detector.detect(normal_sample)

        assert isinstance(score, AnomalyScore)
        assert 0 <= score.score <= 1
        assert score.timestamp is not None

    def test_detect_without_training(self):
        detector = AnomalyDetector(ModelType.ISOLATION_FOREST)

        with pytest.raises(ValueError, match="Model not trained"):
            detector.detect({"test": "data"})

    def test_random_forest_model(self):
        detector = AnomalyDetector(ModelType.RANDOM_FOREST)

        # Create mixed training data
        np.random.seed(42)
        normal_data = np.random.randn(80, 5)
        anomaly_data = np.random.randn(20, 5) + 3  # Shifted distribution

        all_data = np.vstack([normal_data, anomaly_data])
        labels = [0] * 80 + [1] * 20  # 0 = normal, 1 = anomaly

        training_data = TrainingData(
            data=all_data.tolist(),
            feature_names=["f1", "f2", "f3", "f4", "f5"],
            timestamps=[datetime.now()] * 100,
            labels=labels,
        )

        metrics = detector.train(training_data)

        assert detector.is_trained
        assert metrics.precision > 0
        assert metrics.recall > 0
        assert metrics.f1_score > 0


class TestModelManager:
    @pytest.mark.asyncio
    async def test_create_model(self):
        manager = ModelManager()

        model_id = await manager.create_model(
            name="test_model",
            model_type=ModelType.ISOLATION_FOREST,
            description="Test anomaly detection model",
        )

        assert model_id in manager.models
        assert manager.models[model_id].name == "test_model"

    @pytest.mark.asyncio
    async def test_train_model(self):
        manager = ModelManager()

        model_id = await manager.create_model(
            name="test_model", model_type=ModelType.ISOLATION_FOREST
        )

        # Create training data
        np.random.seed(42)
        data = np.random.randn(100, 5)

        training_data = TrainingData(
            data=data.tolist(),
            feature_names=["f1", "f2", "f3", "f4", "f5"],
            timestamps=[datetime.now()] * 100,
            labels=[0] * 100,
        )

        success = await manager.train_model(model_id, training_data)

        assert success
        assert manager.models[model_id].is_trained
        assert manager.models[model_id].last_trained is not None

    @pytest.mark.asyncio
    async def test_predict_with_model(self):
        manager = ModelManager()

        model_id = await manager.create_model(
            name="test_model", model_type=ModelType.ISOLATION_FOREST
        )

        # Train model
        np.random.seed(42)
        data = np.random.randn(100, 5)

        training_data = TrainingData(
            data=data.tolist(),
            feature_names=["f1", "f2", "f3", "f4", "f5"],
            timestamps=[datetime.now()] * 100,
            labels=[0] * 100,
        )

        await manager.train_model(model_id, training_data)

        # Make prediction
        test_data = {
            "packet_count": 1000,
            "byte_count": 50000,
            "flow_count": 50,
            "error_rate": 0.02,
            "protocol_distribution": {"TCP": 0.7},
        }

        score = await manager.predict(model_id, test_data)

        assert score is not None
        assert 0 <= score.score <= 1

    @pytest.mark.asyncio
    async def test_get_model_metrics(self):
        manager = ModelManager()

        model_id = await manager.create_model(
            name="test_model", model_type=ModelType.RANDOM_FOREST
        )

        # Train model with labeled data
        np.random.seed(42)
        normal_data = np.random.randn(80, 5)
        anomaly_data = np.random.randn(20, 5) + 3

        all_data = np.vstack([normal_data, anomaly_data])
        labels = [0] * 80 + [1] * 20

        training_data = TrainingData(
            data=all_data.tolist(),
            feature_names=["f1", "f2", "f3", "f4", "f5"],
            timestamps=[datetime.now()] * 100,
            labels=labels,
        )

        await manager.train_model(model_id, training_data)

        metrics = await manager.get_model_metrics(model_id)

        assert metrics is not None
        assert metrics.accuracy > 0
        assert metrics.model_id == model_id

    @pytest.mark.asyncio
    async def test_ensemble_prediction(self):
        manager = ModelManager()

        # Create multiple models
        model_ids = []
        for model_type in [ModelType.ISOLATION_FOREST,
                           ModelType.RANDOM_FOREST]:
            model_id = await manager.create_model(
                name=f"model_{model_type.value}", model_type=model_type
            )
            model_ids.append(model_id)

            # Train each model
            np.random.seed(42)
            data = np.random.randn(100, 5)

            training_data = TrainingData(
                data=data.tolist(),
                feature_names=["f1", "f2", "f3", "f4", "f5"],
                timestamps=[datetime.now()] * 100,
                labels=[0] * 90 + [1] * 10,  # Some anomalies for RF
            )

            await manager.train_model(model_id, training_data)

        # Make ensemble prediction
        test_data = {
            "packet_count": 1000,
            "byte_count": 50000,
            "flow_count": 50,
            "error_rate": 0.02,
            "protocol_distribution": {"TCP": 0.7},
        }

        ensemble_score = await manager.ensemble_predict(model_ids, test_data)

        assert ensemble_score is not None
        assert 0 <= ensemble_score.score <= 1
        assert ensemble_score.confidence is not None


class TestAnomalyDetectionIntegration:
    @pytest.mark.asyncio
    async def test_end_to_end_anomaly_detection(self):
        """Test complete anomaly detection workflow"""

        manager = ModelManager()

        # Create and train model
        model_id = await manager.create_model(
            name="network_anomaly_detector",
            model_type=ModelType.ISOLATION_FOREST,
            description="Detects network traffic anomalies",
        )

        # Simulate historical network data
        np.random.seed(42)
        historical_data = []

        for i in range(200):
            # Normal traffic pattern
            if i < 180:
                packet_count = np.random.normal(1000, 100)
                error_rate = np.random.uniform(0, 0.05)
            # Anomalous traffic
            else:
                packet_count = np.random.normal(5000, 500)  # DDoS pattern
                error_rate = np.random.uniform(0.1, 0.3)  # High errors

            historical_data.append(
                [
                    packet_count,
                    packet_count * 50,  # byte_count
                    packet_count / 20,  # flow_count
                    error_rate,
                    np.random.uniform(0.6, 0.8),  # TCP ratio
                ]
            )

        training_data = TrainingData(
            data=historical_data,
            feature_names=["packets", "bytes", "flows", "errors", "tcp_ratio"],
            timestamps=[datetime.now(
            ) - timedelta(hours=i) for i in range(200
                                                  )],
            labels=[0] * 180 + [1] * 20,
        )

        await manager.train_model(model_id, training_data)

        # Test detection on new data
        normal_traffic = {
            "packet_count": 1050,
            "byte_count": 52500,
            "flow_count": 52,
            "error_rate": 0.03,
            "protocol_distribution": {"TCP": 0.7},
        }

        anomalous_traffic = {
            "packet_count": 5500,
            "byte_count": 275000,
            "flow_count": 275,
            "error_rate": 0.25,
            "protocol_distribution": {"TCP": 0.7},
        }

        normal_score = await manager.predict(model_id, normal_traffic)
        anomaly_score = await manager.predict(model_id, anomalous_traffic)

        # Anomalous traffic should have higher score
        assert anomaly_score.score > normal_score.score
        assert anomaly_score.is_anomaly != normal_score.is_anomaly

    @pytest.mark.asyncio
    async def test_model_persistence(self):
        """Test saving and loading models"""

        manager = ModelManager()

        # Create and train model
        model_id = await manager.create_model(
            name="persistent_model", model_type=ModelType.RANDOM_FOREST
        )

        np.random.seed(42)
        data = np.random.randn(100, 5)

        training_data = TrainingData(
            data=data.tolist(),
            feature_names=["f1", "f2", "f3", "f4", "f5"],
            timestamps=[datetime.now()] * 100,
            labels=[0] * 90 + [1] * 10,
        )

        await manager.train_model(model_id, training_data)

        # Save model
        saved_path = await manager.save_model(model_id, "/tmp/test_model.pkl")
        assert saved_path is not None

        # Create new manager and load model
        new_manager = ModelManager()
        loaded_id = await new_manager.load_model(
            saved_path, name="loaded_model", model_type=ModelType.RANDOM_FOREST
        )

        assert loaded_id is not None
        assert new_manager.models[loaded_id].is_trained

        # Test prediction with loaded model
        test_data = {"packet_count": 1000}
        score = await new_manager.predict(loaded_id, test_data)
        assert score is not None
