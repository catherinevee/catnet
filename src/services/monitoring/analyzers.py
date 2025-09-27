"""
Metric analyzers for monitoring service.
"""

import asyncio
import logging
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LinearRegression
from sklearn.cluster import DBSCAN
from scipy import stats
from scipy.signal import find_peaks
import warnings

from .models import Metric, MetricType, Alert, AlertSeverity

warnings.filterwarnings('ignore')
logger = logging.getLogger(__name__)


class MetricAnalyzer:
    """Base metric analyzer."""

    def __init__(self):
        self.analysis_window = timedelta(hours=1)
        self.min_data_points = 10

    async def analyze(self, metrics: List[Metric]) -> Dict[str, Any]:
        """Analyze metrics and return comprehensive analysis."""
        df = self.prepare_data(metrics)

        if df.empty:
            return {
                'status': 'no_data',
                'message': 'No metrics available for analysis',
                'timestamp': datetime.utcnow().isoformat()
            }

        # Perform multi-faceted analysis
        analysis_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'metric_count': len(metrics),
            'unique_metrics': len(df['name'].unique()),
            'time_range': {
                'start': df.index.min().isoformat(),
                'end': df.index.max().isoformat(),
                'duration_minutes': int((df.index.max() - df.index.min()).total_seconds() / 60)
            },
            'summary_statistics': {},
            'anomalies': [],
            'trends': [],
            'correlations': [],
            'alerts': [],
            'recommendations': []
        }

        # Instantiate specialized analyzers
        anomaly_detector = AnomalyDetector()
        trend_analyzer = TrendAnalyzer()
        correlation_analyzer = CorrelationAnalyzer()
        threshold_analyzer = ThresholdAnalyzer()

        try:
            # 1. Statistical Analysis
            for metric_name in df['name'].unique():
                metric_df = df[df['name'] == metric_name]
                if len(metric_df) >= self.min_data_points:
                    stats = self.calculate_statistics(metric_df['value'].values)
                    analysis_results['summary_statistics'][metric_name] = stats

            # 2. Anomaly Detection
            anomalies = await anomaly_detector.detect(metrics)
            analysis_results['anomalies'] = anomalies

            # 3. Trend Analysis
            trends = await trend_analyzer.analyze(metrics)
            analysis_results['trends'] = trends

            # 4. Correlation Analysis
            correlations = await correlation_analyzer.analyze(metrics)
            analysis_results['correlations'] = correlations

            # 5. Threshold Violations
            violations = await threshold_analyzer.analyze(metrics)
            analysis_results['threshold_violations'] = violations

            # 6. Generate Alerts based on findings
            analysis_results['alerts'] = self._generate_alerts(
                anomalies, trends, violations
            )

            # 7. Generate Recommendations
            analysis_results['recommendations'] = self._generate_recommendations(
                analysis_results
            )

            # 8. Calculate Overall Health Score
            analysis_results['health_score'] = self._calculate_health_score(
                analysis_results
            )

            analysis_results['status'] = 'completed'

        except Exception as e:
            logger.error(f"Error during metric analysis: {str(e)}")
            analysis_results['status'] = 'error'
            analysis_results['error'] = str(e)

        return analysis_results

    def _generate_alerts(self, anomalies: List, trends: List, violations: List) -> List[Dict[str, Any]]:
        """Generate alerts based on analysis results."""
        alerts = []

        # Critical anomalies
        for anomaly in anomalies:
            if anomaly.get('severity') in ['critical', 'high']:
                alerts.append({
                    'type': 'anomaly',
                    'severity': anomaly['severity'],
                    'metric': anomaly['metric'],
                    'timestamp': anomaly['timestamp'],
                    'message': f"Anomaly detected in {anomaly['metric']}: {', '.join(anomaly['reasons'])}",
                    'score': anomaly.get('anomaly_score', 0)
                })

        # Critical violations
        for violation in violations:
            if violation.get('severity') == 'critical':
                alerts.append({
                    'type': 'threshold_violation',
                    'severity': 'critical',
                    'metric': violation['metric'],
                    'timestamp': violation['timestamp'],
                    'message': f"Critical threshold exceeded for {violation['metric']}",
                    'value': violation['value'],
                    'threshold': violation['threshold']
                })

        # Trending issues
        for trend in trends:
            if trend.get('direction') == 'increasing' and trend.get('strength', 0) > 0.8:
                metric_name = trend['metric']
                if any(keyword in metric_name.lower() for keyword in ['error', 'latency', 'cpu', 'memory']):
                    alerts.append({
                        'type': 'trend_alert',
                        'severity': 'medium',
                        'metric': metric_name,
                        'message': f"Strong upward trend detected in {metric_name}",
                        'trend_strength': trend['strength']
                    })

        return alerts

    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []

        # Based on anomalies
        if analysis.get('anomalies'):
            high_severity_count = sum(1 for a in analysis['anomalies'] if a.get('severity') in ['critical', 'high'])
            if high_severity_count > 5:
                recommendations.append(
                    "Multiple high-severity anomalies detected. Consider implementing automated alerting."
                )

        # Based on trends
        if analysis.get('trends'):
            degrading_trends = [t for t in analysis['trends'] if t.get('direction') == 'increasing' and t.get('strength', 0) > 0.7]
            if degrading_trends:
                recommendations.append(
                    f"Monitor {len(degrading_trends)} metrics showing concerning upward trends."
                )

        # Based on correlations
        if analysis.get('correlations'):
            strong_correlations = [c for c in analysis['correlations'] if abs(c.get('correlation', 0)) > 0.9]
            if strong_correlations:
                recommendations.append(
                    "Strong metric correlations found. Consider consolidating monitoring or investigating dependencies."
                )

        # Based on health score
        health_score = analysis.get('health_score', {}).get('score', 100)
        if health_score < 60:
            recommendations.append(
                "Overall system health is below acceptable levels. Immediate investigation recommended."
            )
        elif health_score < 80:
            recommendations.append(
                "System health shows signs of degradation. Proactive monitoring recommended."
            )

        # Data quality recommendations
        if analysis.get('metric_count', 0) < 10:
            recommendations.append(
                "Limited metrics available. Consider expanding monitoring coverage."
            )

        return recommendations

    def _calculate_health_score(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall system health score."""
        score = 100.0
        factors = []

        # Deduct for anomalies
        anomalies = analysis.get('anomalies', [])
        critical_anomalies = sum(1 for a in anomalies if a.get('severity') == 'critical')
        high_anomalies = sum(1 for a in anomalies if a.get('severity') == 'high')
        medium_anomalies = sum(1 for a in anomalies if a.get('severity') == 'medium')

        score -= critical_anomalies * 20
        score -= high_anomalies * 10
        score -= medium_anomalies * 5

        if critical_anomalies > 0:
            factors.append(f"{critical_anomalies} critical anomalies")
        if high_anomalies > 0:
            factors.append(f"{high_anomalies} high-severity anomalies")

        # Deduct for threshold violations
        violations = analysis.get('threshold_violations', [])
        critical_violations = sum(1 for v in violations if v.get('severity') == 'critical')
        score -= critical_violations * 15

        if critical_violations > 0:
            factors.append(f"{critical_violations} critical threshold violations")

        # Deduct for negative trends
        trends = analysis.get('trends', [])
        concerning_trends = sum(1 for t in trends if t.get('direction') == 'increasing' and t.get('strength', 0) > 0.7)
        score -= concerning_trends * 5

        if concerning_trends > 0:
            factors.append(f"{concerning_trends} concerning trends")

        # Ensure score doesn't go below 0
        score = max(0, score)

        # Determine health level
        if score >= 90:
            level = 'excellent'
        elif score >= 80:
            level = 'good'
        elif score >= 60:
            level = 'fair'
        elif score >= 40:
            level = 'poor'
        else:
            level = 'critical'

        return {
            'score': round(score, 1),
            'level': level,
            'factors': factors
        }

    def prepare_data(self, metrics: List[Metric]) -> pd.DataFrame:
        """Prepare metrics for analysis."""
        data = []
        for metric in metrics:
            data.append({
                'timestamp': metric.timestamp,
                'name': metric.name,
                'value': float(metric.value) if isinstance(metric.value, (int, float)) else 0,
                'source': metric.source,
                **metric.labels
            })

        df = pd.DataFrame(data)
        if not df.empty:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df.set_index('timestamp', inplace=True)
            df.sort_index(inplace=True)

        return df

    def calculate_statistics(self, values: np.ndarray) -> Dict[str, float]:
        """Calculate basic statistics."""
        if len(values) == 0:
            return {}

        return {
            'mean': float(np.mean(values)),
            'median': float(np.median(values)),
            'std': float(np.std(values)),
            'min': float(np.min(values)),
            'max': float(np.max(values)),
            'p25': float(np.percentile(values, 25)),
            'p75': float(np.percentile(values, 75)),
            'p95': float(np.percentile(values, 95)),
            'p99': float(np.percentile(values, 99))
        }


class AnomalyDetector(MetricAnalyzer):
    """Anomaly detection analyzer."""

    def __init__(self):
        super().__init__()
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.baseline_window = timedelta(days=7)
        self.sensitivity = 0.05  # 5% contamination rate
        self.anomaly_cache = {}

    async def detect(self, metrics: List[Metric]) -> List[Dict[str, Any]]:
        """Detect anomalies in metrics."""
        anomalies = []
        df = self.prepare_data(metrics)

        if df.empty:
            return anomalies

        # Group by metric name
        for metric_name in df['name'].unique():
            metric_df = df[df['name'] == metric_name]

            if len(metric_df) < self.min_data_points:
                continue

            # Detect anomalies using multiple methods
            statistical_anomalies = self._detect_statistical_anomalies(metric_df)
            ml_anomalies = self._detect_ml_anomalies(metric_df)
            pattern_anomalies = self._detect_pattern_anomalies(metric_df)

            # Combine results
            for idx, row in metric_df.iterrows():
                is_anomaly = False
                anomaly_score = 0
                reasons = []

                # Check if detected by statistical method
                if idx in statistical_anomalies:
                    is_anomaly = True
                    anomaly_score += 0.3
                    reasons.append("statistical deviation")

                # Check if detected by ML
                if idx in ml_anomalies:
                    is_anomaly = True
                    anomaly_score += 0.5
                    reasons.append("ML detection")

                # Check if detected by pattern analysis
                if idx in pattern_anomalies:
                    is_anomaly = True
                    anomaly_score += 0.2
                    reasons.append("pattern anomaly")

                if is_anomaly:
                    anomaly = {
                        'timestamp': idx,
                        'metric': metric_name,
                        'value': row['value'],
                        'anomaly_score': min(anomaly_score, 1.0),
                        'severity': self._calculate_severity(anomaly_score),
                        'reasons': reasons,
                        'context': self._get_anomaly_context(metric_df, idx)
                    }
                    anomalies.append(anomaly)

        return anomalies

    def _detect_statistical_anomalies(self, df: pd.DataFrame) -> List[pd.Timestamp]:
        """Detect statistical anomalies using z-score."""
        anomalies = []
        values = df['value'].values

        # Calculate z-scores
        z_scores = np.abs(stats.zscore(values))
        threshold = 3  # 3 standard deviations

        for idx, z_score in zip(df.index, z_scores):
            if z_score > threshold:
                anomalies.append(idx)

        return anomalies

    def _detect_ml_anomalies(self, df: pd.DataFrame) -> List[pd.Timestamp]:
        """Detect anomalies using Isolation Forest."""
        anomalies = []
        values = df['value'].values.reshape(-1, 1)

        if len(values) < 20:
            return anomalies

        # Fit and predict
        predictions = self.isolation_forest.fit_predict(values)

        for idx, pred in zip(df.index, predictions):
            if pred == -1:  # Anomaly
                anomalies.append(idx)

        return anomalies

    def _detect_pattern_anomalies(self, df: pd.DataFrame) -> List[pd.Timestamp]:
        """Detect pattern-based anomalies."""
        anomalies = []
        values = df['value'].values

        # Check for sudden spikes
        peaks, properties = find_peaks(values, prominence=2*np.std(values))
        for peak_idx in peaks:
            anomalies.append(df.index[peak_idx])

        # Check for sudden drops
        inverted = -values
        valleys, _ = find_peaks(inverted, prominence=2*np.std(inverted))
        for valley_idx in valleys:
            anomalies.append(df.index[valley_idx])

        return anomalies

    def _calculate_severity(self, anomaly_score: float) -> str:
        """Calculate anomaly severity."""
        if anomaly_score >= 0.8:
            return "critical"
        elif anomaly_score >= 0.6:
            return "high"
        elif anomaly_score >= 0.4:
            return "medium"
        else:
            return "low"

    def _get_anomaly_context(self, df: pd.DataFrame, timestamp: pd.Timestamp) -> Dict[str, Any]:
        """Get context around anomaly."""
        window = timedelta(minutes=30)
        start = timestamp - window
        end = timestamp + window

        context_df = df.loc[start:end]

        return {
            'before_mean': float(df.loc[:timestamp]['value'].tail(10).mean()),
            'after_mean': float(df.loc[timestamp:]['value'].head(10).mean()),
            'local_std': float(context_df['value'].std()),
            'global_mean': float(df['value'].mean()),
            'global_std': float(df['value'].std())
        }


class TrendAnalyzer(MetricAnalyzer):
    """Trend analysis for metrics."""

    def __init__(self):
        super().__init__()
        self.trend_window = timedelta(hours=24)
        self.forecast_horizon = timedelta(hours=6)

    async def analyze(self, metrics: List[Metric]) -> List[Dict[str, Any]]:
        """Analyze trends in metrics."""
        trends = []
        df = self.prepare_data(metrics)

        if df.empty:
            return trends

        for metric_name in df['name'].unique():
            metric_df = df[df['name'] == metric_name]

            if len(metric_df) < self.min_data_points:
                continue

            trend = {
                'metric': metric_name,
                'direction': self._calculate_trend_direction(metric_df),
                'strength': self._calculate_trend_strength(metric_df),
                'forecast': self._forecast_values(metric_df),
                'seasonality': self._detect_seasonality(metric_df),
                'change_points': self._detect_change_points(metric_df)
            }
            trends.append(trend)

        return trends

    def _calculate_trend_direction(self, df: pd.DataFrame) -> str:
        """Calculate trend direction."""
        values = df['value'].values
        x = np.arange(len(values)).reshape(-1, 1)
        y = values.reshape(-1, 1)

        model = LinearRegression()
        model.fit(x, y)

        slope = model.coef_[0][0]

        if abs(slope) < 0.01:
            return "stable"
        elif slope > 0:
            return "increasing"
        else:
            return "decreasing"

    def _calculate_trend_strength(self, df: pd.DataFrame) -> float:
        """Calculate trend strength (R-squared)."""
        values = df['value'].values
        x = np.arange(len(values)).reshape(-1, 1)
        y = values.reshape(-1, 1)

        model = LinearRegression()
        model.fit(x, y)

        return float(model.score(x, y))

    def _forecast_values(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Forecast future values."""
        forecasts = []
        values = df['value'].values

        if len(values) < 20:
            return forecasts

        # Simple linear regression forecast
        x = np.arange(len(values)).reshape(-1, 1)
        y = values.reshape(-1, 1)

        model = LinearRegression()
        model.fit(x, y)

        # Forecast next 6 hours (assuming 1-minute data)
        future_points = 360
        future_x = np.arange(len(values), len(values) + future_points).reshape(-1, 1)
        future_y = model.predict(future_x)

        last_timestamp = df.index[-1]
        for i, value in enumerate(future_y):
            forecast_time = last_timestamp + timedelta(minutes=i+1)
            forecasts.append({
                'timestamp': forecast_time.isoformat(),
                'value': float(value[0]),
                'confidence': 0.8 - (i * 0.001)  # Confidence decreases over time
            })

        return forecasts[:60]  # Return first hour of forecasts

    def _detect_seasonality(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Detect seasonal patterns."""
        values = df['value'].values

        if len(values) < 144:  # Need at least 1 day of data (assuming 10-min intervals)
            return {'detected': False}

        # Simple FFT-based seasonality detection
        fft_result = np.fft.fft(values)
        frequencies = np.fft.fftfreq(len(values))

        # Find dominant frequencies
        power = np.abs(fft_result) ** 2
        dominant_freq_idx = np.argsort(power)[-5:]  # Top 5 frequencies

        periods = []
        for idx in dominant_freq_idx:
            if frequencies[idx] > 0:
                period = 1 / frequencies[idx]
                if 10 < period < 1440:  # Between 10 minutes and 1 day
                    periods.append(int(period))

        return {
            'detected': len(periods) > 0,
            'periods': periods,
            'type': self._classify_seasonality(periods)
        }

    def _classify_seasonality(self, periods: List[int]) -> str:
        """Classify seasonality type."""
        if not periods:
            return "none"

        avg_period = np.mean(periods)

        if 50 < avg_period < 70:
            return "hourly"
        elif 1380 < avg_period < 1500:
            return "daily"
        elif 9900 < avg_period < 10260:
            return "weekly"
        else:
            return "custom"

    def _detect_change_points(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect significant changes in metric behavior."""
        change_points = []
        values = df['value'].values

        if len(values) < 20:
            return change_points

        # Use sliding window to detect changes
        window_size = min(20, len(values) // 4)

        for i in range(window_size, len(values) - window_size):
            before = values[i-window_size:i]
            after = values[i:i+window_size]

            # Perform t-test
            t_stat, p_value = stats.ttest_ind(before, after)

            if p_value < 0.05:  # Significant change
                change_points.append({
                    'timestamp': df.index[i].isoformat(),
                    'before_mean': float(np.mean(before)),
                    'after_mean': float(np.mean(after)),
                    'change_magnitude': float(np.mean(after) - np.mean(before)),
                    'p_value': float(p_value)
                })

        return change_points


class CorrelationAnalyzer(MetricAnalyzer):
    """Correlation analysis between metrics."""

    def __init__(self):
        super().__init__()
        self.min_correlation = 0.7
        self.lag_window = 60  # minutes

    async def analyze(self, metrics: List[Metric]) -> List[Dict[str, Any]]:
        """Find correlations between metrics."""
        correlations = []
        df = self.prepare_data(metrics)

        if df.empty:
            return correlations

        metric_names = df['name'].unique()

        if len(metric_names) < 2:
            return correlations

        # Check correlations between all metric pairs
        for i, metric1 in enumerate(metric_names):
            for metric2 in metric_names[i+1:]:
                df1 = df[df['name'] == metric1]['value']
                df2 = df[df['name'] == metric2]['value']

                # Align timestamps
                aligned = pd.concat([df1, df2], axis=1, join='inner')
                aligned.columns = [metric1, metric2]

                if len(aligned) < self.min_data_points:
                    continue

                # Calculate correlation
                correlation = aligned.corr().iloc[0, 1]

                if abs(correlation) > self.min_correlation:
                    # Check for lagged correlation
                    lag, lagged_corr = self._find_best_lag(aligned[metric1], aligned[metric2])

                    correlation_info = {
                        'metric1': metric1,
                        'metric2': metric2,
                        'correlation': float(correlation),
                        'lag_minutes': lag,
                        'lagged_correlation': float(lagged_corr),
                        'relationship': self._classify_relationship(correlation),
                        'causality': self._test_causality(aligned[metric1], aligned[metric2])
                    }
                    correlations.append(correlation_info)

        return correlations

    def _find_best_lag(self, series1: pd.Series, series2: pd.Series) -> Tuple[int, float]:
        """Find the lag with highest correlation."""
        best_lag = 0
        best_corr = series1.corr(series2)

        for lag in range(1, min(self.lag_window, len(series1) // 2)):
            # Test positive lag
            corr = series1[:-lag].corr(series2[lag:])
            if abs(corr) > abs(best_corr):
                best_lag = lag
                best_corr = corr

            # Test negative lag
            corr = series1[lag:].corr(series2[:-lag])
            if abs(corr) > abs(best_corr):
                best_lag = -lag
                best_corr = corr

        return best_lag, best_corr

    def _classify_relationship(self, correlation: float) -> str:
        """Classify the relationship type."""
        if correlation > 0.9:
            return "strong_positive"
        elif correlation > 0.7:
            return "moderate_positive"
        elif correlation < -0.9:
            return "strong_negative"
        elif correlation < -0.7:
            return "moderate_negative"
        else:
            return "weak"

    def _test_causality(self, series1: pd.Series, series2: pd.Series) -> Dict[str, Any]:
        """Test for causal relationship (simplified Granger causality)."""
        # Simplified causality test
        # In production, would use proper Granger causality test

        # Check if changes in series1 precede changes in series2
        series1_diff = series1.diff().dropna()
        series2_diff = series2.diff().dropna()

        # Align and shift
        aligned = pd.concat([series1_diff, series2_diff.shift(1)], axis=1, join='inner')
        aligned.columns = ['cause', 'effect']

        correlation = aligned.corr().iloc[0, 1]

        return {
            'likely_causal': abs(correlation) > 0.5,
            'causality_score': float(abs(correlation)),
            'direction': 'series1_causes_series2' if correlation > 0.5 else 'unclear'
        }


class PredictiveAnalyzer(MetricAnalyzer):
    """Predictive analytics for metrics."""

    def __init__(self):
        super().__init__()
        self.models = {}
        self.prediction_horizon = 60  # minutes

    async def predict(self, metrics: List[Metric]) -> List[Dict[str, Any]]:
        """Predict future metric values and issues."""
        predictions = []
        df = self.prepare_data(metrics)

        if df.empty:
            return predictions

        for metric_name in df['name'].unique():
            metric_df = df[df['name'] == metric_name]

            if len(metric_df) < 50:
                continue

            prediction = {
                'metric': metric_name,
                'capacity_exhaustion': self._predict_capacity_exhaustion(metric_df),
                'threshold_breach': self._predict_threshold_breach(metric_df),
                'anomaly_probability': self._predict_anomaly_probability(metric_df),
                'failure_risk': self._calculate_failure_risk(metric_df),
                'recommendations': self._generate_recommendations(metric_df)
            }
            predictions.append(prediction)

        return predictions

    def _predict_capacity_exhaustion(self, df: pd.DataFrame) -> Optional[Dict[str, Any]]:
        """Predict when capacity will be exhausted."""
        values = df['value'].values

        # Assume 100% is the capacity limit
        if values[-1] < 70:  # Current usage below 70%
            return None

        # Fit exponential growth model
        x = np.arange(len(values))
        y = values

        # Linear regression on log scale for exponential fit
        log_y = np.log(y + 1)  # Add 1 to avoid log(0)
        model = LinearRegression()
        model.fit(x.reshape(-1, 1), log_y)

        # Predict when it reaches 100%
        target_log = np.log(100)
        if model.coef_[0] > 0:
            steps_to_100 = (target_log - model.intercept_) / model.coef_[0]
            minutes_to_exhaustion = int(steps_to_100)

            if minutes_to_exhaustion > 0 and minutes_to_exhaustion < 10080:  # Within a week
                return {
                    'predicted': True,
                    'minutes_remaining': minutes_to_exhaustion,
                    'hours_remaining': round(minutes_to_exhaustion / 60, 1),
                    'current_usage': float(values[-1]),
                    'growth_rate': float(model.coef_[0])
                }

        return None

    def _predict_threshold_breach(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Predict threshold breaches."""
        breaches = []
        values = df['value'].values

        # Common thresholds to check
        thresholds = [
            {'name': 'warning', 'value': 75},
            {'name': 'critical', 'value': 90},
            {'name': 'maximum', 'value': 95}
        ]

        # Fit trend model
        x = np.arange(len(values)).reshape(-1, 1)
        y = values.reshape(-1, 1)
        model = LinearRegression()
        model.fit(x, y)

        for threshold in thresholds:
            if values[-1] < threshold['value']:
                # Predict when threshold will be reached
                future_x = np.arange(len(values), len(values) + self.prediction_horizon).reshape(-1, 1)
                future_y = model.predict(future_x)

                for i, pred_value in enumerate(future_y):
                    if pred_value[0] >= threshold['value']:
                        breaches.append({
                            'threshold': threshold['name'],
                            'value': threshold['value'],
                            'minutes_to_breach': i + 1,
                            'confidence': 0.8 - (i * 0.01)
                        })
                        break

        return breaches

    def _predict_anomaly_probability(self, df: pd.DataFrame) -> float:
        """Predict probability of anomaly in near future."""
        values = df['value'].values

        # Calculate recent volatility
        recent_std = np.std(values[-20:])
        overall_std = np.std(values)

        volatility_ratio = recent_std / overall_std if overall_std > 0 else 1

        # Check for trending towards extremes
        recent_trend = np.polyfit(range(len(values[-10:])), values[-10:], 1)[0]

        # Calculate anomaly probability
        probability = 0.0

        # High volatility increases probability
        if volatility_ratio > 2:
            probability += 0.3

        # Strong trends increase probability
        if abs(recent_trend) > overall_std:
            probability += 0.3

        # Approaching historical extremes
        if values[-1] > np.percentile(values, 95) or values[-1] < np.percentile(values, 5):
            probability += 0.4

        return min(probability, 1.0)

    def _calculate_failure_risk(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Calculate risk of failure."""
        values = df['value'].values

        # Factors contributing to failure risk
        risk_score = 0.0
        risk_factors = []

        # Check if approaching limits
        if values[-1] > 80:
            risk_score += 0.3
            risk_factors.append("high_usage")

        # Check volatility
        volatility = np.std(values[-20:])
        if volatility > np.std(values) * 2:
            risk_score += 0.2
            risk_factors.append("high_volatility")

        # Check for degradation trend
        if len(values) > 100:
            long_term_trend = np.polyfit(range(len(values)), values, 1)[0]
            if long_term_trend > 0 and df['name'].values[0] in ['error_rate', 'latency']:
                risk_score += 0.3
                risk_factors.append("degradation_trend")

        # Check for repeated spikes
        peaks, _ = find_peaks(values, prominence=np.std(values))
        if len(peaks) > len(values) * 0.1:
            risk_score += 0.2
            risk_factors.append("frequent_spikes")

        risk_level = "low"
        if risk_score > 0.7:
            risk_level = "high"
        elif risk_score > 0.4:
            risk_level = "medium"

        return {
            'risk_score': min(risk_score, 1.0),
            'risk_level': risk_level,
            'risk_factors': risk_factors
        }

    def _generate_recommendations(self, df: pd.DataFrame) -> List[str]:
        """Generate recommendations based on predictions."""
        recommendations = []
        values = df['value'].values
        metric_name = df['name'].values[0]

        # High usage recommendation
        if values[-1] > 80:
            recommendations.append(f"Consider scaling up resources for {metric_name}")

        # Volatility recommendation
        if np.std(values[-20:]) > np.std(values) * 2:
            recommendations.append(f"Investigate cause of increased volatility in {metric_name}")

        # Trend recommendation
        trend = np.polyfit(range(len(values[-30:])), values[-30:], 1)[0]
        if trend > 0 and values[-1] > 70:
            recommendations.append(f"Monitor {metric_name} closely - approaching capacity")

        return recommendations


class ThresholdAnalyzer(MetricAnalyzer):
    """Threshold-based analysis."""

    def __init__(self):
        super().__init__()
        self.thresholds = {}
        self.dynamic_thresholds = {}

    def set_threshold(self, metric: str, warning: float, critical: float):
        """Set static thresholds for a metric."""
        self.thresholds[metric] = {
            'warning': warning,
            'critical': critical
        }

    async def analyze(self, metrics: List[Metric]) -> List[Dict[str, Any]]:
        """Analyze metrics against thresholds."""
        violations = []
        df = self.prepare_data(metrics)

        if df.empty:
            return violations

        for metric_name in df['name'].unique():
            metric_df = df[df['name'] == metric_name]

            # Get thresholds (static or dynamic)
            thresholds = self._get_thresholds(metric_name, metric_df)

            # Check for violations
            for idx, row in metric_df.iterrows():
                value = row['value']

                if value >= thresholds['critical']:
                    violations.append({
                        'timestamp': idx,
                        'metric': metric_name,
                        'value': value,
                        'threshold': thresholds['critical'],
                        'severity': 'critical',
                        'type': 'static' if metric_name in self.thresholds else 'dynamic'
                    })
                elif value >= thresholds['warning']:
                    violations.append({
                        'timestamp': idx,
                        'metric': metric_name,
                        'value': value,
                        'threshold': thresholds['warning'],
                        'severity': 'warning',
                        'type': 'static' if metric_name in self.thresholds else 'dynamic'
                    })

        return violations

    def _get_thresholds(self, metric_name: str, df: pd.DataFrame) -> Dict[str, float]:
        """Get thresholds for metric (static or dynamic)."""
        if metric_name in self.thresholds:
            return self.thresholds[metric_name]
        else:
            # Calculate dynamic thresholds
            return self._calculate_dynamic_thresholds(df)

    def _calculate_dynamic_thresholds(self, df: pd.DataFrame) -> Dict[str, float]:
        """Calculate dynamic thresholds based on historical data."""
        values = df['value'].values

        # Use percentiles for dynamic thresholds
        return {
            'warning': float(np.percentile(values, 90)),
            'critical': float(np.percentile(values, 95))
        }


class BaselineAnalyzer(MetricAnalyzer):
    """Baseline comparison analyzer."""

    def __init__(self):
        super().__init__()
        self.baselines = {}
        self.baseline_window = timedelta(days=7)

    async def analyze(self, metrics: List[Metric]) -> List[Dict[str, Any]]:
        """Compare metrics against baselines."""
        deviations = []
        df = self.prepare_data(metrics)

        if df.empty:
            return deviations

        for metric_name in df['name'].unique():
            metric_df = df[df['name'] == metric_name]

            # Calculate or retrieve baseline
            baseline = await self._get_baseline(metric_name, metric_df)

            # Compare current values against baseline
            for idx, row in metric_df.tail(60).iterrows():  # Last hour
                hour = idx.hour
                day_of_week = idx.dayofweek

                expected = baseline.get(f"{day_of_week}_{hour}", {})
                if expected:
                    deviation_percent = abs((row['value'] - expected['mean']) / expected['mean'] * 100)

                    if deviation_percent > 50:  # More than 50% deviation
                        deviations.append({
                            'timestamp': idx,
                            'metric': metric_name,
                            'actual': row['value'],
                            'expected': expected['mean'],
                            'deviation_percent': deviation_percent,
                            'severity': self._calculate_deviation_severity(deviation_percent)
                        })

        return deviations

    async def _get_baseline(self, metric_name: str, df: pd.DataFrame) -> Dict[str, Any]:
        """Get or calculate baseline for metric."""
        if metric_name in self.baselines:
            return self.baselines[metric_name]

        # Calculate baseline from historical data
        baseline = {}

        for day in range(7):  # Days of week
            for hour in range(24):  # Hours of day
                mask = (df.index.dayofweek == day) & (df.index.hour == hour)
                hour_data = df.loc[mask, 'value']

                if len(hour_data) > 0:
                    baseline[f"{day}_{hour}"] = {
                        'mean': float(hour_data.mean()),
                        'std': float(hour_data.std()),
                        'min': float(hour_data.min()),
                        'max': float(hour_data.max())
                    }

        self.baselines[metric_name] = baseline
        return baseline

    def _calculate_deviation_severity(self, deviation_percent: float) -> str:
        """Calculate severity based on deviation percentage."""
        if deviation_percent > 200:
            return "critical"
        elif deviation_percent > 100:
            return "high"
        elif deviation_percent > 50:
            return "medium"
        else:
            return "low"


class PatternDetector(MetricAnalyzer):
    """Pattern detection in metrics."""

    def __init__(self):
        super().__init__()
        self.patterns = {}

    async def detect(self, metrics: List[Metric]) -> List[Dict[str, Any]]:
        """Detect patterns in metrics."""
        patterns = []
        df = self.prepare_data(metrics)

        if df.empty:
            return patterns

        for metric_name in df['name'].unique():
            metric_df = df[df['name'] == metric_name]

            if len(metric_df) < 50:
                continue

            # Detect various patterns
            patterns.extend(self._detect_recurring_patterns(metric_df))
            patterns.extend(self._detect_step_changes(metric_df))
            patterns.extend(self._detect_gradual_degradation(metric_df))
            patterns.extend(self._detect_oscillations(metric_df))

        return patterns

    def _detect_recurring_patterns(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect recurring patterns."""
        patterns = []
        values = df['value'].values

        # Use autocorrelation to find recurring patterns
        autocorr = np.correlate(values, values, mode='same')
        autocorr = autocorr / np.max(autocorr)

        # Find peaks in autocorrelation
        peaks, properties = find_peaks(autocorr, height=0.7, distance=10)

        for peak in peaks:
            if peak > 0:
                patterns.append({
                    'type': 'recurring',
                    'metric': df['name'].values[0],
                    'period': peak,
                    'strength': float(autocorr[peak]),
                    'description': f"Recurring pattern every {peak} data points"
                })

        return patterns

    def _detect_step_changes(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect step changes in metrics."""
        patterns = []
        values = df['value'].values

        # Calculate differences
        diff = np.diff(values)
        threshold = 3 * np.std(diff)

        for i, d in enumerate(diff):
            if abs(d) > threshold:
                patterns.append({
                    'type': 'step_change',
                    'metric': df['name'].values[0],
                    'timestamp': df.index[i+1].isoformat(),
                    'before': float(values[i]),
                    'after': float(values[i+1]),
                    'magnitude': float(d)
                })

        return patterns

    def _detect_gradual_degradation(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect gradual performance degradation."""
        patterns = []
        values = df['value'].values

        # Fit polynomial to detect non-linear trends
        x = np.arange(len(values))
        coeffs = np.polyfit(x, values, 2)

        # Check for consistent upward curve (degradation)
        if coeffs[0] > 0 and coeffs[1] > 0:
            patterns.append({
                'type': 'gradual_degradation',
                'metric': df['name'].values[0],
                'rate': float(coeffs[1]),
                'acceleration': float(coeffs[0]),
                'description': "Gradual performance degradation detected"
            })

        return patterns

    def _detect_oscillations(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect oscillating behavior."""
        patterns = []
        values = df['value'].values

        # Count zero crossings of detrended data
        detrended = values - np.mean(values)
        zero_crossings = np.where(np.diff(np.sign(detrended)))[0]

        if len(zero_crossings) > len(values) * 0.3:
            avg_period = len(values) / len(zero_crossings)
            patterns.append({
                'type': 'oscillation',
                'metric': df['name'].values[0],
                'frequency': len(zero_crossings),
                'avg_period': float(avg_period),
                'description': f"Oscillating behavior with average period of {avg_period:.1f}"
            })

        return patterns


class RootCauseAnalyzer(MetricAnalyzer):
    """Root cause analysis for incidents."""

    def __init__(self):
        super().__init__()
        self.dependency_graph = {}
        self.impact_scores = {}

    async def analyze_incident(
        self,
        incident_time: datetime,
        affected_metrics: List[str],
        all_metrics: List[Metric]
    ) -> Dict[str, Any]:
        """Analyze root cause of an incident."""
        df = self.prepare_data(all_metrics)

        if df.empty:
            return {}

        # Time window around incident
        window_start = incident_time - timedelta(minutes=30)
        window_end = incident_time + timedelta(minutes=10)
        incident_df = df.loc[window_start:window_end]

        # Analyze metric behavior
        metric_analysis = self._analyze_metric_behavior(incident_df, affected_metrics)

        # Find correlated metrics
        correlated = self._find_correlated_metrics(incident_df, affected_metrics)

        # Determine propagation path
        propagation = self._analyze_propagation(incident_df, affected_metrics)

        # Identify likely root cause
        root_cause = self._identify_root_cause(metric_analysis, correlated, propagation)

        return {
            'incident_time': incident_time.isoformat(),
            'affected_metrics': affected_metrics,
            'root_cause': root_cause,
            'propagation_path': propagation,
            'correlated_metrics': correlated,
            'recommendations': self._generate_remediation(root_cause)
        }

    def _analyze_metric_behavior(
        self,
        df: pd.DataFrame,
        affected_metrics: List[str]
    ) -> Dict[str, Any]:
        """Analyze how metrics behaved during incident."""
        analysis = {}

        for metric in affected_metrics:
            metric_df = df[df['name'] == metric]
            if metric_df.empty:
                continue

            values = metric_df['value'].values
            analysis[metric] = {
                'first_anomaly': self._find_first_anomaly(metric_df),
                'max_deviation': float(np.max(np.abs(values - np.mean(values)))),
                'duration': len(metric_df),
                'pattern': self._classify_incident_pattern(values)
            }

        return analysis

    def _find_first_anomaly(self, df: pd.DataFrame) -> Optional[str]:
        """Find when metric first showed anomaly."""
        values = df['value'].values
        mean = np.mean(values)
        std = np.std(values)

        for idx, value in zip(df.index, values):
            if abs(value - mean) > 3 * std:
                return idx.isoformat()

        return None

    def _classify_incident_pattern(self, values: np.ndarray) -> str:
        """Classify the incident pattern."""
        if len(values) < 3:
            return "unknown"

        # Check for spike
        if np.max(values) > np.mean(values) + 3 * np.std(values):
            return "spike"

        # Check for drop
        if np.min(values) < np.mean(values) - 3 * np.std(values):
            return "drop"

        # Check for gradual increase
        trend = np.polyfit(range(len(values)), values, 1)[0]
        if trend > np.std(values):
            return "gradual_increase"

        # Check for oscillation
        zero_crossings = len(np.where(np.diff(np.sign(values - np.mean(values))))[0])
        if zero_crossings > len(values) * 0.3:
            return "oscillation"

        return "irregular"

    def _find_correlated_metrics(
        self,
        df: pd.DataFrame,
        affected_metrics: List[str]
    ) -> List[Dict[str, Any]]:
        """Find metrics correlated with affected ones."""
        correlated = []
        all_metrics = df['name'].unique()

        for affected in affected_metrics:
            affected_df = df[df['name'] == affected]['value']

            for metric in all_metrics:
                if metric == affected:
                    continue

                metric_df = df[df['name'] == metric]['value']

                # Align and calculate correlation
                aligned = pd.concat([affected_df, metric_df], axis=1, join='inner')
                if len(aligned) < 10:
                    continue

                correlation = aligned.corr().iloc[0, 1]

                if abs(correlation) > 0.7:
                    correlated.append({
                        'metric1': affected,
                        'metric2': metric,
                        'correlation': float(correlation)
                    })

        return correlated

    def _analyze_propagation(
        self,
        df: pd.DataFrame,
        affected_metrics: List[str]
    ) -> List[Dict[str, Any]]:
        """Analyze how issue propagated."""
        propagation = []

        # Sort metrics by when they first showed anomaly
        anomaly_times = {}

        for metric in affected_metrics:
            metric_df = df[df['name'] == metric]
            if not metric_df.empty:
                first_anomaly = self._find_first_anomaly(metric_df)
                if first_anomaly:
                    anomaly_times[metric] = datetime.fromisoformat(first_anomaly)

        # Sort by time
        sorted_metrics = sorted(anomaly_times.items(), key=lambda x: x[1])

        for i, (metric, time) in enumerate(sorted_metrics):
            propagation.append({
                'order': i + 1,
                'metric': metric,
                'anomaly_time': time.isoformat(),
                'delay_from_first': (time - sorted_metrics[0][1]).total_seconds() if i > 0 else 0
            })

        return propagation

    def _identify_root_cause(
        self,
        metric_analysis: Dict[str, Any],
        correlated: List[Dict[str, Any]],
        propagation: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Identify most likely root cause."""
        if not propagation:
            return {'metric': 'unknown', 'confidence': 0.0}

        # First metric in propagation chain is likely root cause
        root_metric = propagation[0]['metric']

        # Calculate confidence based on evidence
        confidence = 0.6  # Base confidence for being first

        # Higher confidence if this metric affects many others
        affected_count = sum(1 for c in correlated if c['metric1'] == root_metric)
        if affected_count > 2:
            confidence += 0.2

        # Check if pattern suggests root cause
        if root_metric in metric_analysis:
            pattern = metric_analysis[root_metric].get('pattern')
            if pattern in ['spike', 'drop']:
                confidence += 0.1

        return {
            'metric': root_metric,
            'confidence': min(confidence, 0.95),
            'evidence': [
                f"First metric to show anomaly",
                f"Affects {affected_count} other metrics",
                f"Pattern: {pattern if root_metric in metric_analysis else 'unknown'}"
            ]
        }

    def _generate_remediation(self, root_cause: Dict[str, Any]) -> List[str]:
        """Generate remediation recommendations."""
        recommendations = []
        metric = root_cause['metric']

        # Generic recommendations based on metric type
        if 'cpu' in metric.lower():
            recommendations.append("Check for runaway processes")
            recommendations.append("Consider scaling compute resources")
        elif 'memory' in metric.lower():
            recommendations.append("Check for memory leaks")
            recommendations.append("Increase memory allocation")
        elif 'disk' in metric.lower():
            recommendations.append("Check disk usage and clean up if needed")
            recommendations.append("Increase disk capacity")
        elif 'network' in metric.lower():
            recommendations.append("Check network connectivity")
            recommendations.append("Review firewall rules")
        elif 'error' in metric.lower():
            recommendations.append("Check application logs for errors")
            recommendations.append("Review recent deployments")

        recommendations.append(f"Monitor {metric} closely for recurrence")

        return recommendations


class CapacityPlanner(MetricAnalyzer):
    """Capacity planning analyzer."""

    def __init__(self):
        super().__init__()
        self.growth_models = {}
        self.capacity_limits = {}

    async def analyze(self, metrics: List[Metric]) -> Dict[str, Any]:
        """Analyze capacity requirements."""
        df = self.prepare_data(metrics)

        if df.empty:
            return {}

        capacity_analysis = {
            'current_utilization': {},
            'growth_projections': {},
            'capacity_requirements': {},
            'recommendations': []
        }

        for metric_name in df['name'].unique():
            if not self._is_capacity_metric(metric_name):
                continue

            metric_df = df[df['name'] == metric_name]

            # Current utilization
            current = float(metric_df['value'].iloc[-1])
            capacity_analysis['current_utilization'][metric_name] = current

            # Growth projection
            growth = self._project_growth(metric_df)
            capacity_analysis['growth_projections'][metric_name] = growth

            # Future requirements
            requirements = self._calculate_requirements(current, growth)
            capacity_analysis['capacity_requirements'][metric_name] = requirements

            # Generate recommendations
            if requirements['action_needed']:
                capacity_analysis['recommendations'].append({
                    'metric': metric_name,
                    'action': requirements['action'],
                    'timeline': requirements['timeline'],
                    'increase_needed': requirements['increase_percent']
                })

        return capacity_analysis

    def _is_capacity_metric(self, metric_name: str) -> bool:
        """Check if metric is capacity-related."""
        capacity_keywords = [
            'cpu', 'memory', 'disk', 'bandwidth',
            'connections', 'threads', 'queue'
        ]
        return any(kw in metric_name.lower() for kw in capacity_keywords)

    def _project_growth(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Project future growth."""
        values = df['value'].values

        # Calculate growth rate
        if len(values) < 30:
            return {'rate': 0, 'type': 'insufficient_data'}

        # Fit linear and exponential models
        x = np.arange(len(values))

        # Linear model
        linear_coeffs = np.polyfit(x, values, 1)
        linear_rate = linear_coeffs[0]

        # Exponential model (log-linear)
        if np.all(values > 0):
            log_values = np.log(values)
            exp_coeffs = np.polyfit(x, log_values, 1)
            exp_rate = exp_coeffs[0]
        else:
            exp_rate = 0

        # Choose best model based on R-squared
        linear_r2 = np.corrcoef(x, values)[0, 1] ** 2
        exp_r2 = np.corrcoef(x, log_values)[0, 1] ** 2 if exp_rate != 0 else 0

        if exp_r2 > linear_r2 and exp_r2 > 0.7:
            return {
                'type': 'exponential',
                'rate': float(exp_rate),
                'daily_growth_percent': float((np.exp(exp_rate * 1440) - 1) * 100),
                'r_squared': float(exp_r2)
            }
        else:
            return {
                'type': 'linear',
                'rate': float(linear_rate),
                'daily_growth': float(linear_rate * 1440),
                'r_squared': float(linear_r2)
            }

    def _calculate_requirements(
        self,
        current: float,
        growth: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate capacity requirements."""
        requirements = {
            'action_needed': False,
            'action': None,
            'timeline': None,
            'increase_percent': 0
        }

        # Assume 80% is the threshold for action
        threshold = 80

        if current > threshold:
            requirements['action_needed'] = True
            requirements['action'] = "Immediate capacity increase needed"
            requirements['timeline'] = "immediate"
            requirements['increase_percent'] = 50
        elif growth['type'] == 'linear' and growth['rate'] > 0:
            # Calculate when threshold will be reached
            days_to_threshold = (threshold - current) / growth.get('daily_growth', 1)

            if days_to_threshold < 30:
                requirements['action_needed'] = True
                requirements['action'] = "Capacity increase needed soon"
                requirements['timeline'] = f"{int(days_to_threshold)} days"
                requirements['increase_percent'] = 30
        elif growth['type'] == 'exponential' and growth['rate'] > 0:
            # More urgent for exponential growth
            daily_growth = growth.get('daily_growth_percent', 0)

            if daily_growth > 5:
                requirements['action_needed'] = True
                requirements['action'] = "Urgent capacity planning needed"
                requirements['timeline'] = "within 1 week"
                requirements['increase_percent'] = 100

        return requirements


class PerformanceAnalyzer(MetricAnalyzer):
    """Performance analysis for services and applications."""

    def __init__(self):
        super().__init__()
        self.sla_targets = {}
        self.baseline_performance = {}

    async def analyze(self, metrics: List[Metric]) -> Dict[str, Any]:
        """Analyze performance metrics."""
        df = self.prepare_data(metrics)

        if df.empty:
            return {}

        analysis = {
            'response_times': self._analyze_response_times(df),
            'error_rates': self._analyze_error_rates(df),
            'throughput': self._analyze_throughput(df),
            'saturation': self._analyze_saturation(df),
            'sla_compliance': self._check_sla_compliance(df),
            'bottlenecks': self._identify_bottlenecks(df),
            'optimization_opportunities': self._find_optimizations(df)
        }

        return analysis

    def _analyze_response_times(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze response time metrics."""
        response_metrics = df[df['name'].str.contains('response|latency', case=False)]

        if response_metrics.empty:
            return {}

        analysis = {}
        for metric in response_metrics['name'].unique():
            metric_df = response_metrics[response_metrics['name'] == metric]
            values = metric_df['value'].values

            analysis[metric] = {
                'avg': float(np.mean(values)),
                'p50': float(np.percentile(values, 50)),
                'p95': float(np.percentile(values, 95)),
                'p99': float(np.percentile(values, 99)),
                'trend': self._calculate_trend_direction(metric_df),
                'variability': float(np.std(values) / np.mean(values)) if np.mean(values) > 0 else 0
            }

        return analysis

    def _analyze_error_rates(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze error rate metrics."""
        error_metrics = df[df['name'].str.contains('error|fail', case=False)]

        if error_metrics.empty:
            return {}

        analysis = {}
        for metric in error_metrics['name'].unique():
            metric_df = error_metrics[error_metrics['name'] == metric]
            values = metric_df['value'].values

            analysis[metric] = {
                'current': float(values[-1]) if len(values) > 0 else 0,
                'avg': float(np.mean(values)),
                'max': float(np.max(values)),
                'increasing': np.polyfit(range(len(values)), values, 1)[0] > 0,
                'spikes': len(find_peaks(values, prominence=np.std(values))[0])
            }

        return analysis

    def _analyze_throughput(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze throughput metrics."""
        throughput_metrics = df[df['name'].str.contains('throughput|requests|transactions', case=False)]

        if throughput_metrics.empty:
            return {}

        analysis = {}
        for metric in throughput_metrics['name'].unique():
            metric_df = throughput_metrics[throughput_metrics['name'] == metric]
            values = metric_df['value'].values

            analysis[metric] = {
                'current': float(values[-1]) if len(values) > 0 else 0,
                'avg': float(np.mean(values)),
                'peak': float(np.max(values)),
                'capacity_utilization': float(values[-1] / np.max(values) * 100) if np.max(values) > 0 else 0
            }

        return analysis

    def _analyze_saturation(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze resource saturation."""
        saturation = {}

        # CPU saturation
        cpu_metrics = df[df['name'].str.contains('cpu', case=False)]
        if not cpu_metrics.empty:
            cpu_values = cpu_metrics['value'].values
            saturation['cpu'] = {
                'current': float(cpu_values[-1]) if len(cpu_values) > 0 else 0,
                'saturated': cpu_values[-1] > 80 if len(cpu_values) > 0 else False,
                'time_above_80': len(cpu_values[cpu_values > 80]) / len(cpu_values) * 100 if len(cpu_values) > 0 else 0
            }

        # Memory saturation
        mem_metrics = df[df['name'].str.contains('memory', case=False)]
        if not mem_metrics.empty:
            mem_values = mem_metrics['value'].values
            saturation['memory'] = {
                'current': float(mem_values[-1]) if len(mem_values) > 0 else 0,
                'saturated': mem_values[-1] > 85 if len(mem_values) > 0 else False,
                'time_above_85': len(mem_values[mem_values > 85]) / len(mem_values) * 100 if len(mem_values) > 0 else 0
            }

        return saturation

    def _check_sla_compliance(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Check SLA compliance."""
        compliance = {}

        for sla_metric, targets in self.sla_targets.items():
            metric_df = df[df['name'] == sla_metric]
            if metric_df.empty:
                continue

            values = metric_df['value'].values
            compliant_values = values[values <= targets['threshold']]
            compliance_rate = len(compliant_values) / len(values) * 100

            compliance[sla_metric] = {
                'target': targets['target'],
                'threshold': targets['threshold'],
                'compliance_rate': float(compliance_rate),
                'compliant': compliance_rate >= targets['target'],
                'violations': len(values) - len(compliant_values)
            }

        return compliance

    def _identify_bottlenecks(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Identify performance bottlenecks."""
        bottlenecks = []

        # Check for correlated high usage
        high_usage_metrics = []
        for metric in df['name'].unique():
            metric_df = df[df['name'] == metric]
            if metric_df['value'].iloc[-1] > 80:
                high_usage_metrics.append(metric)

        if len(high_usage_metrics) > 1:
            bottlenecks.append({
                'type': 'resource_contention',
                'metrics': high_usage_metrics,
                'severity': 'high' if len(high_usage_metrics) > 3 else 'medium'
            })

        # Check for queuing
        queue_metrics = df[df['name'].str.contains('queue', case=False)]
        for metric in queue_metrics['name'].unique():
            metric_df = queue_metrics[queue_metrics['name'] == metric]
            if metric_df['value'].iloc[-1] > metric_df['value'].mean() * 2:
                bottlenecks.append({
                    'type': 'queuing',
                    'metric': metric,
                    'severity': 'medium'
                })

        return bottlenecks

    def _find_optimizations(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Find optimization opportunities."""
        optimizations = []

        # Check for underutilized resources
        for metric in df['name'].unique():
            if 'cpu' in metric.lower() or 'memory' in metric.lower():
                metric_df = df[df['name'] == metric]
                values = metric_df['value'].values

                if np.max(values) < 30:
                    optimizations.append({
                        'type': 'underutilization',
                        'metric': metric,
                        'recommendation': f"Consider reducing allocation for {metric}",
                        'potential_savings': '30-50%'
                    })

        # Check for inefficient patterns
        for metric in df['name'].unique():
            metric_df = df[df['name'] == metric]
            values = metric_df['value'].values

            # High variability suggests inefficiency
            cv = np.std(values) / np.mean(values) if np.mean(values) > 0 else 0
            if cv > 1:
                optimizations.append({
                    'type': 'high_variability',
                    'metric': metric,
                    'recommendation': f"Investigate and stabilize {metric}",
                    'impact': 'performance_improvement'
                })

        return optimizations


class SecurityAnalyzer(MetricAnalyzer):
    """Security-focused metric analysis."""

    def __init__(self):
        super().__init__()
        self.threat_patterns = {}
        self.security_baselines = {}

    async def analyze(self, metrics: List[Metric]) -> Dict[str, Any]:
        """Analyze metrics for security issues."""
        df = self.prepare_data(metrics)

        if df.empty:
            return {}

        analysis = {
            'threat_indicators': self._detect_threat_indicators(df),
            'anomalous_access': self._detect_anomalous_access(df),
            'ddos_indicators': self._detect_ddos_patterns(df),
            'brute_force': self._detect_brute_force(df),
            'data_exfiltration': self._detect_exfiltration(df),
            'compliance_violations': self._check_compliance(df),
            'risk_score': self._calculate_risk_score(df)
        }

        return analysis

    def _detect_threat_indicators(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect potential security threats."""
        threats = []

        # Check for unusual authentication patterns
        auth_metrics = df[df['name'].str.contains('auth|login', case=False)]
        for metric in auth_metrics['name'].unique():
            metric_df = auth_metrics[auth_metrics['name'] == metric]
            values = metric_df['value'].values

            # Sudden spike in failed auth
            if 'fail' in metric.lower():
                recent_avg = np.mean(values[-10:]) if len(values) >= 10 else np.mean(values)
                historical_avg = np.mean(values)

                if recent_avg > historical_avg * 3:
                    threats.append({
                        'type': 'auth_anomaly',
                        'metric': metric,
                        'severity': 'high',
                        'description': 'Unusual authentication failure rate'
                    })

        return threats

    def _detect_anomalous_access(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect anomalous access patterns."""
        anomalies = []

        # Check for off-hours access
        access_metrics = df[df['name'].str.contains('access|connection', case=False)]
        for metric in access_metrics['name'].unique():
            metric_df = access_metrics[access_metrics['name'] == metric]

            # Group by hour
            hourly_access = metric_df.groupby(metric_df.index.hour)['value'].mean()

            # Check for unusual off-hours activity
            night_hours = [0, 1, 2, 3, 4, 5]
            night_activity = hourly_access[hourly_access.index.isin(night_hours)]

            if not night_activity.empty and night_activity.mean() > hourly_access.mean() * 0.5:
                anomalies.append({
                    'type': 'off_hours_access',
                    'metric': metric,
                    'severity': 'medium',
                    'description': 'Significant off-hours activity detected'
                })

        return anomalies

    def _detect_ddos_patterns(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Detect DDoS attack patterns."""
        ddos_indicators = {
            'detected': False,
            'confidence': 0.0,
            'indicators': []
        }

        # Check connection rate
        conn_metrics = df[df['name'].str.contains('connection|request', case=False)]
        for metric in conn_metrics['name'].unique():
            metric_df = conn_metrics[conn_metrics['name'] == metric]
            values = metric_df['value'].values

            if len(values) < 10:
                continue

            # Check for sudden spike
            recent = np.mean(values[-5:])
            baseline = np.mean(values[:-5])

            if recent > baseline * 10:
                ddos_indicators['detected'] = True
                ddos_indicators['confidence'] += 0.3
                ddos_indicators['indicators'].append('connection_spike')

        # Check for resource exhaustion
        resource_metrics = df[df['name'].str.contains('cpu|memory|bandwidth', case=False)]
        exhausted_resources = 0
        for metric in resource_metrics['name'].unique():
            metric_df = resource_metrics[resource_metrics['name'] == metric]
            if metric_df['value'].iloc[-1] > 90:
                exhausted_resources += 1

        if exhausted_resources >= 2:
            ddos_indicators['detected'] = True
            ddos_indicators['confidence'] += 0.4
            ddos_indicators['indicators'].append('resource_exhaustion')

        ddos_indicators['confidence'] = min(ddos_indicators['confidence'], 1.0)
        return ddos_indicators

    def _detect_brute_force(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Detect brute force attack patterns."""
        brute_force = {
            'detected': False,
            'sources': [],
            'target_accounts': []
        }

        # Check for repeated failed authentication
        failed_auth = df[df['name'].str.contains('auth.*fail|login.*fail', case=False)]

        for metric in failed_auth['name'].unique():
            metric_df = failed_auth[failed_auth['name'] == metric]
            values = metric_df['value'].values

            # Check for pattern: many failures followed by success
            if len(values) > 10:
                failures = values[-10:-1]
                if np.mean(failures) > 5:  # High failure rate
                    brute_force['detected'] = True

        return brute_force

    def _detect_exfiltration(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Detect potential data exfiltration."""
        exfiltration = {
            'detected': False,
            'confidence': 0.0,
            'indicators': []
        }

        # Check for unusual outbound traffic
        outbound = df[df['name'].str.contains('outbound|upload|egress', case=False)]

        for metric in outbound['name'].unique():
            metric_df = outbound[outbound['name'] == metric]
            values = metric_df['value'].values

            if len(values) < 20:
                continue

            # Check for unusual patterns
            recent = np.mean(values[-10:])
            historical = np.mean(values[:-10])

            if recent > historical * 5:
                exfiltration['detected'] = True
                exfiltration['confidence'] += 0.5
                exfiltration['indicators'].append('unusual_outbound_traffic')

        return exfiltration

    def _check_compliance(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Check for compliance violations."""
        violations = []

        # Check encryption metrics
        encryption = df[df['name'].str.contains('encrypt|tls|ssl', case=False)]
        for metric in encryption['name'].unique():
            if 'unencrypted' in metric.lower() or 'plain' in metric.lower():
                metric_df = encryption[encryption['name'] == metric]
                if metric_df['value'].iloc[-1] > 0:
                    violations.append({
                        'type': 'encryption_violation',
                        'metric': metric,
                        'severity': 'high',
                        'framework': 'PCI-DSS, HIPAA'
                    })

        return violations

    def _calculate_risk_score(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Calculate overall security risk score."""
        risk_score = 0.0
        risk_factors = []

        # Check various risk indicators
        if len(self._detect_threat_indicators(df)) > 0:
            risk_score += 0.3
            risk_factors.append('threat_indicators')

        if self._detect_ddos_patterns(df)['detected']:
            risk_score += 0.3
            risk_factors.append('ddos_indicators')

        if self._detect_brute_force(df)['detected']:
            risk_score += 0.2
            risk_factors.append('brute_force_detected')

        if self._detect_exfiltration(df)['detected']:
            risk_score += 0.2
            risk_factors.append('possible_exfiltration')

        risk_level = 'low'
        if risk_score > 0.7:
            risk_level = 'critical'
        elif risk_score > 0.5:
            risk_level = 'high'
        elif risk_score > 0.3:
            risk_level = 'medium'

        return {
            'score': min(risk_score, 1.0),
            'level': risk_level,
            'factors': risk_factors
        }