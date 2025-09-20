"""
Mock sklearn imports for testing when scikit-learn is not installed
"""


class IsolationForest:
    def __init__(self, contamination=0.1, random_state=None):
        """TODO: Add docstring"""
        self.contamination = contamination
        self.random_state = random_state

    def fit(self, X, y=None):
        """TODO: Add docstring"""
        return self

    def predict(self, X):
        """TODO: Add docstring"""
        import numpy as np

        return np.ones(X.shape[0])

    def decision_function(self, X):
        """TODO: Add docstring"""
        import numpy as np

        return np.zeros(X.shape[0])


class RandomForestClassifier:
    def __init__(self, n_estimators=100, random_state=None):
        """TODO: Add docstring"""
        self.n_estimators = n_estimators
        self.random_state = random_state

    def fit(self, X, y):
        """TODO: Add docstring"""
        return self

    def predict(self, X):
        """TODO: Add docstring"""
        import numpy as np

        return np.zeros(X.shape[0])

    def predict_proba(self, X):
        """TODO: Add docstring"""
        import numpy as np

        return np.array([[0.5, 0.5] for _ in range(X.shape[0])])


class DBSCAN:
    def __init__(self, eps=0.5, min_samples=5):
        """TODO: Add docstring"""
        self.eps = eps
        self.min_samples = min_samples

    def fit(self, X, y=None):
        """TODO: Add docstring"""
        return self

    def fit_predict(self, X):
        """TODO: Add docstring"""
        import numpy as np

        return np.zeros(X.shape[0])


class StandardScaler:
    def __init__(self):
        """TODO: Add docstring"""
        self.mean_ = None
        self.scale_ = None

    def fit(self, X):
        """TODO: Add docstring"""
        import numpy as np

        self.mean_ = np.mean(X, axis=0)
        self.scale_ = np.std(X, axis=0)
        return self

    def transform(self, X):
        """TODO: Add docstring"""
        if self.mean_ is None:
            self.fit(X)
        return (X - self.mean_) / (self.scale_ + 1e-8)

    def fit_transform(self, X):
        """TODO: Add docstring"""
        self.fit(X)
        return self.transform(X)


class PCA:
    def __init__(self, n_components=2):
        """TODO: Add docstring"""
        self.n_components = n_components

    def fit(self, X):
        """TODO: Add docstring"""
        return self

    def transform(self, X):
        """TODO: Add docstring"""
        return X[:, : self.n_components] if X.shape[1] >= self.n_components else X

    def fit_transform(self, X):
        """TODO: Add docstring"""
        self.fit(X)
        return self.transform(X)
