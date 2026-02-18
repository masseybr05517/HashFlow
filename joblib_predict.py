# joblib_predict.py
import joblib
import numpy as np

_model = None
_expected_n = None

def init(model_path: str, expected_n: int = 27):
    """Load model once and cache it."""
    global _model, _expected_n
    if _model is None:
        _model = joblib.load(model_path)
        _expected_n = int(expected_n)
    return True

def predict_proba_1(x_list):
    """
    x_list: list/tuple of floats length 27
    returns probability of class=1 (float)
    """
    if _model is None:
        raise RuntimeError("Model not initialized. Call init(model_path) first.")
    x = np.asarray(x_list, dtype=np.float64)
    if x.ndim != 1 or x.shape[0] != _expected_n:
        raise ValueError(f"Expected {_expected_n} features, got shape {x.shape}")
    X = x.reshape(1, -1)

    # sklearn classifiers/pipelines support predict_proba
    proba = _model.predict_proba(X)
    return float(proba[0, 1])
