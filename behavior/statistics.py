import math
from typing import List

def mean(values: List[float]) -> float:
    """Calculate the mathematical mean of a list of numbers."""
    if not values: return 0.0
    return sum(values) / len(values)

def std_dev(values: List[float]) -> float:
    """Calculate the standard deviation of a list of numbers."""
    if not values or len(values) < 2: return 0.0
    m = mean(values)
    variance = sum((x - m) ** 2 for x in values) / (len(values) - 1)
    return math.sqrt(variance)

def z_score(value: float, mean_val: float, std_val: float) -> float:
    """Calculate the Z-Score of a given value."""
    if std_val == 0: return 0.0
    return (value - mean_val) / std_val

def moving_average(values: List[float], window: int) -> List[float]:
    """Calculate the moving average over a specific window."""
    if not values or window <= 0: return []
    result = []
    for i in range(len(values) - window + 1):
        window_slice = values[i:i + window]
        result.append(mean(window_slice))
    return result
