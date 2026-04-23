from importlib.metadata import PackageNotFoundError, version

from .analyzer import PasswordAnalyzer
from .models import CriterionResult, PasswordAnalysis
from .scoring import max_possible_score

__version__: str = "3.0"

__all__ = [
    "PasswordAnalyzer",
    "PasswordAnalysis",
    "CriterionResult",
    "max_possible_score",
]