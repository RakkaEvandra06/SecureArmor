"""PassCheck — Password Strength Analyser."""
from importlib.metadata import PackageNotFoundError, version as _metadata_version

from .analyzer import PasswordAnalyzer
from .models import CriterionResult, PasswordAnalysis, SkipReason
from .scoring import AnalysisSummary, criteria_summary, effective_max_score, score_bar

try:
    __version__: str = _metadata_version("securearmor")
except PackageNotFoundError:
    __version__ = "0.0.0+dev"

__all__ = [
    "__version__",
    "PasswordAnalyzer",
    "PasswordAnalysis",
    "CriterionResult",
    "SkipReason",
    "AnalysisSummary",
    "criteria_summary",
    "effective_max_score",
    "score_bar",
]