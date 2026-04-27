from importlib.metadata import PackageNotFoundError, version as _metadata_version

from .analyzer import PasswordAnalyzer
from .models import CriterionResult, PasswordAnalysis
from .scoring import max_possible_score

try:
    __version__: str = _metadata_version("securearmor")
except PackageNotFoundError:
    __version__ = "0.0.0+dev"

__all__ = [
    "__version__",
    "PasswordAnalyzer",
    "PasswordAnalysis",
    "CriterionResult",
    "max_possible_score",
]