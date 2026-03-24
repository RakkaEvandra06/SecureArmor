"""
passcheck — Password Strength Analyser
"""

from .analyzer import PasswordAnalyzer
from .models import CriterionResult, PasswordAnalysis

__all__ = ["PasswordAnalyzer", "PasswordAnalysis", "CriterionResult"]
__version__ = "3.0"
