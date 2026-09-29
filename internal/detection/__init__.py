"""
Rule-based detection layer.

Komponen:
- DetectionRule       : Protocol rule
- DetectionFinding    : hasil deteksi satu rule
- SigmaRuleLoader     : parse & match Sigma-like rules
- LOLBinDetector      : deteksi living-off-the-land binaries
- DetectionEngine     : orkestrasi semua rule

Deterministic. Tidak ada LLM, tidak ada I/O jaringan.
"""

from internal.detection.base import (
    DetectionFinding,
    DetectionRule,
    Severity,
)
from internal.detection.lolbin import LOLBinDetector
from internal.detection.sigma_loader import SigmaRuleLoader
from internal.detection.engine import DetectionEngine

__all__ = [
    "DetectionFinding",
    "DetectionRule",
    "Severity",
    "LOLBinDetector",
    "SigmaRuleLoader",
    "DetectionEngine",
]
