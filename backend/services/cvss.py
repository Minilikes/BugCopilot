"""CVSS v3.1 calculator — interactive widget support + vector string parsing."""

from dataclasses import dataclass
from typing import Optional
import re

# CVSS 3.1 metric weights
AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC_WEIGHTS = {"L": 0.77, "H": 0.44}
PR_WEIGHTS_US = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_WEIGHTS_S  = {"N": 0.85, "L": 0.68, "H": 0.50}
UI_WEIGHTS = {"N": 0.85, "R": 0.62}
C_I_A_WEIGHTS = {"N": 0.0, "L": 0.22, "H": 0.56}
SCOPE_CHANGED = {"U": False, "C": True}


@dataclass
class CVSSMetrics:
    AV: str = "N"   # Attack Vector: N/A/L/P
    AC: str = "L"   # Attack Complexity: L/H
    PR: str = "N"   # Privileges Required: N/L/H
    UI: str = "N"   # User Interaction: N/R
    S:  str = "U"   # Scope: U/C
    C:  str = "N"   # Confidentiality: N/L/H
    I:  str = "N"   # Integrity: N/L/H
    A:  str = "N"   # Availability: N/L/H


def calculate_cvss(m: CVSSMetrics) -> tuple[float, str]:
    """
    Calculate CVSS 3.1 base score and severity label.
    Returns (score, severity_label).
    """
    scope_changed = SCOPE_CHANGED.get(m.S, False)

    av = AV_WEIGHTS.get(m.AV, 0.85)
    ac = AC_WEIGHTS.get(m.AC, 0.77)
    pr = PR_WEIGHTS_S[m.PR] if scope_changed else PR_WEIGHTS_US.get(m.PR, 0.85)
    ui = UI_WEIGHTS.get(m.UI, 0.85)

    isc_base = 1 - (
        (1 - C_I_A_WEIGHTS.get(m.C, 0)) *
        (1 - C_I_A_WEIGHTS.get(m.I, 0)) *
        (1 - C_I_A_WEIGHTS.get(m.A, 0))
    )

    if scope_changed:
        isc = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
    else:
        isc = 6.42 * isc_base

    exploitability = 8.22 * av * ac * pr * ui

    if isc <= 0:
        base = 0.0
    elif scope_changed:
        base = min(1.08 * (isc + exploitability), 10.0)
    else:
        base = min(isc + exploitability, 10.0)

    # Round up to 1 decimal (CVSS spec: ceiling)
    import math
    base = math.ceil(base * 10) / 10

    if base == 0.0:
        label = "None"
    elif base < 4.0:
        label = "Low"
    elif base < 7.0:
        label = "Medium"
    elif base < 9.0:
        label = "High"
    else:
        label = "Critical"

    return round(base, 1), label


def vector_string(m: CVSSMetrics) -> str:
    return f"CVSS:3.1/AV:{m.AV}/AC:{m.AC}/PR:{m.PR}/UI:{m.UI}/S:{m.S}/C:{m.C}/I:{m.I}/A:{m.A}"


def parse_vector(vector: str) -> Optional[CVSSMetrics]:
    """Parse a CVSS 3.x vector string into CVSSMetrics."""
    pattern = re.compile(
        r"AV:([NALP])/AC:([LH])/PR:([NLH])/UI:([NR])/S:([UC])/C:([NLH])/I:([NLH])/A:([NLH])"
    )
    m = pattern.search(vector)
    if not m:
        return None
    av, ac, pr, ui, s, c, i, a = m.groups()
    return CVSSMetrics(AV=av, AC=ac, PR=pr, UI=ui, S=s, C=c, I=i, A=a)


# Bounty tier estimation based on severity + vuln class
BOUNTY_ESTIMATES = {
    "Critical": (5000, 50000),
    "High":     (1000, 10000),
    "Medium":   (300, 2000),
    "Low":      (50, 500),
    "None":     (0, 0),
}


def estimate_bounty(severity: str) -> tuple[int, int]:
    return BOUNTY_ESTIMATES.get(severity, (0, 0))
