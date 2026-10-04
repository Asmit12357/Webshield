"""Scoring: earned points / applicable points, scaled to 100.

Checks with status "na" have max 0 and do not count for or against the site.
A site whose TLS certificate is rejected is capped at CERT_FAIL_CAP, because
nothing else it does protects visitors from interception.
"""
CERT_FAIL_CAP = 50

GRADES = ((95, "A+"), (85, "A"), (75, "B"), (60, "C"), (40, "D"))


def calculate_score(checks):
    earned = sum(c["points"] for c in checks)
    possible = sum(c["max"] for c in checks)
    score = round(100 * earned / possible) if possible else 0
    if any(c["key"] == "certificate" and c["status"] == "fail" for c in checks):
        score = min(score, CERT_FAIL_CAP)
    return score


def grade_for(score):
    for threshold, letter in GRADES:
        if score >= threshold:
            return letter
    return "F"
