from score import calculate_score, grade_for


def chk(key, status, pts, mx):
    return {"key": key, "status": status, "points": pts, "max": mx}


def test_perfect_and_zero():
    assert calculate_score([chk("a", "pass", 10, 10), chk("b", "pass", 5, 5)]) == 100
    assert calculate_score([chk("a", "fail", 0, 10)]) == 0


def test_na_checks_do_not_count():
    assert calculate_score([chk("a", "pass", 10, 10), chk("b", "na", 0, 0)]) == 100


def test_no_checks_scores_zero():
    assert calculate_score([]) == 0


def test_bad_certificate_caps_score():
    checks = [chk("certificate", "fail", 0, 15), chk("a", "pass", 85, 85)]
    assert calculate_score(checks) == 50


def test_grades():
    assert [grade_for(s) for s in (100, 95, 94, 85, 75, 60, 40, 39, 0)] == ["A+", "A+", "A", "A", "B", "C", "D", "F", "F"]
