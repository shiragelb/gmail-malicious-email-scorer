"""Display-name spoofing from the testing plan."""

from app.layers.spoofing import detect_display_name_spoof


def test_google_display_name_from_an_unrelated_domain_is_high_risk():
    result = detect_display_name_spoof("Google Security", "attacker@malicious-domain.ru")
    assert result.spoofing_detected is True
    assert result.risk_weight == "high"
    assert result.points >= 20
    assert result.matched_brand == "Google"


def test_google_display_name_from_gmail_is_not_spoofing():
    result = detect_display_name_spoof("Google Security", "alert@gmail.com")
    assert result.spoofing_detected is False
    assert result.risk_weight == "none"


def test_personal_name_that_shares_a_short_brand_token_is_not_spoofing():
    result = detect_display_name_spoof("Chase Smith", "chase.smith@gmail.com")
    assert result.spoofing_detected is False
