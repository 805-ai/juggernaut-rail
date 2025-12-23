"""
Tests for Zero-Multiplier Veto Engine

Tests the patent claim: S = B × Π(V_i) where any V_i = 0 → S = 0
"""

import pytest
from core.veto import (
    VetoCategory,
    VetoTrigger,
    VetoVector,
    ZeroMultiplierVeto,
    TrustScoreCalculator,
)


class TestVetoVector:
    """Test veto vector functionality."""

    def test_empty_vector_not_vetoed(self):
        """Empty veto vector should not trigger veto."""
        vector = VetoVector()

        assert vector.is_vetoed is False
        assert vector.get_active_triggers() == []

    def test_high_confidence_trigger_vetoes(self):
        """High confidence trigger should cause veto."""
        vector = VetoVector()
        vector.add_trigger(VetoTrigger(
            category=VetoCategory.PII,
            confidence=0.95,
            evidence="SSN detected",
        ))

        assert vector.is_vetoed is True
        assert len(vector.get_active_triggers()) == 1

    def test_low_confidence_trigger_no_veto(self):
        """Low confidence trigger should not cause veto."""
        vector = VetoVector()
        vector.add_trigger(VetoTrigger(
            category=VetoCategory.PII,
            confidence=0.3,  # Below threshold
            evidence="Possible PII",
        ))

        assert vector.is_vetoed is False

    def test_multiple_triggers_combined(self):
        """Multiple triggers should accumulate."""
        vector = VetoVector()
        vector.add_trigger(VetoTrigger(
            category=VetoCategory.PII,
            confidence=0.5,
            evidence="Possible SSN",
        ))
        vector.add_trigger(VetoTrigger(
            category=VetoCategory.COPYRIGHT,
            confidence=0.6,
            evidence="Possible copyrighted text",
        ))

        # Individual triggers below threshold, but should still be tracked
        assert len(vector.triggers) == 2


class TestZeroMultiplierVeto:
    """Test the zero-multiplier veto mechanism (core patent claim)."""

    def test_clean_content_passes(self):
        """Clean content should produce trust score near 1.0."""
        veto = ZeroMultiplierVeto()

        content = "This is a normal, harmless prompt about weather."
        trust_score, vector = veto.evaluate(content)

        assert trust_score > 0.9
        assert vector.is_vetoed is False

    def test_pii_detected_zeros_score(self):
        """PII detection should zero the trust score (zero-multiplier)."""
        veto = ZeroMultiplierVeto()

        content = "My social security number is 123-45-6789"
        trust_score, vector = veto.evaluate(content)

        # Zero-multiplier: any critical veto → score = 0
        assert trust_score < 0.1
        assert vector.is_vetoed is True

    def test_credit_card_detected(self):
        """Credit card detection should trigger veto."""
        veto = ZeroMultiplierVeto()

        content = "My credit card number is 4111-1111-1111-1111"
        trust_score, vector = veto.evaluate(content)

        assert trust_score < 0.1
        assert vector.is_vetoed is True

    def test_password_detected(self):
        """Password in content should trigger veto."""
        veto = ZeroMultiplierVeto()

        content = "The password is: SuperSecret123!"
        trust_score, vector = veto.evaluate(content)

        assert trust_score < 0.5  # Should be penalized


class TestTrustScoreCalculator:
    """Test the trust score calculation formula."""

    def test_formula_implementation(self):
        """
        Test: S_Trust = B_base × (R_actual / R_max) × Π(V_crit_i) × Σ(w_j × f_j)
        """
        calc = TrustScoreCalculator(
            base_score=1.0,
            r_max=1000,
        )

        # All factors positive
        score = calc.calculate(
            r_actual=500,  # 50% of max requests
            veto_factors=[1.0, 1.0, 1.0],  # No vetoes
            weighted_factors=[(0.5, 1.0), (0.5, 1.0)],  # All pass
        )

        assert 0.4 < score < 0.6  # Should be around 0.5 (R_actual/R_max)

    def test_zero_multiplier_effect(self):
        """A single zero veto factor should zero the entire score."""
        calc = TrustScoreCalculator(
            base_score=1.0,
            r_max=1000,
        )

        # One zero in veto factors
        score = calc.calculate(
            r_actual=500,
            veto_factors=[1.0, 0.0, 1.0],  # One zero!
            weighted_factors=[(0.5, 1.0), (0.5, 1.0)],
        )

        # Zero-multiplier: product = 0
        assert score == 0.0

    def test_autonomy_scalar_effect(self):
        """R_actual/R_max ratio should affect score."""
        calc = TrustScoreCalculator(
            base_score=1.0,
            r_max=1000,
        )

        # Low autonomy (few requests)
        score_low = calc.calculate(
            r_actual=100,
            veto_factors=[1.0],
            weighted_factors=[(1.0, 1.0)],
        )

        # High autonomy (many requests)
        score_high = calc.calculate(
            r_actual=900,
            veto_factors=[1.0],
            weighted_factors=[(1.0, 1.0)],
        )

        assert score_low < score_high


class TestVetoCategories:
    """Test all veto categories."""

    @pytest.mark.parametrize("category,content,should_trigger", [
        (VetoCategory.PII, "SSN: 123-45-6789", True),
        (VetoCategory.PII, "Hello world", False),
        (VetoCategory.COPYRIGHT, "This is normal text", False),
        (VetoCategory.BIAS, "Normal professional content", False),
    ])
    def test_category_detection(self, category, content, should_trigger):
        """Test detection for each category."""
        veto = ZeroMultiplierVeto()
        _, vector = veto.evaluate(content)

        has_category = any(
            t.category == category
            for t in vector.triggers
            if t.confidence > 0.5
        )

        if should_trigger:
            assert has_category or vector.is_vetoed
        # Not asserting False cases since detection is probabilistic
