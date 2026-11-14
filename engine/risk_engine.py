class RiskEngine:
    """
    Risk scoring model.

    Each finding contributes a weighted score based on its severity and
    detection confidence:
        contribution = SEVERITY_WEIGHT[severity] * CONFIDENCE_MULT[confidence]

    Soft caps (lab differentiation — keep real Critical visible without 100/100 saturation):
        - Critical findings beyond the first two contribute at half weight
        - High findings beyond the first three contribute at half weight
        - Medium findings beyond the first six contribute at half weight
        - Info never contributes

    The total score is capped at 100 and mapped to a risk level:
        0        -> PASS
        1 – 14   -> LOW
        15 – 34  -> MEDIUM
        35 – 59  -> HIGH
        60 – 100 -> CRITICAL
    """

    WEIGHTS = {"Critical": 20, "High": 7, "Medium": 3, "Low": 1, "Info": 0}
    CONFIDENCE_MULT = {"High": 1.0, "Medium": 0.6, "Low": 0.3}

    # Full-weight slots before soft-cap half weight applies.
    SOFT_CAP_AFTER = {"Critical": 2, "High": 3, "Medium": 6}

    def compute(self, findings):
        counts = {k: 0 for k in self.WEIGHTS}
        raw = 0.0
        seen = {k: 0 for k in self.SOFT_CAP_AFTER}
        for f in findings:
            sev = f.get("severity", "Info")
            conf = f.get("confidence", "High")
            counts[sev] = counts.get(sev, 0) + 1
            weight = self.WEIGHTS.get(sev, 0)
            mult = self.CONFIDENCE_MULT.get(conf, 1.0)
            if sev in seen:
                seen[sev] += 1
                if seen[sev] > self.SOFT_CAP_AFTER[sev]:
                    weight *= 0.5
            raw += weight * mult

        score = min(100, int(round(raw)))
        if   score >= 60: level = "CRITICAL"
        elif score >= 35: level = "HIGH"
        elif score >= 15: level = "MEDIUM"
        elif score >  0:  level = "LOW"
        else:             level = "PASS"

        return {"counts": counts, "score": score, "level": level}
