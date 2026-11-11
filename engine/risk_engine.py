class RiskEngine:
    """
    Risk scoring model.

    Each finding contributes a weighted score based on its severity and
    detection confidence:
        contribution = SEVERITY_WEIGHT[severity] * CONFIDENCE_MULT[confidence]

    The total score is capped at 100 and mapped to a risk level:
        0        -> PASS
        1 – 14   -> LOW
        15 – 34  -> MEDIUM
        35 – 59  -> HIGH
        60 – 100 -> CRITICAL
    """

    WEIGHTS = {"Critical": 25, "High": 10, "Medium": 5, "Low": 1, "Info": 0}
    CONFIDENCE_MULT = {"High": 1.0, "Medium": 0.6, "Low": 0.3}

    def compute(self, findings):
        counts = {k: 0 for k in self.WEIGHTS}
        raw = 0.0
        for f in findings:
            sev = f.get("severity", "Info")
            conf = f.get("confidence", "High")
            counts[sev] = counts.get(sev, 0) + 1
            raw += self.WEIGHTS.get(sev, 0) * self.CONFIDENCE_MULT.get(conf, 1.0)

        score = min(100, int(round(raw)))
        if   score >= 60: level = "CRITICAL"
        elif score >= 35: level = "HIGH"
        elif score >= 15: level = "MEDIUM"
        elif score >  0:  level = "LOW"
        else:             level = "PASS"

        return {"counts": counts, "score": score, "level": level}
