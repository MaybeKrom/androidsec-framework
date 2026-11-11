import json

class RulesEngine:
    def __init__(self, path):
        with open(path, encoding="utf-8") as f:
            self.rules = json.load(f)

    def enrich(self, findings):
        enriched = []
        for f in findings:
            rule = self.rules.get(f["rule_id"])
            if rule is None:
                enriched.append({**f, "severity": "Info", "title": f["rule_id"],
                                 "description": "", "recommendation": ""})
                continue
            enriched.append({**rule, **f})
        return enriched
