from __future__ import annotations

import argparse
import json
import sys

from db_functions import db_query_history
from explainability import validate_interpretability


def _load_feature_deviations(value):
    if isinstance(value, list):
        return value
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return []
    return parsed if isinstance(parsed, list) else []


def _build_alerts_from_history(limit: int) -> list[dict]:
    query_limit = 1_000_000 if limit <= 0 else limit
    history = db_query_history(risk_levels=["Medium", "High", "Critical"], limit=query_limit)
    alerts = []

    for row in history.itertuples(index=False):
        alerts.append({
            "id": int(row.id),
            "anomaly_type": row.anomaly_type,
            "deviation_score": float(row.deviation_score or 0.0),
            "feature_deviations": _load_feature_deviations(row.feature_deviations),
        })

    return alerts


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate stored alert explainability against anomaly-type review rules."
    )
    parser.add_argument("--target", type=float, default=0.90, help="Required interpretability accuracy")
    parser.add_argument("--limit", type=int, default=0, help="Max alerts to review; 0 means all")
    args = parser.parse_args()

    alerts = _build_alerts_from_history(args.limit)
    result = validate_interpretability(alerts, target_accuracy=args.target)

    print("Explainability validation")
    print(f"  Reviewed alerts        : {result['reviewed_alerts']} / {result['total_alerts']}")
    print(f"  Passed alerts          : {result['passed_alerts']}")
    print(f"  Failed alerts          : {result['failed_alerts']}")
    print(f"  Interpretability score : {result['interpretability_accuracy']:.2%}")
    print(f"  Target                 : {result['target_accuracy']:.2%}")
    print(f"  Meets target           : {result['meets_target']}")

    failed_reviews = [review for review in result["reviews"] if not review["passed"]]
    if failed_reviews:
        print("\nFailed alert reviews:")
        for review in failed_reviews:
            print(
                f"  id={review['id']} type={review['anomaly_type']} "
                f"score={review['deviation_score']:.4f} reason={review['reason']}"
            )

    return 0 if result["meets_target"] else 1


if __name__ == "__main__":
    sys.exit(main())
