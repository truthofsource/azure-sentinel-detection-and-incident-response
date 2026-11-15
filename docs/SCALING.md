# Scaling, strengths, weaknesses and cost

Start with representative volume, original-to-arrival delay, cursor age, timer duration, query throttling, window density, duplicate ratio and analyst workload. An eight-hour sample with one controlled distinct event cannot establish a mature false-positive rate or capacity requirement.

## Choices and tradeoffs

| Choice | Strength | Weakness or cost |
| --- | --- | --- |
| Share the API host | Reuses identity and hosting | API downtime also stops collection; permissions are shared |
| Small selected metadata | Limits private data and keeps schema consistent | Deliberately lacks user/IP attribution and full audit coverage |
| Durable pending batch | Replays unresolved work after restart or uncertain acceptance | Repeated ingestion can be billed; bounded recovery can stop |
| First-arrival stable-ID counting | Avoids replay-inflated analytical totals | Native incident grouping is still not an exactly-once ledger |
| Lower thresholds | Detects smaller patterns | Can increase investigation noise and analyst work |
| Longer retention | More investigation history | Higher cost and longer data lifetime |

## How it could grow

If hosting contention or availability becomes a measured problem, consider a dedicated collector identity/worker. Partition checkpoints only with explicit source ownership; multiple writers competing for one lease do not increase useful throughput. Review source-query, ingestion, storage and responder limits together.

Additional applications need versioned schemas, source ownership, exact scopes and acceptance cohorts. A queue or Event Hubs may justify independent buffering/consumers, but adds ordering, access, retention, replay and operational duties. None is silently deployed by this reference.

## Cost interpretation

Charges can include source/health queries, Function usage, storage operations, ingestion, retention, rules and notifications. The recorded eight-hour production cohort had 800 billable row bytes, including a duplicate; that is not a currency amount or monthly forecast. Posted hub workspace cost at the checkpoint was about $0.67 for November 1–12, before the rollout appeared in billing; it was not isolated incremental collector cost or total Azure spending.

Review at a full 24 hours, seven days and thirty days, separating tests from normal activity. Tune only with a concrete sample, known expected activity, missed-detection risk, fixtures and a reversible rollout plan. No recurring observer or automated response is created by this repository.
