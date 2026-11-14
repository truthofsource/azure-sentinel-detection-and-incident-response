# Incident response: from signal to a recorded decision

## Triage

Open the intended Sentinel workspace and the exact case. Check the source, original activity window, distinct count, ingestion delay and current collector health. A count of invocations is not a count of people or failed passwords.

Ask whether an approved test, session expiry, role mistake, maintenance or dependency failure explains the observation. Use separately authorized identity and Activity Logs if attribution is needed; the application projection deliberately lacks usernames and IP addresses.

## Ownership and escalation

Assign a responsible responder and preserve the case link, UTC time window, relevant service and safe correlation fields. Escalate unexplained activity, suspected unauthorized access or confirmed business impact to the accountable security/operations owner. Do not attach staff documents, tokens or raw secrets to the case.

| Decision | Meaning |
| --- | --- |
| True positive | Investigated activity needs the security response the rule was designed for |
| False positive | The signal or interpretation was misleading, such as counting duplicate copies as distinct |
| Benign positive / suspicious but expected | The rule correctly found the condition, but the specific activity was expected or authorized |
| Undetermined | Evidence is insufficient; retain the question and next action |

## Verify the saved response

Record the owner, concise evidence-based explanation and appropriate status/classification. Read back the saved owner, comment author and disposition. A button click is not proof that the change was persisted.

## What was actually accepted

The earlier bounded exercise produced eight qualifying 401 observations in one five-minute window against a five-observation threshold. It created a labelled test incident. Later, the human used a scoped Validation identity, assigned the existing case, added the expected-test rehearsal note and closed it; the saved fields and author were independently verified.

The Responder check established incident access and excluded analytics-rule/role-assignment changes for that test identity. The built-in role also includes scoped deployment-support actions; it is not a custom incident-only permission set. Temporary membership was removed and the test account returned to Disabled.

The owner confirmed a separately authorized diagnostic email after receiver verification. Receipt of the original two notifications was not established. The human rehearsal did not claim another newly generated incident/email cycle.

## Existing access-change cases

Two later New cases contained four grants matching collector setup: source-component reader and DCR-scoped publisher in each environment. That supported an expected-change assessment, not independent proof of every actor or approval. Their disposition remained unchanged at the recorded checkpoint. Do not close unrelated cases merely to stop a shared aggregate alert firing.

The screenshots in this repository are fictional local examples. They contain no actual incident number, person, address or Azure portal session.
