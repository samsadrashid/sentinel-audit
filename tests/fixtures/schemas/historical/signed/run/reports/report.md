# Sentinel audit 01a1bf20-c595-7ec2-a411-5f800d9d0f9e

**Overall:** FAIL  
**State:** Completed  
**Mode / level:** READ / L2  
**Target revision:** tree\-sha256:f438ec0877290ae4b8ee8edf95909f621d9e517061ce67d56f577b825be78c17  
**Data boundary:** Sentinel engine processing is local only: in V1 the engine has no feature that sends source code, evidence or findings to any external service\.

> This report lists what Sentinel checked and found. It is not a statement that the target is secure. Checks that did not run are listed explicitly.

## Checks

| Check | Status | Reason |
|---|---|---|
| app/fixture | FAIL |  |

## Findings

Total 1; verified 0; human-verified without deterministic evidence 0 (reported separately, never counted as verified).

| Severity | Confidence | State | Rule | Title | Location |
|---|---|---|---|---|---|
| medium | medium | suspected | fixture\.marker | fixture marker present | a\.txt:2 |

## Human-verified without deterministic evidence

None.

## Exclusions (suppressed and accepted risk)

None.

## Integrity

The manifest and audit log are signed with the automatic run key\. A valid signature shows integrity relative to that key only\. It does not detect a same\-user process that can rewrite the run folder and use the run key \(D\-34\)\. A signature never proves that a finding is real\.
