# Environments, modes and activity classes

| Environment | Meaning | Rules |
|---|---|---|
| `local` | Your own checkout or files | Read-only classes need no record |
| `staging` | A non-production system you own | Exact or bounded assets; records for active classes |
| `production` | A production system | Exact assets only; `A1` excluded in V1; shortest approval lifetimes (D-37) |

| Activity class | What it does | Isolation | Needs a record |
|---|---|---|---|
| `S1` | Static reading of local files | macOS Seatbelt sandbox | No |
| `S2` | Static analysis with more tooling | Sandbox | No |
| `B1`, `B2` | Bounded build or archive inspection | Sandbox; archive limits | No |
| `A1` | Active, non-destructive validation | Sandbox; record scope | **Yes**, `VALIDATE` only |
| `B3` | Running analysed artifacts | — | **Always refused** |

If the host can't provide the isolation a class needs, the check is `BLOCKED`. It never runs
unconfined, and it is never reported as a pass.
