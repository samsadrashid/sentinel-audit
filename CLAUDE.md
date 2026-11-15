# Sentinel project rules (owner, 2026-11-09)

1. **M1 is closed (accepted, software-complete).** Don't reopen completed M1 tasks, or repeat their full audits and mutation campaigns, without a concrete regression, a security finding or an explicitly defined milestone requirement.
2. **`docs/m1/m1-completion-report.md` and `docs/m2/m2-completion-report.md` are the M1 and M2 baseline records.** M2 is accepted and closed too. Preserve its results and limitations. Don't regenerate or rewrite it without a specific reason.
3. **Production signing stays disabled.** Hardware validation, SD-T01 to SD-T55, physical FIDO2 recovery and the first-enrolment ceremonies are separate outstanding work. Never represent software fixtures as hardware validation.
4. **Remote CI runs on GitHub** (first passed 2026-11-13). The public repository is `samsadrashid/sentinel-audit`: develop on the local `public` branch, which tracks it. `samsadrashid/sentinel` is the private full-history archive (local `main`). Don't commit, push, create a remote or change the Git index without the owner's authorisation.
5. **Don't download the official JSON Schema Test Suite** without separate owner approval.
6. **Preserve D-48 and the append-only decision register** (`docs/architecture-discovery-plan.md`). Reopening a frozen decision needs a concrete reason and a new dated decision.
7. **Move forward by the existing roadmap** (`docs/architecture/discovery.md`, milestones table). Don't invent extra closure tasks for completed milestones.
8. **Per milestone:**
   1. Agree scope and acceptance criteria once.
   2. Implement the complete milestone.
   3. Run one consolidated audit and one final verification cycle.
   4. Fix genuine failures and rerun only the affected checks, then the required final acceptance suite.
9. **Don't stop for incremental approval** during authorised implementation. Ask only when an owner decision, a security boundary, an external dependency or a scope change requires it.

Working notes:
- The Secure Enclave helper tests and the mutation campaign need an unlocked macOS session. The harness preflight refuses otherwise, and environmental failures never count as passes.
- Don't expose private portfolio project names in any project artifact.
