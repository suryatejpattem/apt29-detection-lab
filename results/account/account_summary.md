# Create Account + Privilege Escalation — Tuning Summary

**Technique:** T1136.001 (Persistence)
**Rule:** detections/T1136.001_create_account.yaml

## Measurement (clean windows)
- Attack: 06/25 16:55–17:00 — T1136.001_Admin created (4720) AND added to Administrators (4732)
- Benign: 06/25 18:07–18:48 — testuser created (4720), added to Users only (no Administrators 4732)

| Metric                        | Naive (any 4720) | Tuned (created + promoted to Admin) |
|-------------------------------|------------------|-------------------------------------|
| True positive (attack caught) | Yes              | Yes (1)                             |
| False positives (benign)      | 1                | 0                                   |

## Tuning applied
Naive rule fires on any account creation (4720) — admins create accounts routinely (benign testuser). Tuned rule fires only on the **sequence**: an account created (4720) AND added to Administrators (4732) within a short window — a fresh account immediately given admin rights, which is strongly attacker-specific.

## Correlation method (the real engineering)
- `transaction Security_ID` FAILED: Security_ID is multi-valued (carries both the actor and the target SID), so transaction merged unrelated events on the shared actor SID (-1001).
- `stats by Security_ID` OVER-COUNTED: the actor SID (-1001, the admin running the commands) appears in both the create and the promote, so it falsely satisfied the create→promote pattern. Lab patch = exclude the known actor SID (fragile).
- PRODUCTION fix: `rex` extracts the **Target SID** (under "New Account:"/"Member:") into target_sid, so the actor SID is never grouped on. No exclusion list needed; works for any actor.

## Limitations (accepted blind spots)
- An attacker who creates an account and promotes it >maxspan apart, or via a different group then nesting, evades the simple sequence.
- rex extraction depends on event message format; production should use the Splunk Windows Add-on / CIM fields (Target_Account) rather than a custom regex.