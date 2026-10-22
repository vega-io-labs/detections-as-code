---
id: "8b0f5a3e-2c4d-4e6f-9a1b-3c5d7e9f1a2b"
name: "Service Account Sign-In Triage"
description: "Sign-ins by service accounts from outside their fixed egress range. Use when a detection fires on a non-human identity authenticating from a new IP, country or client. Not for interactive users."
type: "triage"
---

# Triage steps

A service account signs in from the same few addresses with the same client, every time. A change in either is the signal; a failed sign-in on its own is usually a rotated secret.

**Leads that point to a real threat:**

- **A success from outside the documented egress range.** The integration runs from `192.0.2.0/24`; a successful sign-in from any other network is escalate-worthy on its own.
- **A new client or user agent.** The account always authenticates with the same SDK. A browser user agent means someone is using the credential by hand.
- **Activity after hours for a scheduled job.** The nightly sync runs 01:00-02:00 UTC. A session outside that window, with no change ticket, is not the job.

**Leads that rule it out:**

- **Failures only, from the usual range.** A run of failures from `192.0.2.0/24` with no success is a rotated or expired secret. Close it and tell the owning team.
- **A documented migration.** The account owner announced a move to a new range and the source IP is in it.

Escalate when a success comes from outside the range or with a new client, even when everything else looks routine.
