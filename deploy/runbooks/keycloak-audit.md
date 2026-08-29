# Keycloak identity-audit acceptance

Use this procedure for the target environment before production approval and
after changing the Keycloak realm. The committed realm JSON is bootstrap input;
an existing realm must be reconciled through the Keycloak Admin Console or Admin
REST API because startup import is not an upgrade mechanism.

1. Run `python scripts/verify_keycloak_realm.py` against the release source.
2. In the target `email-platform` realm, reconcile the Events configuration to
   the committed JSON: user events enabled, `eventsExpiration=2592000`, only the
   reviewed success/error types enabled, and listener `jboss-logging`. Enable
   admin events, set realm attribute `adminEventsExpiration=2592000`, but keep
   `adminEventsDetailsEnabled=false`; request
   representations can contain data that does not belong in an audit trail.
3. From an approved workstation with an already authenticated, short-lived
   `kcadm` session, capture the effective configuration. Do not put an admin
   password or token in the command or evidence.

   ```sh
   kcadm.sh get events/config -r email-platform
   ```

4. Use a designated non-production identity to generate at least five failed
   logins inside five minutes. Confirm stored `LOGIN_ERROR` records contain no
   password, OTP, access token, refresh token, or credential representation.
   Confirm Prometheus reports only realm-scoped aggregates from
   `keycloak_user_events_total` and that `PlatformKeycloakLoginFailures` reaches
   the approved Alertmanager receiver. Do not enable `clientId`, `idp`, user, or
   IP metric tags.
5. Make one harmless administrator change to the designated test identity and
   confirm an admin event exists while its request representation is absent.
6. Run the encrypted dual-database restore drill and retain matching source and
   restored counts for Keycloak `event_entity` and `admin_event_entity`.

Attach timestamps, redacted event identifiers, the Prometheus query result,
Alertmanager delivery evidence, and restore counts to the production signoff.
Stop the release if any required event is absent, the alert is not delivered,
or sensitive authentication material appears in evidence.
