# Device revocation runbook

Use this when a device is lost, shared, or suspected to be compromised.

1. Identify the device ID from the audit log or operator console.
2. Revoke the device.

   ```powershell
   curl.exe -X POST http://127.0.0.1:8000/api/v1/admin/devices/{device_id}/revoke
   ```

3. Confirm the user can no longer obtain fresh tokens or access open tasks.
4. Review audit events for `device.revoked` and related resource closures.
5. If the same person has a second device, revoke that separately and keep the trace IDs.

