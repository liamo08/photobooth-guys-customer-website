# Google Drive API — disabled OAuth client

**Status:** Open
**First observed:** 2026-04-19 02:00 UTC (daily backup job)
**Last observed:** 2026-04-24 02:00 UTC (still failing every night)
**Affected feature:** Off-site backup uploads from the admin panel to Google Drive
**Severity:** Low — local backups still work; only the off-site copy is missing
**File:** `/opt/photobooth guys website/admin/app.py` (`_upload_to_gdrive`, line ~2698)

## Symptom

Every night at 02:00 UTC the scheduled backup job logs:

```
ERROR in app: Google Drive upload failed:
  ('disabled_client: The OAuth client was disabled.',
   {'error': 'disabled_client',
    'error_description': 'The OAuth client was disabled.'})
```

`journalctl -u pbg-admin -n 200 | grep "Drive upload"` to view recent occurrences.

## Cause

The OAuth client used to authorise `gdrive-token.json` has been disabled in
Google Cloud Console. Common reasons:

- the OAuth consent screen is in "Testing" mode and the 7-day refresh-token
  expiry kicked in, or
- the GCP project containing the client was disabled / had billing issues, or
- the client itself was manually disabled or deleted.

The refresh token in `admin/gdrive-token.json` is now permanently invalid for
this client — re-issuing requires a new OAuth client.

## Impact

- **Local backups: unaffected.** `_create_backup()` writes the zip to
  `admin/backups/` first, then attempts the Drive upload. The Drive failure is
  caught and the backup is still kept locally with `gdrive_uploaded: false` in
  its metadata.
- **Off-site redundancy: missing.** No backup since 2026-04-18 has been copied
  off the VPS. If the box dies, only local backups in `admin/backups/` survive.
- The admin panel itself is unaffected (the 504 incident on 2026-04-24 was a
  separate hung gunicorn worker, not this).

## Resolution steps (when ready to fix)

1. Open Google Cloud Console → APIs & Services → Credentials for the project
   that originally issued the Drive OAuth client.
2. Either re-enable the existing OAuth client, or create a new "Desktop app"
   OAuth 2.0 Client ID.
3. If creating a new one: download the client JSON, replace whatever the admin
   uses for client config, and re-run the OAuth flow (the admin panel has a
   "Connect Google Drive" button on the backups page that writes
   `admin/gdrive-token.json`).
4. Push the OAuth consent screen to "In production" so refresh tokens stop
   expiring after 7 days. Add the Workspace account that owns the Drive folder
   as the only authorised user.
5. Verify by clicking "Upload to Drive" on a recent backup in the admin panel
   — should return a Drive file ID, not an error.
6. Re-run a manual backup and confirm `gdrive_uploaded: true` in its metadata.

## Already-implemented safety net

`_create_backup()` already saves locally first; Drive is best-effort:

```python
# admin/app.py ~ line 2742
if settings.get("auto_upload_gdrive") and GDRIVE_TOKEN_FILE.exists():
    gdrive_id = _upload_to_gdrive(...)
    if gdrive_id:
        meta["gdrive_uploaded"] = True
    else:
        flash("Backup created but Google Drive upload failed", "error")
```

No code change needed for the "save locally if Drive fails" requirement — that
behaviour is already in place.

## Optional hardening (not required to close this ticket)

- Stop the noisy nightly error: flip `auto_upload_gdrive` to `false` in
  `admin/backup-settings.json` until the OAuth client is re-issued, or have
  `_upload_to_gdrive` short-circuit on `disabled_client` and only retry once
  the token file is refreshed.
- Add a `last_gdrive_error` field to `backup-settings.json` so the admin UI can
  surface "Drive disconnected — reconnect" instead of silently failing.
