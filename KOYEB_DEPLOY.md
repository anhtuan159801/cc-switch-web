# CC-Switch Web — Persistent Koyeb Deployment

This fork adds an **opt-in, encrypted cloud configuration backup** for stateless
single-instance hosting. It preserves the provider configuration, including manual
API keys, during container replacement. It does **not** preserve usage logs,
sessions, managed OAuth accounts, uploaded files, or the entire SQLite DB.

## 1. Configure Supabase (required for persistence)

Use an **active** Supabase project. Run
`supabase/migrations/20261014_cc_switch_cloud_config.sql` once in the SQL editor.
This creates `public.cc_switch_cloud_config` with RLS enabled and no
anon/authenticated access. Do not use a publishable or anon API key.

In the Supabase dashboard, obtain:
- Project URL (`https://<project>.supabase.co`)
- A **server-side secret** key (`sb_secret_...`) under API Keys

Keep the secret key exclusively in **Koyeb Secrets**. The service-side key can
bypass RLS for the entire Supabase project, so use a dedicated project where
practical.

## 2. Generate the 256-bit encryption key ON YOUR COMPUTER

```bash
openssl rand -base64 32
```

Store the complete result in Koyeb Secrets. Do not publish the key in your
repository, screenshots, terminal logs, or frontend environment variables.
**Keep an offline backup of this key**: a lost key makes existing cloud backups
undecryptable. Changing the key without migrating backups prevents startup.

## 3. Deploy from this GitHub branch

Koyeb Dashboard -> Create Web Service -> GitHub ->
`anhtuan159801/cc-switch-web` ->
`feat/koyeb-persistent-encrypted-config` -> Builder **Dockerfile**.
Expose HTTP port **3000**, route **/**, HTTPS public domain.

> IMPORTANT: The multi-stage Docker build compiles Rust from source and may
> exceed resource/time limits during Koyeb build. Building requires more resources
> than running the final image. Check build logs and select an appropriate
> Koyeb builder or prebuild/push the container image if necessary.

Required environment values (all secrets except HOST/PORT are private):

| Name | Value |
|---|---|
| `HOST` | `0.0.0.0` |
| `PORT` | `3000` |
| `ALLOW_HTTP_BASIC_OVER_HTTP` | `1` (ONLY with Koyeb HTTPS termination) |
| `CC_SWITCH_WEB_ADMIN_USER` | `admin` (or your preferred username) |
| `CC_SWITCH_WEB_ADMIN_PASSWORD` | Long random password, at least 16 chars |
| `CC_SWITCH_SUPABASE_URL` | `https://<project>.supabase.co` |
| `CC_SWITCH_SUPABASE_SECRET_KEY` | Server-side `sb_secret_...` |
| `CC_SWITCH_SYNC_ENCRYPTION_KEY` | Base64 of 32 random bytes |
| `CC_SWITCH_CLOUD_REQUIRED` | `1` |
| `CC_SWITCH_SYNC_SLOT` | `primary` (optional, one deployment per slot) |

Never expose port 3000 directly to the public without TLS. Koyeb's HTTPS endpoint
terminates TLS at its ingress; use a protected/private service wherever possible.

## 4. How persistence works

- On startup, the app **fetches and decrypts** the cloud snapshot, if one exists.
- Corrupt data, missing secrets, decryption failures, or network errors **fail startup**
  instead of destroying the remote backup.
- After successful restore, the local SQLite provider configuration is populated.
- The worker detects changes and writes encrypted snapshots approximately every
  **2 seconds**; a successful write avoids uploading identical snapshots again.
- The AES-256-GCM encryption key stays in server secrets, not in Supabase.
- When a snapshot does not yet exist, the current initial configuration is uploaded.
- A force-kill or outage immediately after pressing Save can still lose the most
  recent **unsynchronized** changes. Review server logs for
  `Encrypted cloud configuration synchronized` before redeploying.

**Do not run multiple replicas against the same slot.** Last writer wins;
this is designed for a single instance and does not provide distributed locking.

## 5. Verify before trusting it

1. Deploy with a fresh slot. Login with the fixed admin password.
2. Add a test provider with a non-production API key; press Save.
3. Confirm `Encrypted cloud configuration synchronized` in server logs.
4. In Supabase, confirm one row in `cc_switch_cloud_config` and that
   `cipher_text` begins `v1.` — plaintext key must not be visible.
5. Trigger Koyeb redeploy. Log in with the same password, confirm test
   provider is still present and routes correctly.
6. Delete the test key from its provider account after testing.

## Limits and security

- Cloud sync preserves the `MultiAppConfig` snapshot only. External
  OAuth-managed accounts and other local files are **not** backed up.
- Web UI manages the server/container host, NOT Claude Code installed on your PC.
  Connecting a local Claude Code instance needs a separately secured remote API
  gateway configuration.
- Protect Supabase credentials with least privilege; the default Supabase secret
  key is highly privileged. Do not send it to browsers or commit it to git.
- Provider config can include API keys; the snapshot is encrypted, but API keys
  still exist in plaintext temporarily inside the container and local SQLite.
- If database access becomes unavailable at runtime, the worker logs and retries
  syncing; avoid redeploying before the cloud sync has succeeded.
- Supabase Free projects may pause when inactive. Restore requires an active
  project. Confirm current Supabase and Koyeb free-tier limits before production.
- Back up the encryption key securely outside Koyeb.
