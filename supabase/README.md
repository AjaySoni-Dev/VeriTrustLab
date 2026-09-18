# Supabase migration source

`migrations/20260911_forensic_intelligence.sql` versions the MailGraph forensic extension used by Campaign Memory and Evidence Passport.

It is **not** a replacement for the pre-existing VeriTrust Lab base Supabase contract. The application also references the base Gateway/account/billing/privacy tables and RPCs. Deploy this migration only after the compatible base schema is present, or recover/version the full base migration history from the live project before creating a fresh database from scratch.

The forensic extension keeps direct browser roles off the two tables, enables RLS, and makes issued Evidence Passport rows update-immutable. Application access is through the server-side service role and tenant-scoped server queries.
