-- USP 1 / Evidence Passport hardening.
-- Forward-only: preserves issued v1 passports and never reconstructs/backfills signed evidence.
begin;

DO $$
BEGIN
  IF to_regclass('public.email_evidence_passports') IS NULL THEN
    RAISE EXCEPTION 'Evidence Passport hardening requires public.email_evidence_passports to exist; apply the forensic intelligence migration first.';
  END IF;
END
$$;

alter table public.email_evidence_passports
  add column if not exists evidence_payload jsonb null;

-- Preflight historical rows before tightening any constraint. Fail explicitly rather
-- than silently changing signed forensic history.
DO $$
DECLARE
  bad_id uuid;
BEGIN
  SELECT id INTO bad_id
  FROM public.email_evidence_passports
  WHERE key_id !~ '^ed25519:[a-f0-9]{24}$'
     OR jsonb_typeof(public_key_jwk) IS DISTINCT FROM 'object'
     OR public_key_jwk ? 'd'
     OR public_key_jwk ->> 'kty' IS DISTINCT FROM 'OKP'
     OR public_key_jwk ->> 'crv' IS DISTINCT FROM 'Ed25519'
     OR coalesce(public_key_jwk ->> 'x', '') !~ '^[A-Za-z0-9_-]{43}$'
     OR signature !~ '^[A-Za-z0-9_-]{86}$'
     OR jsonb_typeof(payload) IS DISTINCT FROM 'object'
     OR (evidence_payload IS NOT NULL AND jsonb_typeof(evidence_payload) IS DISTINCT FROM 'object')
     OR payload ->> 'passport_id' IS DISTINCT FROM passport_id
     OR payload ->> 'passport_version' IS DISTINCT FROM passport_version
     OR payload ->> 'scan_id' IS DISTINCT FROM scan_id::text
     OR payload ->> 'artifact_id' IS DISTINCT FROM artifact_id::text
     OR payload ->> 'evidence_sha256' IS DISTINCT FROM evidence_sha256
     OR payload ->> 'manifest_sha256' IS DISTINCT FROM manifest_sha256
  LIMIT 1;

  IF bad_id IS NOT NULL THEN
    RAISE EXCEPTION 'Evidence Passport hardening preflight failed: row % has malformed or inconsistent signed/envelope data. No historical rows were modified.', bad_id;
  END IF;

  SELECT p.id INTO bad_id
  FROM public.email_evidence_passports p
  LEFT JOIN public.gateway_scans s
    ON s.id = p.scan_id AND s.org_id = p.org_id
  WHERE s.id IS NULL
  LIMIT 1;
  IF bad_id IS NOT NULL THEN
    RAISE EXCEPTION 'Evidence Passport hardening preflight failed: row % does not belong to the same organization as its scan. No historical rows were modified.', bad_id;
  END IF;

  SELECT p.id INTO bad_id
  FROM public.email_evidence_passports p
  LEFT JOIN public.gateway_artifacts a
    ON a.id = p.artifact_id AND a.scan_id = p.scan_id AND a.org_id = p.org_id
  WHERE a.id IS NULL
  LIMIT 1;
  IF bad_id IS NOT NULL THEN
    RAISE EXCEPTION 'Evidence Passport hardening preflight failed: row % does not belong to the same scan/organization as its artifact. No historical rows were modified.', bad_id;
  END IF;
END
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.email_evidence_passports'::regclass
      AND conname = 'email_evidence_passports_key_id_format_chk'
  ) THEN
    ALTER TABLE public.email_evidence_passports
      ADD CONSTRAINT email_evidence_passports_key_id_format_chk
      CHECK (key_id ~ '^ed25519:[a-f0-9]{24}$') NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.email_evidence_passports'::regclass
      AND conname = 'email_evidence_passports_public_jwk_chk'
  ) THEN
    ALTER TABLE public.email_evidence_passports
      ADD CONSTRAINT email_evidence_passports_public_jwk_chk CHECK (
        jsonb_typeof(public_key_jwk) = 'object'
        AND NOT (public_key_jwk ? 'd')
        AND public_key_jwk ->> 'kty' IS NOT DISTINCT FROM 'OKP'
        AND public_key_jwk ->> 'crv' IS NOT DISTINCT FROM 'Ed25519'
        AND coalesce(public_key_jwk ->> 'x', '') ~ '^[A-Za-z0-9_-]{43}$'
      ) NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.email_evidence_passports'::regclass
      AND conname = 'email_evidence_passports_signature_encoding_chk'
  ) THEN
    ALTER TABLE public.email_evidence_passports
      ADD CONSTRAINT email_evidence_passports_signature_encoding_chk
      CHECK (signature ~ '^[A-Za-z0-9_-]{86}$') NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.email_evidence_passports'::regclass
      AND conname = 'email_evidence_passports_payload_shape_chk'
  ) THEN
    ALTER TABLE public.email_evidence_passports
      ADD CONSTRAINT email_evidence_passports_payload_shape_chk CHECK (
        jsonb_typeof(payload) = 'object'
        AND payload ->> 'passport_id' IS NOT DISTINCT FROM passport_id
        AND payload ->> 'passport_version' IS NOT DISTINCT FROM passport_version
        AND payload ->> 'scan_id' IS NOT DISTINCT FROM scan_id::text
        AND payload ->> 'artifact_id' IS NOT DISTINCT FROM artifact_id::text
        AND payload ->> 'evidence_sha256' IS NOT DISTINCT FROM evidence_sha256
        AND payload ->> 'manifest_sha256' IS NOT DISTINCT FROM manifest_sha256
      ) NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.email_evidence_passports'::regclass
      AND conname = 'email_evidence_passports_evidence_payload_shape_chk'
  ) THEN
    ALTER TABLE public.email_evidence_passports
      ADD CONSTRAINT email_evidence_passports_evidence_payload_shape_chk
      CHECK (evidence_payload IS NULL OR jsonb_typeof(evidence_payload) = 'object') NOT VALID;
  END IF;
END
$$;

alter table public.email_evidence_passports validate constraint email_evidence_passports_key_id_format_chk;
alter table public.email_evidence_passports validate constraint email_evidence_passports_public_jwk_chk;
alter table public.email_evidence_passports validate constraint email_evidence_passports_signature_encoding_chk;
alter table public.email_evidence_passports validate constraint email_evidence_passports_payload_shape_chk;
alter table public.email_evidence_passports validate constraint email_evidence_passports_evidence_payload_shape_chk;

-- The deployed schema already has unique target keys for these composite references.
-- Add them only if an earlier hardening migration has not already done so.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.email_evidence_passports'::regclass
      AND conname = 'email_evidence_passports_scan_org_fkey'
  ) THEN
    ALTER TABLE public.email_evidence_passports
      ADD CONSTRAINT email_evidence_passports_scan_org_fkey
      FOREIGN KEY (scan_id, org_id)
      REFERENCES public.gateway_scans(id, org_id)
      ON DELETE CASCADE
      NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.email_evidence_passports'::regclass
      AND conname = 'email_evidence_passports_artifact_scan_org_fkey'
  ) THEN
    ALTER TABLE public.email_evidence_passports
      ADD CONSTRAINT email_evidence_passports_artifact_scan_org_fkey
      FOREIGN KEY (artifact_id, scan_id, org_id)
      REFERENCES public.gateway_artifacts(id, scan_id, org_id)
      ON DELETE CASCADE
      NOT VALID;
  END IF;
END
$$;

alter table public.email_evidence_passports validate constraint email_evidence_passports_scan_org_fkey;
alter table public.email_evidence_passports validate constraint email_evidence_passports_artifact_scan_org_fkey;

alter table public.email_evidence_passports enable row level security;
revoke all on table public.email_evidence_passports from anon, authenticated;

create or replace function public.veritrust_prevent_evidence_passport_update()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  raise exception 'Evidence Passport records are update-protected; create a new investigation instead of modifying an issued signed Passport.'
    using errcode = '55000';
end;
$$;

comment on table public.email_evidence_passports is
  'Update-protected signed Evidence Passport records. Deletion follows the parent investigation retention/deletion lifecycle; this table is not WORM storage.';
comment on column public.email_evidence_passports.evidence_payload is
  'Exact normalized evidence JSON hashed by evidence_sha256 for new Passport issuances. NULL means exact historical payload was not durably recorded; never backfill from reconstruction.';

commit;
