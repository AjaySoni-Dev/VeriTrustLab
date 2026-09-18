-- VeriTrust Lab forensic-intelligence persistence extension.
--
-- This migration is intentionally limited to the two optional forensic tables
-- directly required by MailGraph Campaign Memory and Evidence Passport. It is
-- designed to be applied on top of the repository's compatible existing base
-- Supabase contract (organizations, gateway_scans, gateway_artifacts, etc.).
-- All application access to these tables is server-side through the service role;
-- no browser/anon/authenticated direct table access is granted here.

begin;

create table if not exists public.email_threat_entities (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete cascade,
  scan_id uuid not null references public.gateway_scans(id) on delete cascade,
  artifact_id uuid not null references public.gateway_artifacts(id) on delete cascade,
  entity_type text not null check (char_length(entity_type) between 1 and 96),
  entity_value text not null check (char_length(entity_value) between 1 and 2048),
  value_hash text not null check (value_hash ~ '^[a-f0-9]{64}$'),
  weight smallint not null check (weight between 1 and 100),
  trust_level text not null default 'observed' check (char_length(trust_level) between 1 and 64),
  provenance jsonb not null default '{}'::jsonb,
  producer_version text not null check (char_length(producer_version) between 1 and 128),
  created_at timestamptz not null default now(),
  constraint email_threat_entities_scan_entity_unique unique (org_id, scan_id, entity_type, value_hash)
);

create index if not exists email_threat_entities_org_hash_created_idx
  on public.email_threat_entities (org_id, value_hash, created_at desc);
create index if not exists email_threat_entities_org_scan_idx
  on public.email_threat_entities (org_id, scan_id);

alter table public.email_threat_entities enable row level security;
revoke all on table public.email_threat_entities from anon, authenticated;
grant select, insert, delete on table public.email_threat_entities to service_role;

create table if not exists public.email_evidence_passports (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete cascade,
  scan_id uuid not null references public.gateway_scans(id) on delete cascade,
  artifact_id uuid not null references public.gateway_artifacts(id) on delete cascade,
  passport_id text not null unique check (passport_id ~ '^vt_evp_[a-f0-9]{24}$'),
  passport_version text not null check (char_length(passport_version) between 1 and 128),
  signature_algorithm text not null check (signature_algorithm = 'Ed25519'),
  key_id text not null check (key_id ~ '^ed25519:[a-f0-9]{24}$'),
  public_key_jwk jsonb not null,
  signature text not null check (char_length(signature) between 32 and 1024),
  evidence_sha256 text not null check (evidence_sha256 ~ '^[a-f0-9]{64}$'),
  manifest_sha256 text not null check (manifest_sha256 ~ '^[a-f0-9]{64}$'),
  issued_at timestamptz,
  payload jsonb not null,
  created_at timestamptz not null default now(),
  constraint email_evidence_passports_scan_unique unique (scan_id),
  constraint email_evidence_passports_org_scan_unique unique (org_id, scan_id)
);

create index if not exists email_evidence_passports_org_created_idx
  on public.email_evidence_passports (org_id, created_at desc);

alter table public.email_evidence_passports enable row level security;
revoke all on table public.email_evidence_passports from anon, authenticated;
grant select, insert, delete on table public.email_evidence_passports to service_role;

create or replace function public.veritrust_prevent_evidence_passport_update()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  raise exception 'Evidence Passport rows are immutable; insert a new scan/package instead of updating an issued passport.'
    using errcode = '55000';
end;
$$;

revoke all on function public.veritrust_prevent_evidence_passport_update() from public;
grant execute on function public.veritrust_prevent_evidence_passport_update() to service_role;

drop trigger if exists veritrust_prevent_evidence_passport_update on public.email_evidence_passports;
create trigger veritrust_prevent_evidence_passport_update
before update on public.email_evidence_passports
for each row execute function public.veritrust_prevent_evidence_passport_update();

commit;
