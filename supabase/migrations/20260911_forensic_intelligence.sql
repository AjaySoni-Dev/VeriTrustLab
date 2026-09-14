-- VeriTrust SIH26106 forensic-intelligence extension.
-- Idempotent against the table inventory already used by the repository.
-- Run in Supabase SQL Editor or through your normal migration pipeline.

begin;

create extension if not exists pgcrypto;

create table if not exists public.email_threat_entities (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete cascade,
  scan_id uuid not null references public.gateway_scans(id) on delete cascade,
  artifact_id uuid not null references public.gateway_artifacts(id) on delete cascade,
  entity_type text not null check (entity_type in (
    'attachment_sha256', 'url_domain', 'reply_to_domain', 'return_path_domain',
    'infrastructure_ip_trusted', 'infrastructure_ip_observed', 'dkim_domain',
    'from_domain', 'sender_domain', 'message_id_domain', 'infrastructure_host',
    'infrastructure_asn'
  )),
  entity_value text not null check (octet_length(entity_value) between 1 and 2048),
  value_hash text not null check (value_hash ~ '^[a-f0-9]{64}$'),
  weight smallint not null check (weight between 1 and 10),
  trust_level text not null default 'observed' check (octet_length(trust_level) between 1 and 64),
  provenance jsonb not null default '{}'::jsonb,
  producer_version text not null check (octet_length(producer_version) between 1 and 128),
  created_at timestamptz not null default now(),
  unique (org_id, scan_id, entity_type, value_hash)
);

create index if not exists email_threat_entities_org_hash_idx
  on public.email_threat_entities (org_id, value_hash, created_at desc);
create index if not exists email_threat_entities_org_scan_idx
  on public.email_threat_entities (org_id, scan_id, created_at desc);
create index if not exists email_threat_entities_org_type_value_idx
  on public.email_threat_entities (org_id, entity_type, entity_value);

alter table public.email_threat_entities enable row level security;

-- The application accesses this table only through the server-side service role.
-- No authenticated/anon policy is deliberately created; tenant evidence cannot be
-- queried directly from a browser even if a client knows another scan identifier.

create table if not exists public.email_evidence_passports (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete cascade,
  scan_id uuid not null references public.gateway_scans(id) on delete cascade,
  artifact_id uuid not null references public.gateway_artifacts(id) on delete cascade,
  passport_id text not null unique check (passport_id ~ '^vt_evp_[a-f0-9]{24}$'),
  passport_version text not null check (octet_length(passport_version) between 1 and 128),
  signature_algorithm text not null check (signature_algorithm = 'Ed25519'),
  key_id text not null check (octet_length(key_id) between 1 and 128),
  public_key_jwk jsonb not null,
  signature text not null check (octet_length(signature) between 40 and 256),
  evidence_sha256 text not null check (evidence_sha256 ~ '^[a-f0-9]{64}$'),
  manifest_sha256 text not null check (manifest_sha256 ~ '^[a-f0-9]{64}$'),
  issued_at timestamptz,
  payload jsonb not null,
  created_at timestamptz not null default now(),
  unique (scan_id)
);

create index if not exists email_evidence_passports_org_scan_idx
  on public.email_evidence_passports (org_id, scan_id);
create index if not exists email_evidence_passports_org_key_idx
  on public.email_evidence_passports (org_id, key_id, created_at desc);

alter table public.email_evidence_passports enable row level security;

create or replace function public.veritrust_prevent_evidence_passport_update()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  raise exception 'Evidence passports are immutable; create a new scan instead of updating a signed passport.'
    using errcode = '55000';
end;
$$;

-- Recreate defensively so re-running the migration is safe.
drop trigger if exists trg_veritrust_evidence_passport_immutable on public.email_evidence_passports;
create trigger trg_veritrust_evidence_passport_immutable
before update on public.email_evidence_passports
for each row execute function public.veritrust_prevent_evidence_passport_update();

comment on table public.email_threat_entities is
  'Tenant-scoped, privacy-minimized MailGraph correlation entities. Raw message bodies are never stored here.';
comment on table public.email_evidence_passports is
  'Immutable Ed25519 evidence-passport signatures and hashes for email forensic investigations.';

commit;
