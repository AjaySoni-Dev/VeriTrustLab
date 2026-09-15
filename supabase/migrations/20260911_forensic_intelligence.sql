-- VeriTrustLab forensic-intelligence persistence
-- Adds the durable stores required by MailGraph Campaign Memory and Evidence Passport.
-- This migration assumes the core VeriTrustLab organization/gateway tables already exist.

create extension if not exists pgcrypto;

create table if not exists public.email_threat_entities (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null,
  scan_id uuid not null,
  artifact_id uuid not null,
  entity_type text not null check (length(entity_type) between 1 and 80),
  entity_value text not null check (length(entity_value) between 1 and 2048),
  value_hash text not null check (value_hash ~ '^[a-f0-9]{64}$'),
  weight integer not null check (weight between 1 and 100),
  trust_level text not null default 'observed' check (length(trust_level) between 1 and 80),
  provenance jsonb not null default '{}'::jsonb,
  producer_version text not null check (length(producer_version) between 1 and 120),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint email_threat_entities_org_scan_type_hash_key unique (org_id, scan_id, entity_type, value_hash)
);

create index if not exists email_threat_entities_org_hash_idx
  on public.email_threat_entities (org_id, value_hash, created_at desc);
create index if not exists email_threat_entities_org_scan_idx
  on public.email_threat_entities (org_id, scan_id, created_at asc);

create table if not exists public.email_evidence_passports (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null,
  scan_id uuid not null unique,
  artifact_id uuid not null,
  passport_id text not null unique check (length(passport_id) between 16 and 160),
  passport_version text not null check (length(passport_version) between 1 and 80),
  signature_algorithm text not null check (signature_algorithm = 'Ed25519'),
  key_id text not null check (length(key_id) between 16 and 160),
  public_key_jwk jsonb not null,
  signature text not null check (length(signature) between 40 and 512),
  evidence_sha256 text not null check (evidence_sha256 ~ '^[a-f0-9]{64}$'),
  manifest_sha256 text not null check (manifest_sha256 ~ '^[a-f0-9]{64}$'),
  issued_at timestamptz not null,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists email_evidence_passports_org_scan_idx
  on public.email_evidence_passports (org_id, scan_id);
create index if not exists email_evidence_passports_key_idx
  on public.email_evidence_passports (key_id, issued_at desc);

alter table public.email_threat_entities enable row level security;
alter table public.email_evidence_passports enable row level security;

-- Browser/JWT callers may read only records belonging to an organization where
-- they have an active membership. Application writes use the trusted server
-- service role after application-layer tenant/permission checks.
drop policy if exists email_threat_entities_member_select on public.email_threat_entities;
create policy email_threat_entities_member_select
  on public.email_threat_entities
  for select
  to authenticated
  using (
    exists (
      select 1
      from public.organization_members membership
      where membership.org_id = email_threat_entities.org_id
        and membership.user_id = auth.uid()
        and membership.status = 'active'
    )
  );

drop policy if exists email_evidence_passports_member_select on public.email_evidence_passports;
create policy email_evidence_passports_member_select
  on public.email_evidence_passports
  for select
  to authenticated
  using (
    exists (
      select 1
      from public.organization_members membership
      where membership.org_id = email_evidence_passports.org_id
        and membership.user_id = auth.uid()
        and membership.status = 'active'
    )
  );

revoke all on table public.email_threat_entities from anon;
revoke all on table public.email_evidence_passports from anon;
grant select on table public.email_threat_entities to authenticated;
grant select on table public.email_evidence_passports to authenticated;
grant all on table public.email_threat_entities to service_role;
grant all on table public.email_evidence_passports to service_role;

-- Evidence Passport records are append-only with respect to mutation. This is
-- an application integrity control, not a WORM-storage or legal-admissibility claim.
create or replace function public.veritrust_prevent_evidence_passport_update()
returns trigger
language plpgsql
as $$
begin
  raise exception 'Evidence Passport rows are immutable; create a new investigation/passport instead.'
    using errcode = '55000';
end;
$$;

drop trigger if exists veritrust_prevent_evidence_passport_update on public.email_evidence_passports;
create trigger veritrust_prevent_evidence_passport_update
before update on public.email_evidence_passports
for each row execute function public.veritrust_prevent_evidence_passport_update();
