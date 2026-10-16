-- CC-Switch Web encrypted configuration snapshots (single-writer deployment).
-- Encrypted on the Koyeb server BEFORE upload; no plaintext provider keys here.
create table if not exists public.cc_switch_cloud_config (
    slot text primary key check (length(slot) between 1 and 64),
    cipher_text text not null check (length(cipher_text) between 1 and 12000000),
    updated_at timestamptz not null default now()
);

alter table public.cc_switch_cloud_config enable row level security;
revoke all on table public.cc_switch_cloud_config from public, anon, authenticated;
-- Deliberately do not create anon/authenticated RLS policies.
-- Koyeb must use a server-side Supabase secret key only.
