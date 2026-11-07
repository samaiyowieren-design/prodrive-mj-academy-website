-- PRODRIVE website inbox, stage 1: run in Supabase SQL Editor.
-- No public table write access. Contact form submissions must pass through a secured Edge Function.
create extension if not exists pgcrypto;
create table if not exists public.website_admins (
  user_id uuid primary key references auth.users(id) on delete cascade
);
create table if not exists public.website_conversations (
  id uuid primary key default gen_random_uuid(),
  visitor_name text not null check (char_length(visitor_name) between 1 and 100),
  visitor_email text not null check (char_length(visitor_email) between 3 and 254),
  visitor_token_hash text not null,
  status text not null default 'open' check (status in ('open','closed')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table if not exists public.website_messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.website_conversations(id) on delete cascade,
  sender text not null check (sender in ('visitor','admin')),
  body text not null check (char_length(body) between 1 and 2000),
  created_at timestamptz not null default now()
);
create index if not exists website_messages_conversation_idx on public.website_messages(conversation_id,created_at);
create index if not exists website_conversations_created_idx on public.website_conversations(created_at desc);
alter table public.website_admins enable row level security;
alter table public.website_conversations enable row level security;
alter table public.website_messages enable row level security;
revoke all on public.website_admins from anon, authenticated;
revoke all on public.website_conversations from anon, authenticated;
revoke all on public.website_messages from anon, authenticated;
-- Only Supabase service-role Edge Functions may read/write messages.
-- Set up your admin auth account separately; NEVER place service_role keys in HTML or JavaScript.
-- When your admin Supabase Auth user exists, add their UUID manually:
-- insert into public.website_admins(user_id) values ('YOUR_ADMIN_AUTH_USER_UUID') on conflict do nothing;
