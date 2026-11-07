-- PRODRIVE website messages: rate limiting for the public Edge Function.
-- Run once in Supabase -> SQL Editor before updating website-messages.
create table if not exists public.website_message_limits (
  bucket_key text primary key check (char_length(bucket_key) <= 160),
  attempt_count integer not null default 1,
  expires_at timestamptz not null
);
create index if not exists website_message_limits_expiration_idx
on public.website_message_limits (expires_at);
alter table public.website_message_limits enable row level security;
revoke all on public.website_message_limits from anon, authenticated;
create or replace function public.website_take_message_quota(
  p_key text, p_limit integer, p_window_seconds integer
) returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  allowed_count integer;
begin
  if p_key is null or char_length(p_key) < 10 or char_length(p_key) > 160
    or p_limit not between 1 and 1000
    or p_window_seconds not between 60 and 86400 then
    return false;
  end if;

  insert into public.website_message_limits(bucket_key,attempt_count,expires_at)
  values (p_key,1,now() + make_interval(secs => p_window_seconds))
  on conflict (bucket_key) do update
    set attempt_count = public.website_message_limits.attempt_count + 1
  where public.website_message_limits.attempt_count < p_limit
    and public.website_message_limits.expires_at > now()
  returning attempt_count into allowed_count;

  return allowed_count is not null;
end;
$$;
revoke all on function public.website_take_message_quota(text,integer,integer)
from public, anon, authenticated;
grant execute on function public.website_take_message_quota(text,integer,integer)
to service_role;
-- Old buckets can be periodically purged using:
-- delete from public.website_message_limits where expires_at < now();
