-- GroundZ: link a TCG Live leaderboard entry to a player's account
-- Run once in Supabase > SQL Editor. Safe to run again.

create table if not exists public.link_requests (
  id          bigint generated always as identity primary key,
  user_id     uuid not null default auth.uid() references auth.users(id) on delete cascade,
  player_id   bigint not null,
  tcg_ign     text not null check (char_length(tcg_ign) between 1 and 24),
  tcg_email   text not null,
  status      text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at  timestamptz not null default now(),
  decided_at  timestamptz
);

-- one open request per player at a time
create unique index if not exists link_requests_one_pending
  on public.link_requests (user_id) where status = 'pending';

alter table public.link_requests enable row level security;

create or replace function public.is_org() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'org');
$$;

drop policy if exists lr_insert_own on public.link_requests;
create policy lr_insert_own on public.link_requests
  for insert to authenticated
  with check (
    user_id = auth.uid()
    and status = 'pending'
    -- the TCG Live email must be the same email this account logs in with
    and lower(tcg_email) = lower(coalesce(auth.jwt() ->> 'email', ''))
  );

drop policy if exists lr_select on public.link_requests;
create policy lr_select on public.link_requests
  for select to authenticated
  using (user_id = auth.uid() or public.is_org());

-- organizer approves: the account takes over the TCG Live leaderboard entry
create or replace function public.approve_link(rid bigint) returns void
language plpgsql security definer set search_path = public as $$
declare r public.link_requests;
begin
  if not public.is_org() then raise exception 'Only the organizer can approve links'; end if;
  select * into r from public.link_requests where id = rid and status = 'pending' for update;
  if not found then raise exception 'That request is no longer waiting'; end if;
  if exists (select 1 from public.profiles where player_id = r.player_id and id <> r.user_id) then
    raise exception 'That leaderboard entry already belongs to another account';
  end if;
  update public.profiles set player_id = r.player_id, tcg_ign = r.tcg_ign where id = r.user_id;
  update public.link_requests set status = 'approved', decided_at = now() where id = rid;
end $$;

create or replace function public.reject_link(rid bigint) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_org() then raise exception 'Only the organizer can decline links'; end if;
  update public.link_requests set status = 'rejected', decided_at = now() where id = rid and status = 'pending';
end $$;

revoke all on function public.approve_link(bigint) from public, anon;
revoke all on function public.reject_link(bigint) from public, anon;
grant execute on function public.approve_link(bigint) to authenticated;
grant execute on function public.reject_link(bigint) to authenticated;
grant select, insert on public.link_requests to authenticated;

notify pgrst, 'reload schema';
