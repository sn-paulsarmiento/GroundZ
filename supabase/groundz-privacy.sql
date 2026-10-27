-- GroundZ: privacy (UAE PDPL) — consent records, account deletion, privacy requests, shorter email retention
-- Run once in Supabase > SQL Editor. Safe to run again.

-- 1) Consent records + age group, in their own table so other players can never read them (only through the functions below)
create table if not exists public.consents (
  user_id         uuid primary key references auth.users(id) on delete cascade,
  consent_version text,
  consent_at      timestamptz,
  marketing       boolean not null default false,
  marketing_at    timestamptz
);
alter table public.consents add column if not exists age_band text check (age_band in ('18+','13-17'));
alter table public.consents enable row level security;
revoke all on public.consents from anon, authenticated;

drop function if exists public.get_my_consent();
create function public.get_my_consent()
returns table(consent_version text, consent_at timestamptz, marketing boolean, marketing_at timestamptz, age_band text)
language sql stable security definer set search_path = public as $$
  select c.consent_version, c.consent_at, coalesce(c.marketing,false), c.marketing_at, c.age_band
    from (select auth.uid() as uid) me left join public.consents c on c.user_id = me.uid
   where me.uid is not null;
$$;

create or replace function public.is_teen(uid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.consents where user_id = uid and age_band = '13-17');
$$;

drop function if exists public.set_consent(text, boolean);
create or replace function public.set_consent(v text, mk boolean, age text default null)
returns void language plpgsql security definer set search_path = public as $$
declare band text;
begin
  if auth.uid() is null then raise exception 'Sign in first'; end if;
  if v is null or char_length(v) > 20 then raise exception 'Invalid notice version'; end if;
  if age is not null and age not in ('18+','13-17') then raise exception 'GroundZ accounts are for players 13 and older'; end if;
  insert into public.consents(user_id, consent_version, consent_at, marketing, marketing_at, age_band)
  values (auth.uid(), v, now(), coalesce(mk,false), case when coalesce(mk,false) then now() end, age)
  on conflict (user_id) do update set
    consent_at      = case when public.consents.consent_version is distinct from excluded.consent_version then now() else public.consents.consent_at end,
    consent_version = excluded.consent_version,
    marketing_at    = case when public.consents.marketing is distinct from excluded.marketing then now() else public.consents.marketing_at end,
    marketing       = excluded.marketing,
    age_band        = coalesce(excluded.age_band, public.consents.age_band);
  select age_band into band from public.consents where user_id = auth.uid();
  if band = '13-17' then
    -- players under 18: private by default (UAE Child Digital Safety Law)
    update public.consents set marketing = false where user_id = auth.uid();
    update public.profiles set avatar = null where id = auth.uid();
    update public.decklists set is_public = false where user_id = auth.uid();
  end if;
end $$;

-- teen accounts stay private even if someone bypasses the site
create or replace function public.teen_guard_profile() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.avatar is not null and public.is_teen(new.id) then
    raise exception 'Profile pictures are off for players under 18';
  end if;
  return new;
end $$;
drop trigger if exists teen_guard_profile on public.profiles;
create trigger teen_guard_profile before insert or update of avatar on public.profiles
  for each row execute function public.teen_guard_profile();

create or replace function public.teen_guard_decklist() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.is_public and public.is_teen(new.user_id) then new.is_public := false; end if;
  return new;
end $$;
drop trigger if exists teen_guard_decklist on public.decklists;
create trigger teen_guard_decklist before insert or update on public.decklists
  for each row execute function public.teen_guard_decklist();

-- 2) Log of privacy requests (PDPL: keep a record of data-subject requests)
create table if not exists public.privacy_requests (
  id          bigint generated always as identity primary key,
  kind        text not null check (kind in ('delete','export','other')),
  player_id   bigint,
  created_at  timestamptz not null default now(),
  handled_at  timestamptz
);
alter table public.privacy_requests enable row level security;
revoke all on public.privacy_requests from anon, authenticated;   -- only reachable through the functions below

-- 3) Delete my account: erases every row linked to the account, logs the request, then removes the login
create or replace function public.delete_my_account()
returns void language plpgsql security definer set search_path = public, auth as $$
declare uid uuid := auth.uid(); pid bigint; r record;
begin
  if uid is null then raise exception 'Sign in first'; end if;
  if exists (select 1 from public.profiles where id = uid and role = 'org') then
    raise exception 'The organizer account can''t be deleted here. Hand over the league first.';
  end if;
  select player_id into pid from public.profiles where id = uid;
  insert into public.privacy_requests(kind, player_id) values ('delete', pid);
  -- every public table with a foreign key to auth.users (registrations, decklists, player_data, link_requests, …)
  for r in
    select c.conrelid::regclass as tbl, a.attname as col
      from pg_constraint c
      join pg_attribute a on a.attrelid = c.conrelid and a.attnum = any(c.conkey)
     where c.contype = 'f' and c.confrelid = 'auth.users'::regclass
       and c.connamespace = 'public'::regnamespace and c.conrelid <> 'public.profiles'::regclass
  loop
    execute format('delete from %s where %I = $1', r.tbl, r.col) using uid;
  end loop;
  delete from public.registrations where user_id = uid;
  delete from public.decklists     where user_id = uid;
  delete from public.player_data   where user_id = uid;
  delete from public.profiles      where id = uid;
  delete from auth.users           where id = uid;
end $$;

-- 4) Organizer: see and close privacy requests
create or replace function public.list_privacy_requests()
returns setof public.privacy_requests language plpgsql stable security definer set search_path = public as $$
begin
  if not public.is_org() then raise exception 'Only the organizer can see privacy requests'; end if;
  return query select * from public.privacy_requests where handled_at is null order by created_at;
end $$;

create or replace function public.mark_privacy_handled(rid bigint)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_org() then raise exception 'Only the organizer can update privacy requests'; end if;
  update public.privacy_requests set handled_at = now() where id = rid;
end $$;

-- 5) Link requests: keep the TCG Live email only until the organizer decides
alter table public.link_requests alter column tcg_email drop not null;
update public.link_requests set tcg_email = null where status <> 'pending' and tcg_email is not null;

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
  update public.link_requests set status = 'approved', decided_at = now(), tcg_email = null where id = rid;
end $$;

create or replace function public.reject_link(rid bigint) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_org() then raise exception 'Only the organizer can decline links'; end if;
  update public.link_requests set status = 'rejected', decided_at = now(), tcg_email = null where id = rid and status = 'pending';
end $$;

-- 6) Who may call what
revoke all on function public.get_my_consent()          from public, anon;
revoke all on function public.set_consent(text,boolean,text) from public, anon;
revoke all on function public.is_teen(uuid) from public, anon, authenticated;
revoke all on function public.delete_my_account()        from public, anon;
revoke all on function public.list_privacy_requests()    from public, anon;
revoke all on function public.mark_privacy_handled(bigint) from public, anon;
revoke all on function public.approve_link(bigint)       from public, anon;
revoke all on function public.reject_link(bigint)        from public, anon;
grant execute on function public.get_my_consent()          to authenticated;
grant execute on function public.set_consent(text,boolean,text) to authenticated;
grant execute on function public.delete_my_account()        to authenticated;
grant execute on function public.list_privacy_requests()    to authenticated;
grant execute on function public.mark_privacy_handled(bigint) to authenticated;
grant execute on function public.approve_link(bigint)       to authenticated;
grant execute on function public.reject_link(bigint)        to authenticated;

notify pgrst, 'reload schema';
