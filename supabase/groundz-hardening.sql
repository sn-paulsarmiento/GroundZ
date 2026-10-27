-- GroundZ: database hardening after the 27 Oct 2026 security audit
-- Run once in Supabase > SQL Editor, AFTER groundz-privacy.sql. Safe to run again.
-- Applied to the live GroundZ project on 28 Oct 2026 as migration groundz_hardening.
-- Your access rules (RLS) already block these actions; this removes the underlying permissions too,
-- so a future mistake in a rule can't expose anything.

do $$
declare t record;
begin
  for t in select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace
            where n.nspname = 'public' and c.relkind in ('r','p') loop
    -- visitors who aren't logged in can only read; every change needs an account
    execute format('revoke insert, update, delete, truncate, references, trigger on public.%I from anon', t.relname);
    -- logged-in players never need to empty tables or attach triggers
    execute format('revoke truncate, references, trigger on public.%I from authenticated', t.relname);
  end loop;
end $$;

-- the same for tables created in future
alter default privileges in schema public revoke insert, update, delete, truncate, references, trigger on tables from anon;
alter default privileges in schema public revoke truncate, references, trigger on tables from authenticated;

-- profiles change only through the site's checked functions (display name, picture, TCG Live name)
-- and the sign-up trigger, so nobody can edit role, player_id or someone else's row directly
revoke insert, update, delete on public.profiles from authenticated;

-- the league record is only ever updated (by the organizer), never created or deleted from the site
revoke insert, delete on public.league_state from authenticated;

-- fix the one function without a fixed search_path
alter function public.bump_version() set search_path = public;

notify pgrst, 'reload schema';
