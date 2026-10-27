-- GroundZ: TCG Live usernames (run once in Supabase > SQL Editor)
alter table public.profiles
  add column if not exists tcg_ign text,
  add column if not exists ign_only boolean not null default false;

grant select (tcg_ign, ign_only) on public.profiles to anon, authenticated;

create or replace function public.set_tcg_ign(n text, o boolean)
returns void language plpgsql security definer set search_path = public as $$
begin
  n := nullif(btrim(coalesce(n, '')), '');
  if n is not null and char_length(n) > 24 then
    raise exception 'TCG Live name is too long';
  end if;
  update public.profiles
     set tcg_ign = n,
         ign_only = (coalesce(o, false) and n is not null)
   where id = auth.uid();
end $$;

revoke all on function public.set_tcg_ign(text, boolean) from public, anon;
grant execute on function public.set_tcg_ign(text, boolean) to authenticated;

notify pgrst, 'reload schema';
