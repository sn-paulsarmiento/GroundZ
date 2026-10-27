-- GroundZ: READ-ONLY security check. Changes nothing.
-- Run in Supabase > SQL Editor and send the result (one table) back to Claude to review.

with
tbl as (
  select c.relname as name, c.relrowsecurity as rls_on, c.relforcerowsecurity as rls_forced
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
   where n.nspname = 'public' and c.relkind in ('r','p')
),
pol as (
  select tablename as name,
         string_agg(policyname || ' [' || cmd || ' to ' || array_to_string(roles, ',') || ']'
                    || coalesce(' USING ' || qual, '') || coalesce(' CHECK ' || with_check, ''), E'\n' order by policyname) as policies
    from pg_policies where schemaname = 'public' group by tablename
),
grt as (
  select table_name as name,
         string_agg(distinct grantee || ':' || privilege_type, ', ') as table_grants
    from information_schema.role_table_grants
   where table_schema = 'public' and grantee in ('anon','authenticated') group by table_name
),
colgrt as (
  select table_name as name,
         string_agg(distinct grantee || ':' || privilege_type || '(' || column_name || ')', ', ') as column_grants
    from information_schema.column_privileges
   where table_schema = 'public' and grantee in ('anon','authenticated')
     and privilege_type in ('UPDATE','INSERT') group by table_name
)
select 'table' as kind, t.name, case when t.rls_on then 'RLS on' else '*** RLS OFF ***' end as status,
       coalesce(g.table_grants,'-') as grants, coalesce(cg.column_grants,'-') as column_write_grants,
       coalesce(p.policies,'(no policies)') as detail
  from tbl t left join pol p using (name) left join grt g using (name) left join colgrt cg using (name)
union all
select 'function', p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')',
       case when p.prosecdef then 'SECURITY DEFINER' else 'invoker' end,
       coalesce((select string_agg(r.rolname, ',') from pg_roles r
                  where r.rolname in ('anon','authenticated','public')
                    and has_function_privilege(r.oid, p.oid, 'EXECUTE')), '-'),
       coalesce(array_to_string(p.proconfig, ' '), 'no search_path set'),
       left(regexp_replace(pg_get_functiondef(p.oid), '\s+', ' ', 'g'), 600)
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'public' and p.prokind = 'f'
union all
select 'storage bucket', b.name, case when b.public then '*** PUBLIC ***' else 'private' end, '-', '-', '-'
  from storage.buckets b
order by 1, 2;
