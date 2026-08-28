select 'RLS' as kind,
       c.relname::text as obj,
       case when c.relrowsecurity then 'enabled' else 'DISABLED' end as detail
from pg_class c
where c.relnamespace = 'public'::regnamespace
  and c.relname in ('roster','requests','user_roles')

union all
select 'TRIGGER', t.tgname::text, 'present'
from pg_trigger t
where t.tgrelid = 'public.user_roles'::regclass
  and not t.tgisinternal

union all
select 'FUNCTION',
       p.proname::text,
       case when p.prosecdef then 'security definer' else 'invoker' end
from pg_proc p
where p.pronamespace = 'public'::regnamespace
  and p.proname in ('current_user_role','current_user_status',
                    'is_manager','is_owner','enforce_role_change_rules')

union all
select 'CONSTRAINT',
       con.conrelid::regclass::text || '.' || con.conname,
       case con.contype when 'u' then 'unique'
                        when 'f' then 'foreign key'
                        else con.contype::text end
from pg_constraint con
where con.conname in ('user_roles_user_id_key','requests_roster_id_fkey')

union all
select 'DEFAULT',
       c.table_name || '.' || c.column_name,
       coalesce(c.column_default, 'none') || ' | '
         || case when c.is_nullable = 'YES' then 'nullable' else 'not null' end
from information_schema.columns c
where c.table_schema = 'public'
  and (c.table_name = 'user_roles' and c.column_name = 'user_id'
    or c.table_name = 'requests'   and c.column_name = 'requester_id'
    or c.table_name = 'roster'     and c.column_name = 'name')

order by 1, 2;
