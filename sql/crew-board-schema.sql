-- ============================================================================
-- CREW BOARD — CONSOLIDATED SCHEMA + RLS SCRIPT
-- ----------------------------------------------------------------------------
-- Project: omlgxlecijdvczbnteai
-- Run once in the Supabase SQL Editor. Safe to re-run (idempotent).
--
-- Fixes:
--   1. Privilege escalation at signup (anyone could insert themselves as owner)
--   2. Anonymous read access to the full user list
--   3. Admin self-promotion to owner
--   4. Forgeable requester_id on change requests
--   5. Bogus gen_random_uuid() defaults on identity columns
--   6. Missing unique constraint on user_roles.user_id
--   7. Missing foreign key on requests.roster_id
-- ============================================================================

begin;

-- ============================================================================
-- 1. HELPER FUNCTIONS
-- ----------------------------------------------------------------------------
-- These are SECURITY DEFINER so that policies on user_roles can read
-- user_roles without recursing into user_roles' own RLS policies.
-- Each returns information about the *calling* user only.
-- ============================================================================

create or replace function public.current_user_role()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select role from public.user_roles where user_id = auth.uid() limit 1;
$$;

create or replace function public.current_user_status()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select status from public.user_roles where user_id = auth.uid() limit 1;
$$;

create or replace function public.is_manager()
returns boolean
language sql
stable
as $$
  select public.current_user_role()
    in ('admin', 'owner', 'hidden_admin', 'hidden_owner');
$$;

create or replace function public.is_owner()
returns boolean
language sql
stable
as $$
  select public.current_user_role() in ('owner', 'hidden_owner');
$$;


-- ============================================================================
-- 2. COLUMN DEFAULTS
-- ----------------------------------------------------------------------------
-- gen_random_uuid() on an identity column is a table-editor leftover. If the
-- app ever omitted the value, the row would silently be assigned to a user
-- that does not exist. These columns must always be supplied explicitly.
-- ============================================================================

alter table public.user_roles alter column user_id     drop default;
alter table public.requests   alter column requester_id drop default;


-- ============================================================================
-- 3. CONSTRAINTS
-- ----------------------------------------------------------------------------
-- Guarded: if existing data violates a constraint, the script raises a NOTICE
-- and continues rather than aborting. Check the Messages pane after running.
-- ============================================================================

-- user_roles.user_id must be NOT NULL and UNIQUE.
-- The app calls .single() on this column and every RLS policy assumes at most
-- one row per user. A duplicate would make those scalar subqueries error out.
do $$
begin
  if exists (select 1 from public.user_roles where user_id is null) then
    raise notice 'SKIPPED user_roles.user_id NOT NULL — null rows exist. Clean up, then re-run.';
  else
    alter table public.user_roles alter column user_id set not null;
  end if;
end $$;

do $$
begin
  if exists (
    select 1 from public.user_roles group by user_id having count(*) > 1
  ) then
    raise notice 'SKIPPED unique(user_roles.user_id) — duplicates exist. Clean up, then re-run.';
  elsif not exists (
    select 1 from pg_constraint where conname = 'user_roles_user_id_key'
  ) then
    alter table public.user_roles
      add constraint user_roles_user_id_key unique (user_id);
  end if;
end $$;

-- requests.roster_id should point at a real roster row.
-- ON DELETE SET NULL so removing a person does not destroy the audit trail.
do $$
begin
  if exists (select 1 from pg_constraint where conname = 'requests_roster_id_fkey') then
    null;
  elsif exists (
    select 1 from public.requests r
    where r.roster_id is not null
      and not exists (select 1 from public.roster ro where ro.id = r.roster_id)
  ) then
    raise notice 'SKIPPED FK requests.roster_id — orphaned rows exist. Clean up, then re-run.';
  else
    alter table public.requests
      add constraint requests_roster_id_fkey
      foreign key (roster_id) references public.roster(id) on delete set null;
  end if;
end $$;

-- A roster row without a name is meaningless; the UI already requires one.
do $$
begin
  if exists (select 1 from public.roster where name is null) then
    raise notice 'SKIPPED roster.name NOT NULL — null rows exist. Clean up, then re-run.';
  else
    alter table public.roster alter column name set not null;
  end if;
end $$;


-- ============================================================================
-- 4. ROLE-CHANGE GUARD
-- ----------------------------------------------------------------------------
-- RLS WITH CHECK cannot see the OLD row, so it cannot express "you may change
-- status but not role". A trigger can. This is what actually stops an Admin
-- from promoting themselves, and what protects the Owner account.
-- ============================================================================

create or replace function public.enforce_role_change_rules()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.user_id is distinct from old.user_id then
    raise exception 'user_id is immutable';
  end if;

  if old.role in ('owner', 'hidden_owner') and not public.is_owner() then
    raise exception 'The Owner account cannot be modified';
  end if;

  if new.role is distinct from old.role and not public.is_owner() then
    raise exception 'Only the Owner can change roles';
  end if;

  return new;
end;
$$;

drop trigger if exists user_roles_guard on public.user_roles;
create trigger user_roles_guard
  before update on public.user_roles
  for each row execute function public.enforce_role_change_rules();


-- ============================================================================
-- 5. ROW LEVEL SECURITY
-- ----------------------------------------------------------------------------
-- Every policy is scoped TO AUTHENTICATED. The previous policies were TO PUBLIC,
-- which in Supabase includes the anon role — i.e. anyone holding the anon key
-- published in index.html.
-- ============================================================================

alter table public.roster     enable row level security;
alter table public.requests   enable row level security;
alter table public.user_roles enable row level security;

-- ── roster ──────────────────────────────────────────────────────────────────

drop policy if exists roster_read  on public.roster;
drop policy if exists roster_write on public.roster;

create policy roster_read on public.roster
  for select to authenticated
  using (public.current_user_status() = 'approved');

create policy roster_write on public.roster
  for all to authenticated
  using (public.is_manager())
  with check (public.is_manager());

-- ── requests ────────────────────────────────────────────────────────────────

drop policy if exists requests_read   on public.requests;
drop policy if exists requests_insert on public.requests;
drop policy if exists requests_update on public.requests;

-- requester_id is now pinned to the caller: no forging who asked for what.
-- status is pinned to 'pending': no self-approving on the way in.
create policy requests_insert on public.requests
  for insert to authenticated
  with check (
    requester_id = auth.uid()
    and public.current_user_status() = 'approved'
    and status = 'pending'
  );

create policy requests_read on public.requests
  for select to authenticated
  using (requester_id = auth.uid() or public.is_manager());

create policy requests_update on public.requests
  for update to authenticated
  using (public.is_manager())
  with check (public.is_manager());

-- ── user_roles ──────────────────────────────────────────────────────────────

drop policy if exists user_roles_read           on public.user_roles;
drop policy if exists user_roles_insert         on public.user_roles;
drop policy if exists user_roles_update         on public.user_roles;
drop policy if exists user_roles_read_self      on public.user_roles;
drop policy if exists user_roles_read_managers  on public.user_roles;
drop policy if exists user_roles_insert_self    on public.user_roles;
drop policy if exists user_roles_update_managers on public.user_roles;

-- Everyone can see their own row (the app needs this for full_name and role).
create policy user_roles_read_self on public.user_roles
  for select to authenticated
  using (user_id = auth.uid());

-- Admins and the Owner can see everyone (Manage Users panel).
create policy user_roles_read_managers on public.user_roles
  for select to authenticated
  using (public.is_manager());

-- THE CRITICAL FIX: a new signup may only ever create their own row,
-- as a pending member. role and status are no longer caller-controlled.
create policy user_roles_insert_self on public.user_roles
  for insert to authenticated
  with check (
    user_id = auth.uid()
    and role = 'member'
    and status = 'pending'
  );

-- Managers may update rows; the trigger in section 4 decides what they may
-- actually change.
create policy user_roles_update_managers on public.user_roles
  for update to authenticated
  using (public.is_manager())
  with check (public.is_manager());

commit;


-- ============================================================================
-- 6. VERIFICATION
-- ----------------------------------------------------------------------------
-- Run this after the script. Every table should show 'enabled', and no policy
-- should list anon among its roles.
-- ============================================================================

select
  c.relname                                                as table_name,
  case when c.relrowsecurity then 'enabled' else 'DISABLED' end as rls,
  p.policyname,
  p.cmd,
  array_to_string(p.roles, ',')                            as roles
from pg_class c
left join pg_policies p
  on p.schemaname = 'public' and p.tablename = c.relname
where c.relnamespace = 'public'::regnamespace
  and c.relname in ('roster', 'requests', 'user_roles')
order by c.relname, p.policyname;
