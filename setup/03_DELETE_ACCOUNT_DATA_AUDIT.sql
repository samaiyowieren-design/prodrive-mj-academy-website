-- PRODRIVE M&J ACADEMY — ACCOUNT DELETION SAFETY AUDIT
-- READ ONLY: DOES NOT DELETE, CHANGE, OR LOCK ANY STUDENT DATA.
-- Checks which tables may hold user identifiers and how foreign keys behave.
-- Run in Supabase -> SQL Editor and export the result as CSV.

with user_columns as (
  select
    'USER_IDENTIFIER_COLUMN'::text as finding,
    format('%I.%I', c.table_schema, c.table_name) as table_or_source,
    c.column_name::text as field_or_constraint,
    c.udt_name::text as type_or_target,
    'Review whether rows belong to the account being deleted'::text as deletion_rule
  from information_schema.columns c
  where c.table_schema = 'public'
    and (
      c.column_name in (
        'user_id','student_id','owner_id','auth_user_id','profile_id',
        'redeemed_by','redeemed_by_user_id','claimed_by','claimed_user_id',
        'created_by','purchase_user_id','student_user_id'
      )
      or c.column_name ~* '(^|_)(user|student|owner|profile|account)(_.*)?_id$'
    )
), foreign_key_rules as (
  select
    'FOREIGN_KEY'::text as finding,
    c.conrelid::regclass::text as table_or_source,
    c.conname::text as field_or_constraint,
    c.confrelid::regclass::text as type_or_target,
    case c.confdeltype
      when 'c' then 'CASCADE'
      when 'n' then 'SET NULL'
      when 'd' then 'SET DEFAULT'
      when 'r' then 'RESTRICT'
      else 'NO ACTION'
    end as deletion_rule
  from pg_constraint c
  join pg_namespace n on n.oid = (select relnamespace from pg_class where oid = c.conrelid)
  where c.contype = 'f'
    and n.nspname = 'public'
)
select finding, table_or_source, field_or_constraint, type_or_target, deletion_rule
from user_columns
union all
select finding, table_or_source, field_or_constraint, type_or_target, deletion_rule
from foreign_key_rules
order by table_or_source, finding, field_or_constraint;
