-- Family Vault — Supabase schema
-- Run this once in Supabase: Dashboard → SQL Editor → New query → paste → Run.
--
-- How it stays safe:
--  * Passwords are encrypted in the browser before they are sent here. Supabase
--    only ever stores scrambled data (AES-256-GCM).
--  * The tables are locked (RLS on, no policies). The website can only talk to
--    the database through the functions below.
--  * Wrong answers are counted; 8 wrong answers in 15 minutes locks the vault.

create extension if not exists pgcrypto with schema extensions;

-- One row: the encrypted vault plus the question texts.
create table if not exists public.vault (
  id               int primary key default 1 check (id = 1),
  questions        jsonb not null,          -- ["question 1", ... "question 10"]
  answers_required int not null check (answers_required between 1 and 3),
  data             jsonb not null,          -- {iv, ct}: encrypted list of logins
  write_hash       text not null,           -- proves a writer has unlocked the vault
  version          int not null default 1,  -- stops two people overwriting each other
  updated_at       timestamptz not null default now()
);

-- One "key slot" per question (or per pair of questions). Each slot holds the
-- vault key encrypted with the answer(s) to that question/pair.
create table if not exists public.vault_slots (
  combo       text primary key,   -- e.g. '3' or '2,7' (question numbers, 0-based)
  salt        text not null,
  auth_hash   text not null,      -- sha256 of a proof derived from the answers
  wrapped_key jsonb not null      -- {iv, ct}
);

-- Failed unlock attempts, for the lockout.
create table if not exists public.vault_attempts (
  id bigserial primary key,
  at timestamptz not null default now()
);

alter table public.vault          enable row level security;
alter table public.vault_slots    enable row level security;
alter table public.vault_attempts enable row level security;
revoke all on public.vault, public.vault_slots, public.vault_attempts from anon, authenticated;

-- Has the vault been created? If so, pick a random question (or pair) to ask.
create or replace function public.vault_challenge()
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare
  v public.vault;
  s public.vault_slots;
begin
  select * into v from public.vault where id = 1;
  if not found then
    return jsonb_build_object('setup', false);
  end if;

  select * into s from public.vault_slots order by random() limit 1;
  return jsonb_build_object(
    'setup', true,
    'combo', s.combo,
    'salt', s.salt,
    'questions', (
      select jsonb_agg(jsonb_build_object('idx', t.i, 'text', v.questions ->> t.i) order by t.i)
      from unnest(string_to_array(s.combo, ',')::int[]) as t(i)
    )
  );
end $$;

-- Check the answer proof. Returns the encrypted vault if correct.
create or replace function public.vault_unlock(p_combo text, p_proof text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare
  v public.vault;
  s public.vault_slots;
  fails int;
begin
  delete from public.vault_attempts where at < now() - interval '1 day';
  select count(*) into fails from public.vault_attempts where at > now() - interval '15 minutes';
  if fails >= 8 then
    return jsonb_build_object('error', 'locked');
  end if;

  select * into s from public.vault_slots where combo = p_combo;
  if not found or s.auth_hash <> encode(digest(p_proof, 'sha256'), 'hex') then
    insert into public.vault_attempts default values;
    return jsonb_build_object('error', 'wrong', 'remaining', 7 - fails);
  end if;

  delete from public.vault_attempts where true;
  select * into v from public.vault where id = 1;
  return jsonb_build_object(
    'wrapped_key', s.wrapped_key,
    'data', v.data,
    'version', v.version,
    'questions', v.questions,
    'answers_required', v.answers_required
  );
end $$;

-- Re-read the latest vault (used when someone else saved in the meantime).
create or replace function public.vault_fetch(p_proof text)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare
  v public.vault;
begin
  select * into v from public.vault where id = 1;
  if not found or v.write_hash <> encode(digest(p_proof, 'sha256'), 'hex') then
    return jsonb_build_object('error', 'denied');
  end if;
  return jsonb_build_object(
    'data', v.data,
    'version', v.version,
    'questions', v.questions,
    'answers_required', v.answers_required
  );
end $$;

-- First-time setup. Only works while no vault exists.
create or replace function public.vault_setup(
  p_questions jsonb, p_answers_required int, p_data jsonb, p_write_hash text, p_slots jsonb
)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
begin
  if exists (select 1 from public.vault) then
    return jsonb_build_object('error', 'exists');
  end if;

  insert into public.vault (id, questions, answers_required, data, write_hash)
  values (1, p_questions, p_answers_required, p_data, p_write_hash);

  insert into public.vault_slots (combo, salt, auth_hash, wrapped_key)
  select x ->> 'combo', x ->> 'salt', x ->> 'auth_hash', x -> 'wrapped_key'
  from jsonb_array_elements(p_slots) as x;

  return jsonb_build_object('version', 1);
end $$;

-- Save changes. Only someone who has unlocked the vault can produce p_proof.
-- Pass p_questions / p_answers_required / p_slots to change the security questions.
create or replace function public.vault_save(
  p_proof text, p_version int, p_data jsonb,
  p_questions jsonb default null, p_answers_required int default null, p_slots jsonb default null
)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare
  v public.vault;
begin
  select * into v from public.vault where id = 1 for update;
  if not found then
    return jsonb_build_object('error', 'missing');
  end if;
  if v.write_hash <> encode(digest(p_proof, 'sha256'), 'hex') then
    return jsonb_build_object('error', 'denied');
  end if;
  if v.version <> p_version then
    return jsonb_build_object('error', 'conflict');
  end if;

  update public.vault set
    data = p_data,
    questions = coalesce(p_questions, questions),
    answers_required = coalesce(p_answers_required, answers_required),
    version = version + 1,
    updated_at = now()
  where id = 1;

  if p_slots is not null then
    delete from public.vault_slots where true;
    insert into public.vault_slots (combo, salt, auth_hash, wrapped_key)
    select x ->> 'combo', x ->> 'salt', x ->> 'auth_hash', x -> 'wrapped_key'
    from jsonb_array_elements(p_slots) as x;
  end if;

  return jsonb_build_object('version', v.version + 1);
end $$;

grant execute on function public.vault_challenge() to anon, authenticated;
grant execute on function public.vault_unlock(text, text) to anon, authenticated;
grant execute on function public.vault_fetch(text) to anon, authenticated;
grant execute on function public.vault_setup(jsonb, int, jsonb, text, jsonb) to anon, authenticated;
grant execute on function public.vault_save(text, int, jsonb, jsonb, int, jsonb) to anon, authenticated;

-- To wipe everything and start again (deletes all saved passwords!):
--   truncate public.vault, public.vault_slots, public.vault_attempts;
-- To clear a lockout early:
--   truncate public.vault_attempts;
