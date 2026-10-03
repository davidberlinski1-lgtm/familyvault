-- Family Vault update 002: family PIN (layer 1) + encrypted security team photo.
-- Run once in Supabase: SQL Editor → New query → paste → Run.
-- New installs: run schema.sql first, then this file.
--
-- After this update:
--  * Page 1 asks for the family PIN. Only with the right PIN does the server
--    send page 2: the security team photo and the security questions.
--  * Wrong PINs count towards the same lockout as wrong answers
--    (8 wrong in 15 minutes locks the vault).
--  * The photo is encrypted in the browser with a key made from the PIN.
--  * Until a PIN is set, the site works as before (straight to the questions).

alter table public.vault add column if not exists pin_salt text;   -- public salt for the PIN
alter table public.vault add column if not exists pin_hash text;   -- sha256 of a proof made from the PIN
alter table public.vault add column if not exists photo    jsonb;  -- {iv, ct, type}: encrypted photo

-- Replace functions whose arguments change.
drop function if exists public.vault_challenge();
drop function if exists public.vault_unlock(text, text);
drop function if exists public.vault_setup(jsonb, int, jsonb, text, jsonb);

-- Page 1: is there a vault, and does it have a PIN?
create or replace function public.vault_gate()
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare
  v public.vault;
begin
  select * into v from public.vault where id = 1;
  if not found then
    return jsonb_build_object('setup', false);
  end if;
  return jsonb_build_object('setup', true, 'has_pin', v.pin_hash is not null, 'pin_salt', v.pin_salt);
end $$;

-- Page 2: check the PIN, then send a random question (or pair) and the photo.
create or replace function public.vault_challenge(p_pin_proof text default null, p_with_photo boolean default true)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare
  v public.vault;
  s public.vault_slots;
  fails int;
begin
  select * into v from public.vault where id = 1;
  if not found then
    return jsonb_build_object('setup', false);
  end if;

  delete from public.vault_attempts where at < now() - interval '1 day';
  select count(*) into fails from public.vault_attempts where at > now() - interval '15 minutes';
  if fails >= 8 then
    return jsonb_build_object('error', 'locked');
  end if;
  if v.pin_hash is not null
     and (p_pin_proof is null or v.pin_hash <> encode(digest(p_pin_proof, 'sha256'), 'hex')) then
    insert into public.vault_attempts default values;
    return jsonb_build_object('error', 'wrong', 'remaining', 7 - fails);
  end if;

  select * into s from public.vault_slots order by random() limit 1;
  return jsonb_build_object(
    'setup', true,
    'combo', s.combo,
    'salt', s.salt,
    'photo', case when p_with_photo then v.photo end,
    'questions', (
      select jsonb_agg(jsonb_build_object('idx', t.i, 'text', v.questions ->> t.i) order by t.i)
      from unnest(string_to_array(s.combo, ',')::int[]) as t(i)
    )
  );
end $$;

-- Check the PIN and the answers. Returns the encrypted vault if both are right.
create or replace function public.vault_unlock(p_combo text, p_proof text, p_pin_proof text default null)
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

  select * into v from public.vault where id = 1;
  select * into s from public.vault_slots where combo = p_combo;
  if s.combo is null
     or s.auth_hash <> encode(digest(p_proof, 'sha256'), 'hex')
     or (v.pin_hash is not null
         and (p_pin_proof is null or v.pin_hash <> encode(digest(p_pin_proof, 'sha256'), 'hex'))) then
    insert into public.vault_attempts default values;
    return jsonb_build_object('error', 'wrong', 'remaining', 7 - fails);
  end if;

  delete from public.vault_attempts where true;
  return jsonb_build_object(
    'wrapped_key', s.wrapped_key,
    'data', v.data,
    'version', v.version,
    'questions', v.questions,
    'answers_required', v.answers_required,
    'has_pin', v.pin_hash is not null
  );
end $$;

-- First-time setup (now with a PIN). Only works while no vault exists.
create or replace function public.vault_setup(
  p_questions jsonb, p_answers_required int, p_data jsonb, p_write_hash text, p_slots jsonb,
  p_pin_salt text default null, p_pin_hash text default null
)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
begin
  if exists (select 1 from public.vault) then
    return jsonb_build_object('error', 'exists');
  end if;

  insert into public.vault (id, questions, answers_required, data, write_hash, pin_salt, pin_hash)
  values (1, p_questions, p_answers_required, p_data, p_write_hash, p_pin_salt, p_pin_hash);

  insert into public.vault_slots (combo, salt, auth_hash, wrapped_key)
  select x ->> 'combo', x ->> 'salt', x ->> 'auth_hash', x -> 'wrapped_key'
  from jsonb_array_elements(p_slots) as x;

  return jsonb_build_object('version', 1);
end $$;

-- Set or change the PIN (needs an unlocked vault). The photo is encrypted with
-- the PIN, so it is re-sent encrypted with the new PIN at the same time.
create or replace function public.vault_set_pin(p_proof text, p_pin_salt text, p_pin_hash text, p_photo jsonb)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare
  v public.vault;
begin
  select * into v from public.vault where id = 1 for update;
  if not found or v.write_hash <> encode(digest(p_proof, 'sha256'), 'hex') then
    return jsonb_build_object('error', 'denied');
  end if;
  update public.vault
    set pin_salt = p_pin_salt, pin_hash = p_pin_hash, photo = p_photo, updated_at = now()
  where id = 1;
  return jsonb_build_object('ok', true);
end $$;

-- Upload or replace the photo (needs an unlocked vault).
create or replace function public.vault_set_photo(p_proof text, p_photo jsonb)
returns jsonb
language plpgsql security definer set search_path = public, extensions
as $$
declare
  v public.vault;
begin
  select * into v from public.vault where id = 1 for update;
  if not found or v.write_hash <> encode(digest(p_proof, 'sha256'), 'hex') then
    return jsonb_build_object('error', 'denied');
  end if;
  update public.vault set photo = p_photo, updated_at = now() where id = 1;
  return jsonb_build_object('ok', true);
end $$;

grant execute on function public.vault_gate() to anon, authenticated;
grant execute on function public.vault_challenge(text, boolean) to anon, authenticated;
grant execute on function public.vault_unlock(text, text, text) to anon, authenticated;
grant execute on function public.vault_setup(jsonb, int, jsonb, text, jsonb, text, text) to anon, authenticated;
grant execute on function public.vault_set_pin(text, text, text, jsonb) to anon, authenticated;
grant execute on function public.vault_set_photo(text, jsonb) to anon, authenticated;

-- If the family forgets the PIN, remove it (then set a new one inside the vault):
--   update public.vault set pin_salt = null, pin_hash = null, photo = null;
