# Family Vault

A private website for the family's streaming logins, with two layers of security:

1. **Page 1 (public):** the family PIN.
2. **Page 2 (only after the PIN):** the security team photo and security questions.
   You write 10 questions, and each visit asks one or two at random.

- **Hosting:** GitHub Pages (free, static files only)
- **Storage:** Supabase (free tier)
- **Encryption:** done in the browser, so Supabase only ever stores scrambled data

## How it keeps the passwords safe

| Risk | Protection |
|---|---|
| Someone reads the database | Everything is encrypted (AES-256) with a key that only correct answers can unlock. Answers are never stored. |
| Someone guesses the PIN or answers | 8 wrong PINs or answers in 15 minutes locks the vault for everyone. Guesses are checked by the server, so they can't be tried offline. |
| Strangers see family photos | The photo and the questions are only sent after the right PIN. The photo is encrypted with the PIN and never stored as a plain file. |
| Someone vandalises the vault | Only someone who has unlocked it can save changes. |
| A laptop is left open | The vault locks itself after 10 minutes of inactivity. |
| Two people edit at once | Neither person's change is lost. The site reloads the latest version and applies the change again. |

**Important:** if everyone forgets the answers, the passwords can't be recovered.
That's the point of the encryption. Keep a note of the answers somewhere safe offline.

**Tips for good questions:** pick things only the family knows ("what do we call
the TV remote?"). Avoid things findable on Facebook or LinkedIn, like birthdays,
schools, or a mother's maiden name. "2 questions" mode is much harder to guess.

## Setup (about 15 minutes)

### 1. Supabase
1. Go to <https://supabase.com/dashboard> and create a **New project** (e.g. `family-vault`).
2. Open **SQL Editor → New query**, paste everything in [`supabase/schema.sql`](supabase/schema.sql), and click **Run**.
   Then do the same with [`supabase/002_pin_and_photo.sql`](supabase/002_pin_and_photo.sql).
3. Open **Project Settings → API Keys**. Copy the **Project URL** and the **publishable key**
   (or the legacy `anon` key).
4. Paste both into [`config.js`](config.js).

### 2. GitHub Pages
1. Create a new repository at <https://github.com/new>, e.g. `family-vault`.
   It can be public. The code contains no secrets.
2. Upload these files (drag and drop works) or push them with git.
3. In the repo go to **Settings → Pages**, set **Source: Deploy from a branch** and
   **Branch: main / (root)**, then click **Save**.
4. After about a minute your site is live at `https://YOUR-USERNAME.github.io/family-vault/`.

### 3. Create the vault
Open the site **straight away** and choose a family PIN, then fill in your 10 questions and answers. Until
that's done, anyone who finds the address could set it up first. Setup takes
under a minute while the site builds the encryption keys.

Then open **Settings** to upload the security team photo, and share the link with the family.

## Maintenance (Supabase SQL Editor)
- Clear a lockout early: `truncate public.vault_attempts;`
- Wipe everything and start over (**deletes all saved logins**):
  `truncate public.vault, public.vault_slots, public.vault_attempts;`
- Change the PIN, photo or questions: unlock the site and click **Settings**.
- Forgotten PIN: `update public.vault set pin_salt = null, pin_hash = null, photo = null;`
  then unlock with the questions and set a new PIN (and re-upload the photo) in **Settings**.
