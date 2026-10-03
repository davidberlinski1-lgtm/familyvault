// All encryption happens here, in the browser. Supabase never sees answers,
// the vault key, or any saved password in readable form.

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

// Slows down anyone guessing answers. Pairs of answers are already far harder
// to guess than one, so they use fewer rounds (keeps 45 pair-slots quick to build).
const iterationsFor = answerCount => (answerCount === 1 ? 600_000 : 150_000);

// "St. John's" and "st johns" count as the same answer.
export function normalizeAnswer(answer) {
  return answer
    .normalize('NFKD')
    .replace(/\p{M}/gu, '')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]/gu, '');
}

export function toB64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

export function fromB64(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

const toHex = bytes => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
const randomBytes = n => globalThis.crypto.getRandomValues(new Uint8Array(n));

export async function sha256Hex(text) {
  return toHex(new Uint8Array(await subtle.digest('SHA-256', enc.encode(text))));
}

// Every way of picking k question numbers out of n, e.g. (3, 2) → [0,1] [0,2] [1,2].
export function combinations(n, k) {
  const out = [];
  const walk = (start, picked) => {
    if (picked.length === k) return out.push([...picked]);
    for (let i = start; i < n; i++) walk(i + 1, [...picked, i]);
  };
  walk(0, []);
  return out;
}

// Answers (in question-number order) → a key that unwraps the vault key, plus a
// separate proof the server can check without learning anything about the answers.
export async function deriveFromAnswers(answers, saltB64) {
  const material = answers.map(normalizeAnswer).join('\u001f');
  const base = await subtle.importKey('raw', enc.encode(material), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: fromB64(saltB64), iterations: iterationsFor(answers.length) },
    base,
    512,
  ));
  const wrapKey = await subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt']);
  return { wrapKey, authProof: toHex(bits.slice(32)) };
}

async function aesEncrypt(key, bytes) {
  const iv = randomBytes(12);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));
  return { iv: toB64(iv), ct: toB64(ct) };
}

async function aesDecrypt(key, box) {
  return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(box.iv) }, key, fromB64(box.ct)));
}

const importVaultKey = raw => subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);

export const newVaultKey = () => randomBytes(32);

export async function unwrapVaultKey(wrapKey, wrapped) {
  try {
    return await aesDecrypt(wrapKey, wrapped);
  } catch {
    throw new Error('Those answers did not unlock the vault.');
  }
}

export async function encryptEntries(vaultKey, entries) {
  return aesEncrypt(await importVaultKey(vaultKey), enc.encode(JSON.stringify(entries)));
}

export async function decryptEntries(vaultKey, box) {
  return JSON.parse(dec.decode(await aesDecrypt(await importVaultKey(vaultKey), box)));
}

// Anyone who has unlocked the vault can compute this; nobody else can.
export async function writeProof(vaultKey) {
  return sha256Hex('family-vault-write:' + toHex(vaultKey));
}

// One key slot per question (or per pair of questions when k = 2).
export async function buildKeySlots(vaultKey, answers, k, onProgress) {
  const combos = combinations(answers.length, k);
  let done = 0;
  const makeSlot = async combo => {
    const salt = toB64(randomBytes(16));
    const { wrapKey, authProof } = await deriveFromAnswers(combo.map(j => answers[j]), salt);
    const slot = {
      combo: combo.join(','),
      salt,
      auth_hash: await sha256Hex(authProof),
      wrapped_key: await aesEncrypt(wrapKey, vaultKey),
    };
    onProgress?.(++done, combos.length);
    return slot;
  };
  // Browsers run key derivation on background threads, so a few at once is faster.
  const slots = [];
  for (let i = 0; i < combos.length; i += 4) {
    slots.push(...await Promise.all(combos.slice(i, i + 4).map(makeSlot)));
  }
  return slots;
}
