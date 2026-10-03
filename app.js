import { rpc, isConfigured } from './api.js';
import * as vc from './crypto.js';

const QUESTION_COUNT = 10;
const IDLE_LOCK_MS = 10 * 60 * 1000;
const FIELDS = ['service', 'profile', 'username', 'password', 'url', 'notes'];
const GATE_VIEWS = new Set(['loading', 'unlock', 'questions']);
const PHOTO_MAX_PX = 900;

const DEFAULT_QUESTIONS = [
  'What was the name of our first family pet?',
  'Where did we go on our first family holiday abroad?',
  'What do we call the TV remote in our house?',
  'What street was our first family home on?',
  'Which restaurant do we always go to for birthdays?',
  'What was the make and colour of our first family car?',
  'What dish does everyone always ask for at Sunday dinner?',
  'What was the name of the youngest\'s favourite cuddly toy?',
  'Which song always gets played on family car journeys?',
  'What is the family nickname for Grandad?',
];

const BRAND_COLORS = {
  netflix: '#E50914', disney: '#113CCF', prime: '#00A8E1', amazon: '#00A8E1',
  apple: '#333333', max: '#002BE7', hbo: '#5822B4', now: '#00818A',
  paramount: '#0064FF', iplayer: '#F54997', bbc: '#F54997', itv: '#00C7A9',
  spotify: '#1DB954', youtube: '#FF0000', sky: '#0072C9', hulu: '#1CE783',
  peacock: '#000000', crunchyroll: '#F47521', dazn: '#191919',
};

const state = {
  key: null, proof: null, version: 0, entries: [],
  questions: [], required: 1, challenge: null,
};
let editingId = null;

// ---------- helpers ----------

const $ = (sel, root = document) => root.querySelector(sel);

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? '' : v);
  }
  node.append(...[].concat(children).filter(c => c != null && c !== false && c !== ''));
  return node;
}

function show(view) {
  for (const s of document.querySelectorAll('main [data-view]')) s.hidden = s.dataset.view !== view;
  document.body.dataset.view = view;
  document.body.dataset.theme = GATE_VIEWS.has(view) ? 'gate' : '';
  window.scrollTo(0, 0);
}

function showError(message) {
  $('#error-msg').textContent = message;
  show('error');
}

let toastTimer;
function toast(text) {
  const t = $('#toast');
  t.textContent = text;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 1800);
}

function setBusy(form, busy) {
  for (const c of form.querySelectorAll('button, input, select, textarea')) c.disabled = busy;
}

function setMsg(form, text, info = false) {
  const m = $('.msg', form);
  m.textContent = text;
  m.classList.toggle('info', info);
}

// ---------- page 1: family PIN ----------

const wait = ms => new Promise(r => setTimeout(r, ms));
// Don't pop up the phone keyboard (and scroll past the photo) on touch screens.
const focusIfDesktop = input => { if (matchMedia('(pointer: fine)').matches) input?.focus(); };

async function start() {
  Object.assign(state, {
    key: null, proof: null, entries: [], challenge: null,
    pinKey: null, pinProof: null, hasPin: false,
  });
  $('#entries').replaceChildren();
  setPhoto(null);
  if ($('#entry-dialog').open) $('#entry-dialog').close();

  if (!isConfigured()) {
    showError('This site isn\'t connected yet. Add your Supabase URL and key to config.js, then reload.');
    return;
  }
  show('loading');
  try {
    const gate = await rpc('vault_gate');
    if (!gate.setup) {
      renderQaForm($('#setup-form'), DEFAULT_QUESTIONS, 2);
      show('setup');
      return;
    }
    state.gate = gate;
    renderPinPage();
    show('unlock');
    focusIfDesktop($('#pin-input'));
  } catch (err) {
    showError(/vault_gate/.test(err.message)
      ? 'The database needs updating. Run supabase/002_pin_and_photo.sql in Supabase.'
      : err.message);
  }
}

function renderPinPage() {
  const form = $('#pin-form');
  const hasPin = state.gate.has_pin;
  form.reset();
  $('#pin-input').hidden = !hasPin;
  $('#pin-input').required = hasPin;
  $('#pin-prompt').textContent = hasPin ? 'Enter the original Berlinski family PIN' : 'No family PIN set yet';
  setMsg(form, '');
  $('.dial-wrap').classList.remove('open');
  for (const p of document.querySelectorAll('.gate-panel')) p.classList.remove('denied');
}

function denied(form, text) {
  setMsg(form, text);
  const panel = form.closest('.gate-panel');
  panel.classList.remove('denied');
  void panel.offsetWidth; // restart the shake animation
  panel.classList.add('denied');
}

function wrongMessage(res) {
  if (res.error === 'locked') return 'Too many wrong tries. The vault is locked for 15 minutes.';
  return res.remaining > 0
    ? `Access denied. ${res.remaining} more wrong ${res.remaining === 1 ? 'try' : 'tries'} and the vault locks for 15 minutes.`
    : 'Access denied. The vault is now locked for 15 minutes.';
}

const validPin = pin => /^\d{4,8}$/.test(pin);

async function onPin(e) {
  e.preventDefault();
  const form = e.target;
  let pinKey = null;
  let pinProof = null;

  setBusy(form, true);
  setMsg(form, 'Checking…', true);
  try {
    if (state.gate.has_pin) {
      const pin = form.elements.pin.value.trim();
      if (!validPin(pin)) return denied(form, 'The PIN is 4 to 8 digits.');
      ({ wrapKey: pinKey, authProof: pinProof } = await vc.derivePinKeys(pin, state.gate.pin_salt));
    }
    const ch = await rpc('vault_challenge', { p_pin_proof: pinProof });
    if (ch.error) return denied(form, wrongMessage(ch));

    Object.assign(state, { pinKey, pinProof });
    setMsg(form, state.gate.has_pin ? 'PIN accepted.' : '', true);
    $('.dial-wrap').classList.add('open');
    await wait(800);
    await setPhotoFromBox(ch.photo);
    renderChallenge(ch);
    show('questions');
    focusIfDesktop($('#challenge-questions input'));
  } catch (err) {
    denied(form, err.message);
  } finally {
    setBusy(form, false);
  }
}

// ---------- page 2: photo + security questions ----------

function renderChallenge(ch) {
  state.challenge = ch;
  $('#challenge-questions').replaceChildren(...ch.questions.map((q, i) =>
    el('label', { class: 'field' }, [
      el('span', { class: 'q-text', text: q.text }),
      el('input', { name: `a${i}`, required: true, autocapitalize: 'none', spellcheck: 'false' }),
    ])));
  setMsg($('#unlock-form'), '');
}

async function onNewQuestion() {
  const form = $('#unlock-form');
  setBusy(form, true);
  try {
    let ch;
    for (let i = 0; i < 4; i++) {
      ch = await rpc('vault_challenge', { p_pin_proof: state.pinProof, p_with_photo: false });
      if (ch.error) return denied(form, wrongMessage(ch));
      if (ch.combo !== state.challenge?.combo) break;
    }
    renderChallenge(ch);
  } catch (err) {
    setMsg(form, err.message);
  } finally {
    setBusy(form, false);
    focusIfDesktop($('#challenge-questions input'));
  }
}

async function onUnlock(e) {
  e.preventDefault();
  const form = e.target;
  const ch = state.challenge;
  const answers = ch.questions.map((_, i) => form.elements[`a${i}`].value);
  if (answers.some(a => !vc.normalizeAnswer(a))) return denied(form, 'Please answer every question.');

  setBusy(form, true);
  setMsg(form, 'Checking…', true);
  try {
    const { wrapKey, authProof } = await vc.deriveFromAnswers(answers, ch.salt);
    const res = await rpc('vault_unlock', { p_combo: ch.combo, p_proof: authProof, p_pin_proof: state.pinProof });
    if (res.error) return denied(form, wrongMessage(res));
    const key = await vc.unwrapVaultKey(wrapKey, res.wrapped_key);
    setMsg(form, 'Access granted. Welcome home!', true);
    await wait(600);
    await enterVault({
      key,
      version: res.version,
      entries: await vc.decryptEntries(key, res.data),
      questions: res.questions,
      required: res.answers_required,
      hasPin: res.has_pin,
    });
    form.reset();
  } catch (err) {
    denied(form, err.message);
  } finally {
    setBusy(form, false);
  }
}

async function enterVault({ key, version, entries, questions, required, hasPin }) {
  Object.assign(state, { key, version, entries, questions, required, hasPin, proof: await vc.writeProof(key) });
  $('#search').value = '';
  $('#pin-notice').hidden = hasPin;
  renderEntries();
  show('vault');
  resetIdle();
}

// ---------- security team photo (encrypted with the PIN) ----------

let photoUrl = null;

function setPhoto(bytes, type) {
  if (photoUrl) URL.revokeObjectURL(photoUrl);
  state.photoBytes = bytes;
  state.photoType = type;
  photoUrl = bytes ? URL.createObjectURL(new Blob([bytes], { type })) : null;
  for (const img of [$('#team-img'), $('#photo-preview')]) {
    if (photoUrl) img.src = photoUrl; else img.removeAttribute('src');
  }
  $('#team').hidden = !photoUrl;
  $('#photo-preview').hidden = !photoUrl;
  $('#photo-label').textContent = photoUrl ? 'Replace photo' : 'Upload photo';
}

async function setPhotoFromBox(box) {
  if (!box || !state.pinKey) return setPhoto(null);
  try {
    setPhoto(await vc.decryptWithKey(state.pinKey, box), box.type);
  } catch {
    setPhoto(null);
  }
}

// Shrinks the photo and crops away any transparent border, keeping transparency.
async function preparePhoto(file) {
  const bmp = await createImageBitmap(file);
  const scale = Math.min(1, PHOTO_MAX_PX / Math.max(bmp.width, bmp.height));
  const w = Math.round(bmp.width * scale);
  const h = Math.round(bmp.height * scale);
  const src = document.createElement('canvas');
  src.width = w;
  src.height = h;
  const ctx = src.getContext('2d');
  ctx.drawImage(bmp, 0, 0, w, h);

  const { data } = ctx.getImageData(0, 0, w, h);
  let top = h, left = w, right = -1, bottom = -1;
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      if (data[(y * w + x) * 4 + 3] > 8) {
        if (y < top) top = y;
        if (y > bottom) bottom = y;
        if (x < left) left = x;
        if (x > right) right = x;
      }
    }
  }
  if (right < 0) throw new Error('That image looks empty.');

  const out = document.createElement('canvas');
  out.width = right - left + 1;
  out.height = bottom - top + 1;
  out.getContext('2d').drawImage(src, left, top, out.width, out.height, 0, 0, out.width, out.height);

  const toBlob = (type, q) => new Promise(r => out.toBlob(r, type, q));
  const webp = await toBlob('image/webp', 0.85);
  return webp?.type === 'image/webp' ? webp : toBlob('image/png');
}

async function onPhotoChosen(e) {
  const file = e.target.files[0];
  e.target.value = '';
  if (!file) return;
  const msg = $('#photo-msg');
  msg.classList.add('info');
  msg.textContent = 'Encrypting photo…';
  try {
    const blob = await preparePhoto(file);
    const bytes = new Uint8Array(await blob.arrayBuffer());
    const box = await vc.encryptWithKey(state.pinKey, bytes);
    const res = await rpc('vault_set_photo', { p_proof: state.proof, p_photo: { ...box, type: blob.type } });
    if (res.error) throw new Error('not allowed. Lock and unlock again.');
    setPhoto(bytes, blob.type);
    msg.textContent = 'Photo saved. Only people with the PIN can see it.';
  } catch (err) {
    msg.classList.remove('info');
    msg.textContent = `Couldn't save the photo: ${err.message}`;
  }
}

// ---------- settings: PIN, photo, questions ----------

function openSecurity() {
  const form = $('#pin-set-form');
  form.reset();
  setMsg(form, '');
  $('#pin-status').textContent = state.hasPin
    ? 'A PIN is set. Type a new one here to change it.'
    : 'No PIN yet. Until you set one, the security questions are open to anyone with the link.';
  $('#photo-input').disabled = !state.hasPin;
  $('#photo-msg').classList.add('info');
  $('#photo-msg').textContent = state.hasPin ? '' : 'Set a PIN first. The photo is encrypted with it.';
  show('security');
}

async function onPinSet(e) {
  e.preventDefault();
  const form = e.target;
  const pin = form.elements.pin.value.trim();
  if (!validPin(pin)) return setMsg(form, 'The PIN must be 4 to 8 digits.');
  if (pin !== form.elements.pin2.value.trim()) return setMsg(form, 'The two PINs don\'t match.');

  setBusy(form, true);
  setMsg(form, 'Saving…', true);
  try {
    const salt = vc.newSalt();
    const { wrapKey, authProof } = await vc.derivePinKeys(pin, salt);
    // The photo is encrypted with the PIN, so re-encrypt it with the new one.
    const photo = state.photoBytes
      ? { ...(await vc.encryptWithKey(wrapKey, state.photoBytes)), type: state.photoType }
      : null;
    const res = await rpc('vault_set_pin', {
      p_proof: state.proof, p_pin_salt: salt, p_pin_hash: await vc.sha256Hex(authProof), p_photo: photo,
    });
    if (res.error) throw new Error('Not allowed. Lock and unlock again.');
    Object.assign(state, { pinKey: wrapKey, pinProof: authProof, hasPin: true });
    $('#pin-notice').hidden = true;
    openSecurity();
    setMsg(form, 'PIN saved. Everyone will need it from now on.', true);
  } catch (err) {
    setMsg(form, err.message);
  } finally {
    setBusy(form, false);
  }
}

// ---------- question forms (setup + settings) ----------

function renderQaForm(form, questions, required) {
  $('.qa-list', form).replaceChildren(...questions.map((q, i) =>
    el('div', { class: 'qa' }, [
      el('span', { class: 'qa-num', text: `${i + 1}` }),
      el('input', { name: `q${i}`, value: q, required: true, placeholder: 'Question', 'aria-label': `Question ${i + 1}` }),
      el('input', { name: `a${i}`, required: true, placeholder: 'Answer', 'aria-label': `Answer ${i + 1}`, autocapitalize: 'none', spellcheck: 'false' }),
    ])));
  form.elements.answersRequired.value = String(required);
  setMsg(form, '');
}

function readQaForm(form) {
  const questions = [];
  const answers = [];
  for (let i = 0; i < QUESTION_COUNT; i++) {
    const q = form.elements[`q${i}`].value.trim();
    const a = form.elements[`a${i}`].value;
    if (!q) return { error: `Question ${i + 1} is empty.` };
    if (!vc.normalizeAnswer(a)) return { error: `Please answer question ${i + 1}.` };
    questions.push(q);
    answers.push(a);
  }
  if (new Set(questions.map(q => q.toLowerCase())).size !== questions.length) {
    return { error: 'Each question must be different.' };
  }
  return { questions, answers, required: Number(form.elements.answersRequired.value) };
}

const progress = form => (done, total) => setMsg(form, `Securing your vault… ${done} of ${total}`, true);

async function onSetup(e) {
  e.preventDefault();
  const form = e.target;
  const pin = form.elements.pin.value.trim();
  if (!validPin(pin)) return setMsg(form, 'The family PIN must be 4 to 8 digits.');
  if (pin !== form.elements.pin2.value.trim()) return setMsg(form, 'The two PINs don\'t match.');
  const parsed = readQaForm(form);
  if (parsed.error) return setMsg(form, parsed.error);

  setBusy(form, true);
  try {
    const pinSalt = vc.newSalt();
    const { wrapKey: pinKey, authProof: pinProof } = await vc.derivePinKeys(pin, pinSalt);
    const key = vc.newVaultKey();
    const slots = await vc.buildKeySlots(key, parsed.answers, parsed.required, progress(form));
    const res = await rpc('vault_setup', {
      p_questions: parsed.questions,
      p_answers_required: parsed.required,
      p_data: await vc.encryptEntries(key, []),
      p_write_hash: await vc.sha256Hex(await vc.writeProof(key)),
      p_slots: slots,
      p_pin_salt: pinSalt,
      p_pin_hash: await vc.sha256Hex(pinProof),
    });
    if (res.error === 'exists') throw new Error('A vault already exists. Reload the page to unlock it.');
    if (res.error) throw new Error(res.error);
    Object.assign(state, { pinKey, pinProof });
    await enterVault({
      key, version: res.version, entries: [], questions: parsed.questions, required: parsed.required, hasPin: true,
    });
    toast('Vault created');
  } catch (err) {
    setMsg(form, err.message);
  } finally {
    setBusy(form, false);
  }
}

function openSettings() {
  renderQaForm($('#settings-form'), state.questions, state.required);
  show('settings');
}

async function onSettings(e) {
  e.preventDefault();
  const form = e.target;
  const parsed = readQaForm(form);
  if (parsed.error) return setMsg(form, parsed.error);

  setBusy(form, true);
  try {
    const slots = await vc.buildKeySlots(state.key, parsed.answers, parsed.required, progress(form));
    await save(list => list, {
      p_questions: parsed.questions,
      p_answers_required: parsed.required,
      p_slots: slots,
    });
    state.questions = parsed.questions;
    state.required = parsed.required;
    show('security');
    toast('Security questions updated');
  } catch (err) {
    setMsg(form, err.message);
  } finally {
    setBusy(form, false);
  }
}

// ---------- saving ----------

async function refresh() {
  const res = await rpc('vault_fetch', { p_proof: state.proof });
  if (res.error) throw new Error('Your session has expired. Lock and unlock again.');
  state.entries = await vc.decryptEntries(state.key, res.data);
  state.version = res.version;
  state.questions = res.questions;
  state.required = res.answers_required;
}

// Applies `change` to the latest list and saves it. If another family member
// saved in the meantime, reloads their version and applies the change again.
async function save(change, extra = {}) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const next = change(structuredClone(state.entries));
    const res = await rpc('vault_save', {
      p_proof: state.proof,
      p_version: state.version,
      p_data: await vc.encryptEntries(state.key, next),
      ...extra,
    });
    if (!res.error) {
      state.entries = next;
      state.version = res.version;
      renderEntries();
      return;
    }
    if (res.error !== 'conflict') {
      throw new Error(res.error === 'denied' ? 'Not allowed. Lock and unlock again.' : `Save failed: ${res.error}`);
    }
    await refresh();
  }
  throw new Error('Someone else is editing right now. Please try again.');
}

// ---------- entries ----------

function avatarColor(service) {
  const s = service.toLowerCase().replace(/[^a-z]/g, '');
  for (const [name, color] of Object.entries(BRAND_COLORS)) if (s.includes(name)) return color;
  let h = 0;
  for (const c of s) h = (h * 31 + c.charCodeAt(0)) % 360;
  return `hsl(${h} 55% 45%)`;
}

function safeLink(url) {
  try {
    const u = new URL(/^https?:\/\//i.test(url) ? url : `https://${url}`);
    return el('a', { href: u.href, target: '_blank', rel: 'noopener noreferrer', text: u.hostname.replace(/^www\./, '') });
  } catch {
    return el('span', { class: 'value', text: url });
  }
}

async function copy(text, what) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`${what} copied`);
  } catch {
    toast('Couldn\'t copy — select and copy it manually');
  }
}

const copyBtn = (text, what) =>
  el('button', { type: 'button', class: 'small-btn', text: 'Copy', onclick: () => copy(text, what) });

function entryCard(e) {
  const avatar = el('div', { class: 'avatar', text: (e.service.trim()[0] || '?').toUpperCase(), 'aria-hidden': 'true' });
  avatar.style.background = avatarColor(e.service);

  const rows = [];
  if (e.username) {
    rows.push(el('div', { class: 'kv' }, [
      el('span', { class: 'label', text: 'Login' }),
      el('span', { class: 'value', text: e.username }),
      el('div', { class: 'btns' }, copyBtn(e.username, 'Login')),
    ]));
  }
  if (e.password) {
    const MASK = '••••••••';
    const value = el('span', { class: 'value masked', text: MASK });
    const toggle = el('button', {
      type: 'button', class: 'small-btn', text: 'Show',
      onclick: () => {
        const showing = value.classList.toggle('masked');
        value.textContent = showing ? MASK : e.password;
        toggle.textContent = showing ? 'Show' : 'Hide';
      },
    });
    rows.push(el('div', { class: 'kv' }, [
      el('span', { class: 'label', text: 'Password' }),
      value,
      el('div', { class: 'btns' }, [toggle, copyBtn(e.password, 'Password')]),
    ]));
  }
  if (e.url) {
    rows.push(el('div', { class: 'kv' }, [
      el('span', { class: 'label', text: 'Website' }),
      safeLink(e.url),
      el('span'),
    ]));
  }
  if (e.notes) rows.push(el('p', { class: 'notes', text: e.notes }));

  return el('article', { class: 'entry' }, [
    el('header', {}, [
      avatar,
      el('div', { class: 'title' }, [
        el('h3', { text: e.service }),
        e.profile && el('div', { class: 'muted small', text: e.profile }),
      ]),
      el('button', { type: 'button', class: 'small-btn', text: 'Edit', onclick: () => openEntry(e) }),
    ]),
    ...rows,
  ]);
}

function renderEntries() {
  const q = $('#search').value.trim().toLowerCase();
  const list = state.entries
    .filter(e => !q || ['service', 'profile', 'username', 'notes'].some(k => (e[k] || '').toLowerCase().includes(q)))
    .sort((a, b) => a.service.localeCompare(b.service, undefined, { sensitivity: 'base' }));

  $('#entries').replaceChildren(...list.map(entryCard));
  const empty = $('#empty');
  empty.hidden = list.length > 0;
  empty.textContent = state.entries.length
    ? 'Nothing matches your search.'
    : 'No logins saved yet. Click “+ Add” to store your first streaming service.';
}

function openEntry(entry) {
  const form = $('#entry-form');
  editingId = entry?.id ?? null;
  for (const k of FIELDS) form.elements[k].value = entry?.[k] ?? '';
  $('#entry-title').textContent = entry ? `Edit ${entry.service}` : 'Add a service';
  $('#entry-delete').hidden = !entry;
  setMsg(form, '');
  $('#entry-dialog').showModal();
}

async function onEntrySubmit(e) {
  e.preventDefault();
  const form = e.target;
  const entry = { id: editingId ?? crypto.randomUUID(), updated: new Date().toISOString() };
  for (const k of FIELDS) entry[k] = form.elements[k].value.trim();
  if (!entry.service) return setMsg(form, 'Please enter the service name.');

  setBusy(form, true);
  setMsg(form, 'Saving…', true);
  try {
    await save(list => {
      const i = list.findIndex(x => x.id === entry.id);
      if (i >= 0) list[i] = entry; else list.push(entry);
      return list;
    });
    $('#entry-dialog').close();
    toast('Saved');
  } catch (err) {
    setMsg(form, err.message);
  } finally {
    setBusy(form, false);
  }
}

async function onEntryDelete() {
  const form = $('#entry-form');
  const name = form.elements.service.value || 'this service';
  if (!confirm(`Delete ${name}? This can't be undone.`)) return;
  const id = editingId;
  setBusy(form, true);
  try {
    await save(list => list.filter(x => x.id !== id));
    $('#entry-dialog').close();
    toast('Deleted');
  } catch (err) {
    setMsg(form, err.message);
  } finally {
    setBusy(form, false);
  }
}

// ---------- auto-lock ----------

let idleTimer;
function resetIdle() {
  clearTimeout(idleTimer);
  if (!state.key) return;
  idleTimer = setTimeout(() => {
    start();
    toast('Locked after 10 minutes of inactivity');
  }, IDLE_LOCK_MS);
}
for (const ev of ['pointerdown', 'keydown', 'scroll', 'touchstart']) {
  addEventListener(ev, resetIdle, { passive: true });
}

// ---------- wiring ----------

$('#unlock-form').addEventListener('submit', onUnlock);
$('#new-question').addEventListener('click', onNewQuestion);
$('#setup-form').addEventListener('submit', onSetup);
$('#settings-form').addEventListener('submit', onSettings);
$('#settings-cancel').addEventListener('click', () => show('security'));
$('#add-btn').addEventListener('click', () => openEntry(null));
$('#settings-btn').addEventListener('click', openSecurity);
$('#pin-notice-btn').addEventListener('click', openSecurity);
$('#security-back').addEventListener('click', () => show('vault'));
$('#questions-btn').addEventListener('click', openSettings);
$('#pin-set-form').addEventListener('submit', onPinSet);
$('#pin-form').addEventListener('submit', onPin);
$('#lock-btn').addEventListener('click', () => { clearTimeout(idleTimer); start(); });
$('#search').addEventListener('input', renderEntries);
$('#entry-form').addEventListener('submit', onEntrySubmit);
$('#entry-cancel').addEventListener('click', () => $('#entry-dialog').close());
$('#entry-delete').addEventListener('click', onEntryDelete);
$('#retry').addEventListener('click', start);
$('#photo-input').addEventListener('change', onPhotoChosen);

start();
