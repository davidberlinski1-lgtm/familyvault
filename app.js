import { rpc, isConfigured } from './api.js';
import * as vc from './crypto.js';

const QUESTION_COUNT = 10;
const IDLE_LOCK_MS = 10 * 60 * 1000;
const FIELDS = ['service', 'profile', 'username', 'password', 'url', 'notes'];

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

// ---------- start / unlock ----------

async function start() {
  state.key = null;
  state.proof = null;
  state.entries = [];
  $('#entries').replaceChildren();
  if ($('#entry-dialog').open) $('#entry-dialog').close();

  if (!isConfigured()) {
    showError('This site isn\'t connected yet. Add your Supabase URL and key to config.js, then reload.');
    return;
  }
  show('loading');
  try {
    const ch = await rpc('vault_challenge');
    if (!ch.setup) {
      renderQaForm($('#setup-form'), DEFAULT_QUESTIONS, 1);
      show('setup');
      return;
    }
    renderChallenge(ch);
    show('unlock');
    $('#challenge-questions input')?.focus();
  } catch (err) {
    showError(err.message);
  }
}

function renderChallenge(ch) {
  state.challenge = ch;
  $('#challenge-questions').replaceChildren(...ch.questions.map((q, i) =>
    el('label', { class: 'field' }, [
      el('span', { class: 'q-text', text: q.text }),
      el('input', { name: `a${i}`, required: true, autocapitalize: 'none', spellcheck: 'false' }),
    ])));
  setMsg($('#unlock-form'), '');
  $('.dial-wrap').classList.remove('open');
  $('.gate-panel').classList.remove('denied');
}

function denied(form, text) {
  setMsg(form, text);
  const panel = $('.gate-panel');
  panel.classList.remove('denied');
  void panel.offsetWidth; // restart the shake animation
  panel.classList.add('denied');
}

async function onNewQuestion() {
  const form = $('#unlock-form');
  setBusy(form, true);
  try {
    let ch;
    for (let i = 0; i < 4; i++) {
      ch = await rpc('vault_challenge');
      if (ch.combo !== state.challenge?.combo) break;
    }
    renderChallenge(ch);
  } catch (err) {
    setMsg(form, err.message);
  } finally {
    setBusy(form, false);
    $('#challenge-questions input')?.focus();
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
    const res = await rpc('vault_unlock', { p_combo: ch.combo, p_proof: authProof });
    if (res.error === 'locked') {
      return denied(form, 'Too many wrong answers. The vault is locked for 15 minutes.');
    }
    if (res.error === 'wrong') {
      return denied(form, res.remaining > 0
        ? `Access denied. ${res.remaining} more wrong ${res.remaining === 1 ? 'try' : 'tries'} and the vault locks for 15 minutes.`
        : 'Access denied. The vault is now locked for 15 minutes.');
    }
    const key = await vc.unwrapVaultKey(wrapKey, res.wrapped_key);
    setMsg(form, 'Access granted. Welcome home!', true);
    $('.dial-wrap').classList.add('open');
    await new Promise(r => setTimeout(r, 850));
    await enterVault({
      key,
      version: res.version,
      entries: await vc.decryptEntries(key, res.data),
      questions: res.questions,
      required: res.answers_required,
    });
    form.reset();
  } catch (err) {
    denied(form, err.message);
  } finally {
    setBusy(form, false);
  }
}

async function enterVault({ key, version, entries, questions, required }) {
  Object.assign(state, { key, version, entries, questions, required, proof: await vc.writeProof(key) });
  $('#search').value = '';
  renderEntries();
  show('vault');
  resetIdle();
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
  const parsed = readQaForm(form);
  if (parsed.error) return setMsg(form, parsed.error);

  setBusy(form, true);
  try {
    const key = vc.newVaultKey();
    const slots = await vc.buildKeySlots(key, parsed.answers, parsed.required, progress(form));
    const res = await rpc('vault_setup', {
      p_questions: parsed.questions,
      p_answers_required: parsed.required,
      p_data: await vc.encryptEntries(key, []),
      p_write_hash: await vc.sha256Hex(await vc.writeProof(key)),
      p_slots: slots,
    });
    if (res.error === 'exists') throw new Error('A vault already exists. Reload the page to unlock it.');
    if (res.error) throw new Error(res.error);
    await enterVault({ key, version: res.version, entries: [], questions: parsed.questions, required: parsed.required });
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
    show('vault');
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
$('#settings-cancel').addEventListener('click', () => show('vault'));
$('#add-btn').addEventListener('click', () => openEntry(null));
$('#settings-btn').addEventListener('click', openSettings);
$('#lock-btn').addEventListener('click', () => { clearTimeout(idleTimer); start(); });
$('#search').addEventListener('input', renderEntries);
$('#entry-form').addEventListener('submit', onEntrySubmit);
$('#entry-cancel').addEventListener('click', () => $('#entry-dialog').close());
$('#entry-delete').addEventListener('click', onEntryDelete);
$('#retry').addEventListener('click', start);

start();
