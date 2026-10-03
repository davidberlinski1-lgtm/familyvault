import { SUPABASE_URL, SUPABASE_KEY } from './config.js?v=20261003b';

export const isConfigured = () => !SUPABASE_URL.includes('YOUR-PROJECT') && !SUPABASE_KEY.startsWith('YOUR-');

export async function rpc(fn, args = {}) {
  const headers = { apikey: SUPABASE_KEY, 'Content-Type': 'application/json' };
  // Legacy anon keys are JWTs and also go in the Authorization header.
  if (SUPABASE_KEY.startsWith('eyJ')) headers.Authorization = `Bearer ${SUPABASE_KEY}`;

  let res;
  try {
    res = await fetch(`${SUPABASE_URL}/rest/v1/rpc/${fn}`, {
      method: 'POST',
      headers,
      body: JSON.stringify(args),
    });
  } catch {
    throw new Error('Could not reach the vault server. Check your internet connection.');
  }
  if (!res.ok) throw new Error(`Server error (${res.status}): ${await res.text()}`);
  return res.json();
}
