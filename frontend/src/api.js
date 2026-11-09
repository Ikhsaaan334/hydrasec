const TOKEN_KEY = 'hydrasec_token';

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

export async function api(path, { method = 'GET', body, token } = {}) {
  const authToken = token ?? getToken();
  const res = await fetch('/api' + path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(authToken ? { Authorization: 'Bearer ' + authToken } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  if (res.status === 401) {
    clearToken();
    if (!window.location.pathname.startsWith('/login')) {
      window.location.assign('/login');
    }
    throw new Error('Session expired — please sign in again');
  }

  let data = {};
  try { data = await res.json(); } catch { /* body bukan JSON */ }
  if (!res.ok) {
    throw new Error(data?.error || 'Request failed (' + res.status + ')');
  }
  return data;
}
