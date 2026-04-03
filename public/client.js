/**
 * client.js — Central Alberta After Dark
 *
 * Handles CSRF token fetching and attaches it to all state-changing fetch
 * requests so the server's csurf middleware accepts them.
 */

let _csrfToken = null;

/**
 * Fetch (and cache) the CSRF token from the server.
 * Call this before any POST/PUT/DELETE request.
 */
async function getCsrfToken() {
  if (_csrfToken) return _csrfToken;
  try {
    const res = await fetch('/api/csrf-token');
    if (!res.ok) throw new Error('Failed to fetch CSRF token');
    const data = await res.json();
    _csrfToken = data.csrfToken;
    return _csrfToken;
  } catch (err) {
    console.error('CSRF token fetch error:', err);
    return null;
  }
}

/**
 * Wrapper around fetch that automatically injects the CSRF token header
 * for state-changing methods (POST, PUT, DELETE, PATCH).
 */
async function secureFetch(url, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const mutating = ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method);

  if (mutating) {
    const token = await getCsrfToken();
    options.headers = {
      ...(options.headers || {}),
      'X-CSRF-Token': token,
    };
  }

  return fetch(url, options);
}

document.addEventListener('DOMContentLoaded', async () => {
  // On the success page, populate the hidden session_id field for the
  // billing portal form (customer ID lookup happens server-side).
  const sessionIdEl = document.getElementById('session-id');
  if (sessionIdEl) {
    const searchParams = new URLSearchParams(window.location.search);
    if (searchParams.has('session_id')) {
      sessionIdEl.setAttribute('value', searchParams.get('session_id'));
    }
  }

  // Show a toast if the user just verified their email
  const params = new URLSearchParams(window.location.search);
  if (params.get('verified') === '1') {
    const toast = document.getElementById('toast');
    if (toast) {
      toast.textContent = '✅ Email verified! You can now log in.';
      toast.style.display = 'block';
      setTimeout(() => { toast.style.display = 'none'; }, 5000);
    }
    // Clean the URL
    history.replaceState(null, '', '/');
  }
});
