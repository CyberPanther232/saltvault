// Background service worker for SaltVault Chrome MV3 extension
// Bridges popup/content scripts to SaltVault backend endpoints.

const DEFAULT_BASE_URL = 'http://localhost:5000';

async function getBaseUrl() {
  const { baseUrl } = await chrome.storage.sync.get(['baseUrl']);
  return baseUrl || DEFAULT_BASE_URL;
}

async function fetchWithCred(path, options = {}) {
  const base = await getBaseUrl();
  const url = `${base}${path}`;
  const resp = await fetch(url, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  return resp;
}

async function postJson(path, payload) {
	const base = await getBaseUrl();
	const res = await fetch(`${base}${path}`, {
		method: 'POST',
		credentials: 'include',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(payload || {})
	});
	return res.json();
}

// Login to SaltVault using master password (assumes form-based auth at /login)
async function loginMasterPassword({ username, password, totp, backup_code }) {
  const base = await getBaseUrl();
  const payload = { username: username || 'admin', password, totp: totp || '', backup_code: backup_code || '' };
  const resp = await fetch(`${base}/api/login`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) return { ok: false, status: resp.status, error: 'Login failed' };
  // After login, session cookie is set. Return success.
  return { ok: true };
}

// List passwords (optionally filtered by domain)
async function listPasswords({ domain } = {}) {
  const resp = await fetchWithCred('/api/passwords/list', { method: 'GET' });
  if (resp.ok) {
    const data = await resp.json();
    const items = Array.isArray(data) ? data : data.items || [];
    return { ok: true, items: domain ? items.filter(i => (i.url || '').includes(domain)) : items };
  }
  // Fallback to HTML list by scraping minimal data
  const htmlResp = await fetchWithCred('/', { method: 'GET', headers: { 'Accept': 'text/html' } });
  if (!htmlResp.ok) return { ok: false, status: htmlResp.status, error: 'Unable to fetch list' };
  const html = await htmlResp.text();
  const items = scrapePasswordsFromIndexHtml(html);
  return { ok: true, items: domain ? items.filter(i => (i.url || '').includes(domain)) : items };
}

// Get single password by id
async function getPassword({ id }) {
  const resp = await fetchWithCred(`/api/view-password/${id}`, { method: 'GET' });
  if (!resp.ok) return { ok: false, status: resp.status, error: 'Fetch failed' };
  const data = await resp.json();
  return { ok: true, item: data };
}

// Add password entry
async function addPassword({ title, username, password, email, url, notes }) {
  const resp = await fetchWithCred('/api/add-password', {
    method: 'POST',
    body: JSON.stringify({ title, username, password, email, url, notes }),
  });
  if (resp.ok) {
    const data = await resp.json().catch(() => ({}));
    return { ok: true, item: data };
  }
  return { ok: resp.ok, error: `Failed with status: ${resp.status}` };
}

// Helper: scrape minimal info from index HTML when JSON not available
function scrapePasswordsFromIndexHtml(html) {
  const items = [];
  const rowRegex = /data-id\s*=\s*"(\d+)"[\s\S]*?<td[^>]*>(.*?)<\/td>[\s\S]*?<td[^>]*>(.*?)<\/td>[\s\S]*?<td[^>]*>(.*?)<\/td>/g;
  let m;
  while ((m = rowRegex.exec(html)) !== null) {
    items.push({ id: m[1], title: m[2], username: m[3], url: m[4] });
  }
  return items;
}

// Autofill: find best match for a given domain
async function findCredentialsForDomain({ domain }) {
  const { ok, items } = await listPasswords({ domain });
  if (!ok) return { ok: false, error: 'List failed' };
  const match = items.find(i => (i.url || '').includes(domain)) || items[0];
  if (!match) return { ok: false, error: 'No entries' };
  const det = await getPassword({ id: match.id });
  return det.ok ? { ok: true, item: det.item } : det;
}

// Edit password entry

async function editPassword({ id, title, username, password, email, url, notes }) {

  const resp = await fetchWithCred(`/api/edit-password/${id}`, {

    method: 'POST',

    body: JSON.stringify({ title, username, password, email, url, notes }),

  });

  if (resp.ok) {

    const data = await resp.json().catch(() => ({}));

    return { ok: true, item: data };

  }

  return { ok: resp.ok };

}



// Message router

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  console.log(msg);

  (async () => {

    try {

      switch (msg.type) {

        case 'setBaseUrl': {

          await chrome.storage.sync.set({ baseUrl: msg.baseUrl });

          sendResponse({ ok: true });

          break;

        }

        case 'loginMaster': {

          const res = await loginMasterPassword({ username: msg.username, password: msg.password, totp: msg.totp });

          sendResponse(res);

          break;

        }

        case 'listPasswords': {

          const res = await listPasswords({ domain: msg.domain });

          sendResponse(res);

          break;

        }

        case 'getPassword': {

          const res = await getPassword({ id: msg.id });

          sendResponse(res);

          break;

        }

        case 'addPassword': {

          const res = await addPassword(msg.payload || {});

          sendResponse(res);

          break;

        }

        case 'editPassword': {

          const res = await editPassword(msg.payload || {});

          sendResponse(res);

          break;

        }

        case 'findCredsForDomain': {

          const res = await findCredentialsForDomain({ domain: msg.domain });

          sendResponse(res);

          break;

        }
        case 'generate': {
            const data = await postJson('/generate-password', msg.payload);
            sendResponse({ ok: true, data });
            break;
        }
        case 'strengthen': {
            const data = await postJson('/strengthen-password', msg.payload);
            sendResponse({ ok: true, data });
            break;
        }
        case 'autofill': {
            // Forward to content script
            if (sender.tab && sender.tab.id) {
                await chrome.tabs.sendMessage(sender.tab.id, { type: 'autofill', data: msg.payload });
                sendResponse({ ok: true });
            } else {
                // Try active tab
                const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
                if (tab) {
                    await chrome.tabs.sendMessage(tab.id, { type: 'autofill', data: msg.payload });
                    sendResponse({ ok: true });
                } else sendResponse({ ok: false, error: 'No active tab' });
            }
            break;
        }
        default:
          sendResponse({ ok: false, error: 'Unknown message type' });
      }
    } catch (e) {
      sendResponse({ ok: false, error: String(e) });
    }
  })();
  return true; // keep port open for async
});

// Optional: context menu to save current page credentials (placeholder)
