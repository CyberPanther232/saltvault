// Content script: detect login forms and request autofill from background

function detectLoginFields() {
  const inputs = Array.from(document.querySelectorAll('input'));
  let userField = null;
  let passField = null;
  for (const input of inputs) {
    const name = (input.name || '').toLowerCase();
    const id = (input.id || '').toLowerCase();
    const type = (input.type || '').toLowerCase();
    const placeholder = (input.placeholder || '').toLowerCase();
    if (!passField && type === 'password') passField = input;
    const hint = `${name} ${id} ${placeholder}`;
    if (!userField && (hint.includes('user') || hint.includes('email') || hint.includes('login') || type === 'email' || type === 'text')) {
      userField = input;
    }
  }
  return { userField, passField };
}

async function autofillForCurrentSite() {
  const { userField, passField } = detectLoginFields();
  if (!passField) return;
  const domain = location.hostname;
  chrome.runtime.sendMessage({ type: 'findCredsForDomain', domain }, (res) => {
    if (!res || !res.ok) return;
    const { item } = res;
    if (userField && item && item.username) userField.value = item.username;
    if (passField && item && item.password) passField.value = item.password;
  });
}

// Attempt autofill on DOM ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', autofillForCurrentSite);
} else {
  autofillForCurrentSite();
}
// Detect common login fields and provide autofill
function findLoginFields() {
	const password = document.querySelector('input[type="password"]');
	// Heuristics for username/email fields
	const username = document.querySelector('input[name*="user" i], input[id*="user" i], input[name*="login" i], input[id*="login" i]');
	const email = document.querySelector('input[type="email"], input[name*="email" i], input[id*="email" i]');
	return { username: username || email, password };
}

function autofill({ username, password }) {
	const fields = findLoginFields();
	if (fields.username && typeof username === 'string') { fields.username.value = username; }
	if (fields.password && typeof password === 'string') { fields.password.value = password; }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
	if (msg.type === 'autofill') {
		autofill(msg.data || {});
		sendResponse({ ok: true });
	}
});

// Expose quick scrape for popup (optional)
function scrape() {
	const fields = findLoginFields();
	return {
		title: document.title,
		username: fields.username ? fields.username.value : '',
		password: fields.password ? fields.password.value : ''
	};
}
console.log('This is a popup!');