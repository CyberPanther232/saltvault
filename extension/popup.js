(function() {
  const $ = (sel) => document.querySelector(sel);

  function initBaseUrl() {
    chrome.storage.sync.get(['baseUrl'], ({ baseUrl }) => {
      const el = $('#baseUrl');
      if (el) el.value = baseUrl || 'http://localhost:5000';
    });
  }

  function onSaveBaseUrl() {
    const baseUrl = ($('#baseUrl').value || '').trim();
    chrome.runtime.sendMessage({ type: 'setBaseUrl', baseUrl }, (res) => {
      console.log(res && res.ok ? 'Base URL saved' : 'Failed to save URL');
    });
  }

  function onLogin() {
    const username = ($('#username').value || '').trim();
    const password = $('#master').value || '';
    const totp = ($('#totp').value || '').trim();
    chrome.runtime.sendMessage({ type: 'loginMaster', username, password, totp }, (res) => {
      console.log(res && res.ok ? 'Logged in' : `Login failed: ${res && res.error}`);
    });
  }

  function onList() {
    const domain = ($('#searchDomain').value || '').trim();
    chrome.runtime.sendMessage({ type: 'listPasswords', domain }, (res) => {
      const ul = $('#results');
      if (!ul) return;
      ul.innerHTML = '';
      if (!res || !res.ok) { ul.innerHTML = '<li class="list-group-item">Failed to fetch</li>'; return; }
      (res.items || []).forEach(i => {
        const li = document.createElement('li');
        li.className = 'list-group-item';
        li.textContent = `${i.title || '(no title)'} — ${i.username || ''} — ${i.url || ''}`;
        li.addEventListener('click', () => {
          chrome.runtime.sendMessage({ type: 'getPassword', id: i.id }, (det) => {
            if (det && det.ok) {
              alert(`Username: ${det.item.username}\nPassword: ${det.item.password}`);
            }
          });
        });
        ul.appendChild(li);
      });
    });
  }

  function onAdd() {
    const payload = {
      title: ($('#addTitle').value || '').trim(),
      username: ($('#addUsername').value || '').trim(),
      password: $('#addPassword').value || '',
      url: ($('#addUrl').value || '').trim(),
      notes: ($('#addNotes').value || '').trim()
    };
    chrome.runtime.sendMessage({ type: 'addPassword', payload }, (res) => {
      console.log(res && res.ok ? 'Added' : `Add failed: ${res && res.error}`);
    });
  }

  function onAutofill() {
    const domain = new URL(window.location.href).hostname;
    chrome.runtime.sendMessage({ type: 'findCredsForDomain', domain }, (res) => {
      console.log(res && res.ok ? 'Autofill data ready' : `Autofill failed: ${res && res.error}`);
    });
  }

  function bindEvents() {
    const saveBtn = $('#saveBaseUrl');
    const loginBtn = $('#loginBtn');
    const listBtn = $('#listBtn');
    const addBtn = $('#addBtn');
    const autofillBtn = $('#autofillBtn');

    if (saveBtn) saveBtn.addEventListener('click', onSaveBaseUrl);
    if (loginBtn) loginBtn.addEventListener('click', onLogin);
    if (listBtn) listBtn.addEventListener('click', onList);
    if (addBtn) addBtn.addEventListener('click', onAdd);
    if (autofillBtn) autofillBtn.addEventListener('click', onAutofill);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => { initBaseUrl(); bindEvents(); });
  } else {
    initBaseUrl();
    bindEvents();
  }
})();
