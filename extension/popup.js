(function() {
  const $ = (sel) => document.querySelector(sel);
  let SESSION_DURATION = 3600 * 1000; // 1 hour in milliseconds

  function showStatus(message, type = 'info') {
    const box = $('#statusBox');
    if (!box) return;
    box.textContent = message || '';
    box.className = `alert alert-${type}`;
    box.style.display = message ? 'block' : 'none';
    if (message && type !== 'danger') {
      setTimeout(() => { if (box.textContent === message) box.style.display = 'none'; }, 4000);
    }
  }

  function updateUIMode(isLoggedIn) {
    $('#preLoginHeader').style.display = isLoggedIn ? 'none' : 'block';
    $('#loginSection').style.display = isLoggedIn ? 'none' : 'flex';
    $('#mainContent').style.display = isLoggedIn ? 'block' : 'none';
    $('#watermark').style.display = isLoggedIn ? 'block' : 'none';
    if (!isLoggedIn) {
      $('#settingsSection').style.display = 'none';
    }
  }

  async function checkSessionState() {
    const { loginSession } = await chrome.storage.local.get(['loginSession']);
    const { sessionDuration, baseUrl } = await chrome.storage.sync.get(['sessionDuration', 'baseUrl']);

    if (sessionDuration) {
      SESSION_DURATION = sessionDuration * 60 * 1000;
    }

    if (baseUrl) {
      const el = $('#baseUrl');
      if (el) el.value = baseUrl;
      const elLogin = $('#baseUrlLogin');
      if (elLogin) elLogin.value = baseUrl;
    }

    if (loginSession && loginSession.loggedIn && (Date.now() - loginSession.timestamp < SESSION_DURATION)) {
      updateUIMode(true);
      const { baseUrl, sessionDuration } = await chrome.storage.sync.get(['baseUrl', 'sessionDuration']);
      if (baseUrl) {
        const el = $('#baseUrl');
        if (el) el.value = baseUrl;
      }
      if (sessionDuration) {
        const el = $('#sessionDuration');
        if (el) el.value = sessionDuration;
      }
    } else {
      updateUIMode(false);
    }

    // Check for autofill setting
    const { autofillSetting } = await chrome.storage.sync.get({ autofillSetting: 'ask' });
    const radio = $(`#autofill${autofillSetting.charAt(0).toUpperCase() + autofillSetting.slice(1)}`);
    if (radio) {
      radio.checked = true;
    }
  }

  function onSaveBaseUrl() {
    let baseUrl = ($('#baseUrl').value || '').trim();
    if (!baseUrl) {
      baseUrl = ($('#baseUrlLogin').value || '').trim();
    }

    if (!baseUrl) {
      showStatus('Base URL cannot be empty', 'danger');
      return;
    }
    chrome.runtime.sendMessage({ type: 'setBaseUrl', baseUrl }, (res) => {
      if (res && res.ok) {
        showStatus('Base URL saved', 'success');
        const el = $('#baseUrl');
        if (el) el.value = baseUrl;
        const elLogin = $('#baseUrlLogin');
        if (elLogin) elLogin.value = baseUrl;
      } else {
        showStatus(`Failed to save URL${res && res.error ? ': ' + res.error : ''}`, 'danger');
      }
    });
  }

  function onSaveSessionDuration() {
    const duration = parseInt($('#sessionDuration').value, 10);
    if (isNaN(duration) || duration <= 0) {
      showStatus('Invalid session duration', 'danger');
      return;
    }
    chrome.storage.sync.set({ sessionDuration: duration }, () => {
      SESSION_DURATION = duration * 60 * 1000;
      showStatus('Session duration saved', 'success');
    });
  }

  function onLogin() {
    const username = ($('#username').value || '').trim();
    const password = $('#master').value || '';
    const totp = ($('#totp').value || '').trim();
    
    const m = $('#master'); const t = $('#totp');
    if (m) m.value = '';
    if (t) t.value = '';

    chrome.runtime.sendMessage({ type: 'loginMaster', username, password, totp }, async (res) => {
      if (res && res.ok) {
        showStatus('Logged in successfully', 'success');
        const session = { loggedIn: true, timestamp: Date.now() };
        chrome.storage.local.set({ loginSession: session });
        updateUIMode(true);
        const { baseUrl, sessionDuration } = await chrome.storage.sync.get(['baseUrl', 'sessionDuration']);
        if (baseUrl) {
          const el = $('#baseUrl');
          if (el) el.value = baseUrl;
        }
        if (sessionDuration) {
          const el = $('#sessionDuration');
          if (el) el.value = sessionDuration;
        }
      } else {
        showStatus(`Login failed${res && res.error ? ': ' + res.error : ''}`, 'danger');
        updateUIMode(false);
      }
    });
  }

  function onLogout() {
    chrome.storage.local.remove('loginSession');
    chrome.storage.sync.remove(['baseUrl', 'sessionDuration']);
    showStatus('Logged out and settings cleared', 'info');
    updateUIMode(false);
  }

  function onList() {
    const domain = ($('#searchDomain').value || '').trim();
    chrome.runtime.sendMessage({ type: 'listPasswords', domain }, (res) => {
      const ul = $('#results');
      if (!ul) return;
      ul.innerHTML = '';
      if (!res || !res.ok) { 
        ul.innerHTML = '<li class="list-group-item">Failed to fetch passwords</li>'; 
        showStatus('Failed to fetch passwords', 'danger'); 
        return; 
      }
      showStatus(`Found ${(res.items || []).length} item(s)`, 'info');
      (res.items || []).forEach(i => {
        const li = document.createElement('li');
        li.className = 'list-group-item';
        li.textContent = `${i.title || '(no title)'} — ${i.username || ''}`;
        li.addEventListener('click', () => {
          chrome.runtime.sendMessage({ type: 'getPassword', id: i.id }, (det) => {
            if (det && det.ok) {
              navigator.clipboard.writeText(det.item.password).then(() => {
                showStatus('Password copied to clipboard', 'success');
              });
            } else {
              showStatus('Failed to retrieve password', 'danger');
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
      email: ($('#addEmail').value || '').trim(),
      url: ($('#addUrl').value || '').trim(),
      notes: ($('#addNotes').value || '').trim()
    };
    chrome.runtime.sendMessage({ type: 'addPassword', payload }, (res) => {
      if (res && res.ok) {
        showStatus('Password added', 'success');
        $('#addTitle').value = '';
        $('#addUsername').value = '';
        $('#addPassword').value = '';
        $('#addEmail').value = '';
        $('#addUrl').value = '';
        $('#addNotes').value = '';
      } else {
        showStatus(`Add failed${res && res.error ? ': ' + res.error : ''}`, 'danger');
      }
    });
  }

  function handleActionChange(event) {
    const selected = event.target.value;
    $('#addPasswordContainer').style.display = 'none';
    $('#editPasswordContainer').style.display = 'none';
    $('#viewPasswordsContainer').style.display = 'none';

    if (selected === 'add') {
      $('#addPasswordContainer').style.display = 'block';
    } else if (selected === 'edit') {
      $('#editPasswordContainer').style.display = 'block';
      // Placeholder text, full implementation is pending
      $('#editPasswordContainer').innerHTML = '<p class="small text-muted">Edit functionality is not yet implemented.</p>';
    } else if (selected === 'view') {
      $('#viewPasswordsContainer').style.display = 'block';
      renderViewPasswords();
    }
  }

  function renderViewPasswords() {
    const container = $('#viewPasswordsContainer');
    container.innerHTML = '<p class="small text-muted">Loading...</p>';

    chrome.runtime.sendMessage({ type: 'listPasswords' }, (res) => {
      if (!res || !res.ok || !res.items) {
        container.innerHTML = '<p class="small text-danger">Failed to load passwords.</p>';
        return;
      }
      if (res.items.length === 0) {
        container.innerHTML = '<p class="small text-muted">No passwords found.</p>';
        return;
      }

      container.innerHTML = ''; // Clear loading message
      const ul = document.createElement('ul');
      ul.className = 'list-group list-group-flush';
      
      res.items.forEach(item => {
        const li = document.createElement('li');
        li.className = 'list-group-item d-flex justify-content-between align-items-center';
        
        const titleSpan = document.createElement('span');
        titleSpan.textContent = item.title;
        li.appendChild(titleSpan);

        const btnGroup = document.createElement('div');
        const copyUserBtn = document.createElement('button');
        copyUserBtn.className = 'btn btn-outline-secondary btn-sm';
        copyUserBtn.textContent = 'Copy User';
        copyUserBtn.addEventListener('click', () => {
          navigator.clipboard.writeText(item.username).then(() => {
            showStatus(`Username for "${item.title}" copied`, 'success');
          });
        });

        const copyPassBtn = document.createElement('button');
        copyPassBtn.className = 'btn btn-outline-primary btn-sm ml-2';
        copyPassBtn.textContent = 'Copy Pass';
        copyPassBtn.addEventListener('click', () => {
          chrome.runtime.sendMessage({ type: 'getPassword', id: item.id }, (det) => {
            if (det && det.ok) {
              navigator.clipboard.writeText(det.item.password).then(() => {
                showStatus(`Password for "${item.title}" copied`, 'success');
              });
            } else {
              showStatus('Failed to retrieve password', 'danger');
            }
          });
        });

        btnGroup.appendChild(copyUserBtn);
        btnGroup.appendChild(copyPassBtn);
        li.appendChild(btnGroup);
        ul.appendChild(li);
      });
      container.appendChild(ul);
    });
  }
  
  function handleAutofillSettingChange(event) {
    const setting = event.target.value;
    chrome.storage.sync.set({ autofillSetting: setting });
    showStatus(`Autofill setting saved: ${setting}`, 'success');
  }

  function onAutofill() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0] && tabs[0].url) {
        const domain = new URL(tabs[0].url).hostname;
        chrome.runtime.sendMessage({ type: 'findCredsForDomain', domain }, (res) => {
          if (res && res.ok) {
            chrome.tabs.sendMessage(tabs[0].id, { type: 'autofill', creds: res.item });
          } else {
            showStatus(`No credentials found for ${domain}`, 'danger');
          }
        });
      }
    });
  }

  function toggleSettings() {
    const settingsSection = $('#settingsSection');
    settingsSection.style.display = settingsSection.style.display === 'none' ? 'block' : 'none';
  }

  function bindEvents() {
    $('#saveBaseUrl')?.addEventListener('click', onSaveBaseUrl);
    $('#saveBaseUrlLogin')?.addEventListener('click', onSaveBaseUrl);
    $('#saveSessionDuration')?.addEventListener('click', onSaveSessionDuration);
    $('#loginBtn')?.addEventListener('click', onLogin);
    $('#logoutBtn')?.addEventListener('click', onLogout);
    $('#settingsBtn')?.addEventListener('click', toggleSettings);
    $('#listBtn')?.addEventListener('click', onList);
    $('#addBtn')?.addEventListener('click', onAdd);
    $('#actionSelector')?.addEventListener('change', handleActionChange);
    $('#autofillBtn')?.addEventListener('click', onAutofill);
    document.querySelectorAll('input[name="autofillSetting"]').forEach(radio => {
      radio.addEventListener('change', handleAutofillSettingChange);
    });
  }

  function init() {
    checkSessionState();
    bindEvents();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();