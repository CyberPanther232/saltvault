// Content script for SaltVault Extension

(function() {
  const AUTOFILL_BAR_ID = 'saltvault-autofill-bar';

  /**
   * Finds the most likely username/email and password fields on the page.
   * @returns {{usernameField: HTMLInputElement, passwordField: HTMLInputElement}}
   */
  function findLoginFields() {
    let passwordField = document.querySelector('input[type="password"]');
    if (!passwordField) return { usernameField: null, passwordField: null };

    let usernameField = null;
    const inputs = Array.from(document.querySelectorAll('input[type="text"], input[type="email"]'));
    let minDistance = Infinity;
    
    inputs.forEach(input => {
      const rect1 = input.getBoundingClientRect();
      const rect2 = passwordField.getBoundingClientRect();
      const distance = Math.sqrt(Math.pow(rect1.x - rect2.x, 2) + Math.pow(rect1.y - rect2.y, 2));
      
      const name = (input.name || '').toLowerCase();
      const id = (input.id || '').toLowerCase();
      const placeholder = (input.placeholder || '').toLowerCase();
      const hint = `${name} ${id} ${placeholder}`;

      if ((hint.includes('user') || hint.includes('email') || hint.includes('login')) && distance < minDistance) {
        minDistance = distance;
        usernameField = input;
      }
    });

    if (!usernameField) {
      usernameField = document.querySelector('input[type="email"], input[name*="user" i], input[id*="user" i], input[name*="login" i], input[id*="login" i]');
    }

    return { usernameField, passwordField };
  }

  /**
   * Fills the provided credentials into the login fields.
   * @param {{username: string, password: string}} creds 
   */
  function doAutofill(creds) {
    if (!creds) return;
    const { usernameField, passwordField } = findLoginFields();

    if (usernameField && creds.username) {
      usernameField.value = creds.username;
    }
    if (passwordField && creds.password) {
      passwordField.value = creds.password;
    }
  }

  /**
   * Creates and injects the "Ask to Autofill" bar into the page.
   * @param {object} creds The credentials to be filled.
   */
  function createAutofillBar(creds) {
    if (document.getElementById(AUTOFILL_BAR_ID)) return; // Bar already exists

    const bar = document.createElement('div');
    bar.id = AUTOFILL_BAR_ID;
    bar.style.all = 'initial';
    bar.style.position = 'fixed';
    bar.style.top = '0';
    bar.style.left = '0';
    bar.style.width = '100%';
    bar.style.backgroundColor = '#2a2a2a';
    bar.style.color = '#eee';
    bar.style.padding = '10px';
    bar.style.textAlign = 'center';
    bar.style.zIndex = '99999999';
    bar.style.fontFamily = 'sans-serif';
    bar.style.fontSize = '14px';

    const message = document.createElement('span');
    message.textContent = 'SaltVault found credentials for this site. ';
    bar.appendChild(message);

    const yesButton = document.createElement('button');
    yesButton.textContent = 'Autofill';
    yesButton.style.all = 'initial';
    yesButton.style.backgroundColor = '#4CAF50';
    yesButton.style.color = 'white';
    yesButton.style.padding = '5px 10px';
    yesButton.style.border = 'none';
    yesButton.style.borderRadius = '4px';
    yesButton.style.cursor = 'pointer';
    yesButton.style.marginLeft = '10px';
    yesButton.addEventListener('click', () => {
      doAutofill(creds);
      bar.remove();
    });
    bar.appendChild(yesButton);

    const noButton = document.createElement('button');
    noButton.textContent = 'Dismiss';
    noButton.style.all = 'initial';
    noButton.style.backgroundColor = '#f44336';
    noButton.style.color = 'white';
    noButton.style.padding = '5px 10px';
    noButton.style.border = 'none';
    noButton.style.borderRadius = '4px';
    noButton.style.cursor = 'pointer';
    noButton.style.marginLeft = '10px';
    noButton.addEventListener('click', () => {
      bar.remove();
    });
    bar.appendChild(noButton);

    document.body.prepend(bar);
  }


  /**
   * Main logic that runs on page load.
   */
  function onPageLoad() {
    chrome.storage.sync.get({ autofillSetting: 'ask' }, ({ autofillSetting }) => {
      if (autofillSetting === 'off') {
        return; // Do nothing
      }

      const { passwordField } = findLoginFields();
      if (!passwordField) {
        return; // No password field found, likely not a login page
      }

      const domain = location.hostname;
      chrome.runtime.sendMessage({ type: 'findCredsForDomain', domain }, (res) => {
        if (res && res.ok && res.item) {
          if (autofillSetting === 'auto') {
            doAutofill(res.item);
          } else if (autofillSetting === 'ask') {
            createAutofillBar(res.item);
          }
        }
      });
    });
  }

  /**
   * Listen for messages from the background script or popup.
   */
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'autofill' && msg.creds) {
      doAutofill(msg.creds);
      sendResponse({ ok: true });
    }
    return true; // Keep message channel open for async responses
  });

  // Run the main logic after the page has finished loading.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', onPageLoad);
  } else {
    onPageLoad();
  }

})();