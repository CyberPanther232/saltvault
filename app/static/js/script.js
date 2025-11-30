// SaltVault main client script
(function(){
  console.log('SaltVault script loaded');

  // Copy to clipboard utility
  window.copyText = function(selector){
    try {
      const el = document.querySelector(selector);
      if(!el) return;
      const text = el.textContent || el.value || '';
      navigator.clipboard.writeText(text).then(()=>{
        console.log('Copied to clipboard');
      });
    } catch(e){ console.warn('Copy failed', e); }
  };

  // Toggle visibility for password fields with data-toggle-target attribute
  document.addEventListener('click', function(e){
    const t = e.target;
    if(t.matches('[data-toggle-pass]')){
      const targetSel = t.getAttribute('data-toggle-pass');
      const input = document.querySelector(targetSel);
      if(input){
        input.type = input.type === 'password' ? 'text' : 'password';
      }
    }
  });
})();
