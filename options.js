(async function(){
  // Import security utilities
  const { SecurityUtils } = await import('./security-utils-client.js');
  
  const tbody = document.querySelector('#list tbody');
  const originInput = document.getElementById('originInput');
  const addBtn = document.getElementById('addBtn');
  const exportBtn = document.getElementById('exportAllowlist');
  const importFile = document.getElementById('importFile');
  const importBtn = document.getElementById('importAllowlist');
  const status = document.getElementById('status');

  async function getAllowlist() {
    const res = await chrome.storage.sync.get({ allowlist: [] });
    return new Set(res.allowlist || []);
  }
  async function setAllowlist(set) {
    await chrome.storage.sync.set({ allowlist: Array.from(set) });
  }

  function render(listSet) {
    tbody.textContent = ''; // Clear safely
    Array.from(listSet).sort().forEach(origin => {
      const tr = SecurityUtils.escaping.createSafeElement('tr');
      const originTd = SecurityUtils.escaping.createSafeElement('td', {}, origin);
      const actionsTd = SecurityUtils.escaping.createSafeElement('td');
      const removeBtn = SecurityUtils.escaping.createSafeElement('button', {
        'data-act': 'remove',
        'data-origin': origin
      }, 'Remove');
      
      actionsTd.appendChild(removeBtn);
      tr.appendChild(originTd);
      tr.appendChild(actionsTd);
      tbody.appendChild(tr);
    });
  }

  async function load() {
    const set = await getAllowlist();
    render(set);
  }

  addBtn.onclick = async () => {
    try {
      const val = SecurityUtils.validation.sanitizeString(originInput.value);
      if (!SecurityUtils.validation.isValidUrl(val)) {
        throw new Error('Invalid URL');
      }
      
      const origin = new URL(val).origin;
      const set = await getAllowlist();
      set.add(origin);
      await setAllowlist(set);
      originInput.value = '';
      status.textContent = 'Added.';
      load();
      setTimeout(() => status.textContent = '', 1500);
    } catch {
      status.textContent = 'Please enter a valid URL like https://example.com';
      setTimeout(() => status.textContent = '', 2000);
    }
  };

  tbody.addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-act="remove"]');
    if (!btn) return;
    const origin = btn.getAttribute('data-origin');
    const set = await getAllowlist();
    set.delete(origin);
    await setAllowlist(set);
    status.textContent = 'Removed.';
    load();
    setTimeout(() => status.textContent = '', 1500);
  });

  exportBtn.onclick = async () => {
    const hasPermission = await SecurityUtils.permissions.requestDownloadPermissions();
    if (!hasPermission) {
      status.textContent = 'Download permission is required for exporting.';
      setTimeout(() => status.textContent = '', 2000);
      return;
    }
    
    const set = await getAllowlist();
    const blob = new Blob([JSON.stringify({ allowlist: Array.from(set) }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    if (chrome.downloads) chrome.downloads.download({ url, filename: 'allowlist.json' }); else window.open(url);
  };

  importBtn.onclick = async () => {
    const file = importFile.files?.[0];
    if (!file) return;
    
    try {
      const text = await file.text();
      const obj = JSON.parse(text);
      
      if (!SecurityUtils.validation.validateConfiguration(obj) || !Array.isArray(obj.allowlist)) {
        throw new Error('Invalid format');
      }
      
      // Validate each URL in the allowlist
      const validUrls = obj.allowlist.filter(url => SecurityUtils.validation.isValidUrl(url));
      if (validUrls.length !== obj.allowlist.length) {
        status.textContent = 'Some invalid URLs were skipped.';
      } else {
        status.textContent = 'Imported.';
      }
      
      await chrome.storage.sync.set({ allowlist: validUrls });
      load();
      setTimeout(() => status.textContent = '', 1500);
    } catch {
      status.textContent = 'Invalid JSON format.';
      setTimeout(() => status.textContent = '', 2000);
    }
  };

  load();
})();
