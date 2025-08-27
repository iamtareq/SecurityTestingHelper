// Client-side security utilities for popup and options pages
// ES6 module version with DOM utilities

export const SecurityUtils = {
  // Input validation utilities
  validation: {
    isValidUrl(input) {
      if (!input || typeof input !== 'string') return false;
      try {
        const url = new URL(input.trim());
        return url.protocol === 'https:' || url.protocol === 'http:';
      } catch {
        return false;
      }
    },

    isValidOrigin(input) {
      if (!input || typeof input !== 'string') return false;
      try {
        const url = new URL(input.trim());
        return (url.protocol === 'https:' || url.protocol === 'http:') && url.pathname === '/';
      } catch {
        return false;
      }
    },

    sanitizeString(input, maxLength = 1000) {
      if (!input || typeof input !== 'string') return '';
      return input.trim().slice(0, maxLength);
    },

    validatePayload(payload) {
      if (!payload || typeof payload !== 'string') return false;
      // Basic validation - no script tags or javascript: URLs
      const dangerous = /<script|javascript:|on\w+=/i;
      return !dangerous.test(payload);
    },

    validateConfiguration(config) {
      if (!config || typeof config !== 'object') return false;
      // Validate configuration object structure
      const allowedKeys = ['allowlist', 'settings', 'preferences'];
      return Object.keys(config).every(key => allowedKeys.includes(key));
    }
  },

  // HTML escaping utilities
  escaping: {
    escapeHtml(unsafe) {
      if (!unsafe || typeof unsafe !== 'string') return '';
      return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    },

    escapeAttribute(unsafe) {
      if (!unsafe || typeof unsafe !== 'string') return '';
      return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#x27;")
        .replace(/\//g, "&#x2F;");
    },

    createSafeElement(tag, attributes = {}, textContent = '') {
      const element = document.createElement(tag);
      
      // Set attributes safely
      Object.entries(attributes).forEach(([key, value]) => {
        if (key.startsWith('on')) return; // Block event handlers
        element.setAttribute(key, this.escapeAttribute(String(value)));
      });
      
      // Set text content safely
      if (textContent) {
        element.textContent = String(textContent);
      }
      
      return element;
    },

    // Safe innerHTML replacement
    setSafeInnerHTML(element, htmlContent) {
      if (!element || !element.nodeType) return;
      
      // Clear existing content
      element.textContent = '';
      
      // Create a temporary container
      const temp = document.createElement('div');
      temp.innerHTML = this.escapeHtml(htmlContent);
      
      // Move sanitized content
      while (temp.firstChild) {
        element.appendChild(temp.firstChild);
      }
    }
  },

  // Permission management utilities
  permissions: {
    async requestPermissionIfNeeded(permission, hostPermission = null) {
      try {
        const hasPermission = await chrome.permissions.contains({
          permissions: [permission],
          ...(hostPermission ? { origins: [hostPermission] } : {})
        });

        if (hasPermission) return true;

        return await chrome.permissions.request({
          permissions: [permission],
          ...(hostPermission ? { origins: [hostPermission] } : {})
        });
      } catch (error) {
        console.error('Permission request failed:', error);
        return false;
      }
    },

    async requestDownloadPermissions() {
      return await this.requestPermissionIfNeeded('downloads');
    }
  },

  // DOM utilities for safe rendering
  dom: {
    renderList(container, title, items, getRow) {
      if (!container) return;
      
      // Clear container safely
      container.textContent = '';
      
      // Create title element safely
      const titleDiv = SecurityUtils.escaping.createSafeElement('div', { class: 'item' });
      const titleH3 = SecurityUtils.escaping.createSafeElement('h3', {}, title);
      titleDiv.appendChild(titleH3);
      
      if (items.length === 0) {
        const noItems = SecurityUtils.escaping.createSafeElement('p');
        const small = SecurityUtils.escaping.createSafeElement('small', { class: 'muted' }, 'No issues found.');
        noItems.appendChild(small);
        titleDiv.appendChild(noItems);
      }
      
      container.appendChild(titleDiv);
      
      items.forEach(item => {
        const row = SecurityUtils.escaping.createSafeElement('div', { class: 'row' });
        // Use safe HTML rendering for the row content
        const safeContent = getRow(item);
        row.innerHTML = safeContent; // This needs to be validated by the caller
        titleDiv.appendChild(row);
      });
    },

    createTable(headers, rows) {
      const table = SecurityUtils.escaping.createSafeElement('table', { class: 'table' });
      
      // Create header
      const thead = SecurityUtils.escaping.createSafeElement('thead');
      const headerRow = SecurityUtils.escaping.createSafeElement('tr');
      
      headers.forEach(header => {
        const th = SecurityUtils.escaping.createSafeElement('th', {}, header);
        headerRow.appendChild(th);
      });
      
      thead.appendChild(headerRow);
      table.appendChild(thead);
      
      // Create body
      const tbody = SecurityUtils.escaping.createSafeElement('tbody');
      
      rows.forEach(rowData => {
        const row = SecurityUtils.escaping.createSafeElement('tr');
        headers.forEach(header => {
          const td = SecurityUtils.escaping.createSafeElement('td', { class: 'mono' }, 
            String(rowData[header] || ''));
          row.appendChild(td);
        });
        tbody.appendChild(row);
      });
      
      table.appendChild(tbody);
      return table;
    }
  }
};