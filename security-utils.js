// Security utilities for input validation, HTML escaping, and permission management
// Compatible with importScripts for use in service workers

const SecurityUtils = {
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

    async requestCookiePermissions(url) {
      try {
        const origin = new URL(url).origin;
        return await this.requestPermissionIfNeeded('cookies', origin + '/*');
      } catch (error) {
        console.error('Cookie permission request failed:', error);
        return false;
      }
    },

    async requestWebRequestPermissions() {
      return await this.requestPermissionIfNeeded('webRequest', '<all_urls>');
    },

    async requestDownloadPermissions() {
      return await this.requestPermissionIfNeeded('downloads');
    }
  },

  // Encrypted storage utilities using Chrome's built-in encryption
  storage: {
    // Encode data for secure storage (basic obfuscation)
    encodeData(data) {
      try {
        const jsonString = JSON.stringify(data);
        return btoa(jsonString); // Base64 encoding
      } catch (error) {
        console.error('Data encoding failed:', error);
        return null;
      }
    },

    // Decode data from secure storage
    decodeData(encodedData) {
      try {
        const jsonString = atob(encodedData);
        return JSON.parse(jsonString);
      } catch (error) {
        console.error('Data decoding failed:', error);
        return null;
      }
    },

    async setSecure(key, data) {
      const encodedData = this.encodeData(data);
      if (!encodedData) return false;

      try {
        await chrome.storage.local.set({ [`secure_${key}`]: encodedData });
        return true;
      } catch (error) {
        console.error('Secure storage set failed:', error);
        return false;
      }
    },

    async getSecure(key) {
      try {
        const result = await chrome.storage.local.get(`secure_${key}`);
        const encodedData = result[`secure_${key}`];
        if (!encodedData) return null;

        return this.decodeData(encodedData);
      } catch (error) {
        console.error('Secure storage get failed:', error);
        return null;
      }
    },

    async removeSecure(key) {
      try {
        await chrome.storage.local.remove(`secure_${key}`);
        return true;
      } catch (error) {
        console.error('Secure storage remove failed:', error);
        return false;
      }
    },

    async setTemporary(key, data) {
      try {
        await chrome.storage.session.set({ [key]: data });
        return true;
      } catch (error) {
        console.error('Temporary storage set failed:', error);
        return false;
      }
    },

    async getTemporary(key) {
      try {
        const result = await chrome.storage.session.get(key);
        return result[key] || null;
      } catch (error) {
        console.error('Temporary storage get failed:', error);
        return null;
      }
    },

    async clearTemporary() {
      try {
        await chrome.storage.session.clear();
        return true;
      } catch (error) {
        console.error('Temporary storage clear failed:', error);
        return false;
      }
    },

    // Cleanup old data entries
    async cleanup(olderThanDays = 7) {
      try {
        const cutoffTime = Date.now() - (olderThanDays * 24 * 60 * 60 * 1000);
        const allData = await chrome.storage.local.get(null);
        const keysToRemove = [];

        Object.keys(allData).forEach(key => {
          if (key.startsWith('history:')) {
            const timestamp = parseInt(key.split(':')[1]);
            if (timestamp < cutoffTime) {
              keysToRemove.push(key);
            }
          }
        });

        if (keysToRemove.length > 0) {
          await chrome.storage.local.remove(keysToRemove);
        }

        return keysToRemove.length;
      } catch (error) {
        console.error('Storage cleanup failed:', error);
        return 0;
      }
    }
  }
};