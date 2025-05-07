/**
 * React Security Suite - Browser API Compatibility Polyfill
 * 
 * This script provides compatibility between Chrome's extension API
 * and Firefox's WebExtensions API.
 */

(function() {
  // Only create the polyfill if browser is not defined
  if (typeof browser === 'undefined' || Object.getPrototypeOf(browser) !== Object.prototype) {
    window.browser = {
      runtime: {
        sendMessage: chrome.runtime.sendMessage,
        onMessage: chrome.runtime.onMessage,
        getManifest: chrome.runtime.getManifest
      },
      
      tabs: {
        query: chrome.tabs.query,
        sendMessage: chrome.tabs.sendMessage
      },
      
      storage: {
        local: chrome.storage.local
      },
      
      browserAction: {
        setBadgeText: chrome.browserAction ? chrome.browserAction.setBadgeText : function() {},
        setBadgeBackgroundColor: chrome.browserAction ? chrome.browserAction.setBadgeBackgroundColor : function() {}
      }
    };
  }
  
  // Ensure compatibility for different API styles
  if (chrome) {
    // Chrome uses callback style APIs
    const originalSendMessage = browser.runtime.sendMessage;
    browser.runtime.sendMessage = function(message) {
      return new Promise((resolve) => {
        originalSendMessage(message, resolve);
      });
    };
    
    const originalTabsQuery = browser.tabs.query;
    browser.tabs.query = function(query) {
      return new Promise((resolve) => {
        originalTabsQuery(query, resolve);
      });
    };
    
    const originalTabsSendMessage = browser.tabs.sendMessage;
    browser.tabs.sendMessage = function(tabId, message) {
      return new Promise((resolve) => {
        originalTabsSendMessage(tabId, message, resolve);
      });
    };
    
    const originalStorageGet = browser.storage.local.get;
    browser.storage.local.get = function(keys) {
      return new Promise((resolve) => {
        originalStorageGet(keys, resolve);
      });
    };
    
    const originalStorageSet = browser.storage.local.set;
    browser.storage.local.set = function(items) {
      return new Promise((resolve) => {
        originalStorageSet(items, resolve);
      });
    };
  }
})();
