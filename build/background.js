/**
 * React Security Suite - Background Service Worker
 * 
 * This script manages the extension's state and coordinates communication
 * between the popup UI and content scripts.
 */

// Extension state
let state = {
  mode: 'defense', // 'defense' or 'training'
  scanResults: [],
  protectionActive: false,
  trainingActive: false,
  autoDemoActive: false,
  detectedReactVersion: null,
  logs: []
};

// Initialize extension state from storage
chrome.storage.local.get(['reactSecurityState'], (result) => {
  if (result.reactSecurityState) {
    state = {...state, ...result.reactSecurityState};
  }
});

// Save state to storage
function saveState() {
  chrome.storage.local.set({reactSecurityState: state});
}

// Log events with timestamps
function logEvent(category, action, details) {
  const log = {
    timestamp: new Date().toISOString(),
    category,
    action,
    details,
    url: details?.url || 'unknown'
  };
  
  state.logs.unshift(log);
  // Keep logs limited to 100 entries
  if (state.logs.length > 100) {
    state.logs.pop();
  }
  
  saveState();
  return log;
}

// Handle messages from popup and content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Handle scan results from content script
  if (message.action === 'scanComplete') {
    state.scanResults = message.vulnerabilities || [];
    
  // Update badge to show number of vulnerabilities
  if (sender.tab && sender.tab.id) {
    // Use browserAction instead of action for Firefox compatibility
    try {
      if (typeof browser !== 'undefined') {
        browser.browserAction.setBadgeText({ 
          text: state.scanResults.length > 0 ? state.scanResults.length.toString() : '',
          tabId: sender.tab.id
        });
        browser.browserAction.setBadgeBackgroundColor({ 
          color: '#FF0000',
          tabId: sender.tab.id
        });
      } else {
        chrome.browserAction.setBadgeText({ 
          text: state.scanResults.length > 0 ? state.scanResults.length.toString() : '',
          tabId: sender.tab.id
        });
        chrome.browserAction.setBadgeBackgroundColor({ 
          color: '#FF0000',
          tabId: sender.tab.id
        });
      }
    } catch (error) {
      console.error("Error setting badge:", error);
    }
  }
    
    logEvent('scan', 'completed', {
      url: sender.tab?.url,
      vulnerabilitiesFound: state.scanResults.length
    });
    
    saveState();
    sendResponse({success: true});
  }
  
  // Handle React version detection
  if (message.action === 'reactDetected') {
    state.detectedReactVersion = message.version;
    logEvent('detection', 'reactFound', {
      url: sender.tab?.url,
      version: message.version
    });
    saveState();
    sendResponse({success: true});
  }
  
  // Handle protection status updates
  if (message.action === 'protectionStatus') {
    state.protectionActive = message.active;
    logEvent('protection', message.active ? 'enabled' : 'disabled', {
      url: sender.tab?.url
    });
    saveState();
    sendResponse({success: true});
  }
  
  // Handle training mode activation/deactivation
  if (message.action === 'setTrainingMode') {
    if (message.active && !state.trainingActive) {
      // Require confirmation for training mode
      logEvent('training', 'activated', {
        url: sender.tab?.url,
        confirmed: message.confirmed
      });
      
      if (message.confirmed) {
        state.trainingActive = true;
        state.mode = 'training';
        saveState();
      }
    } else if (!message.active && state.trainingActive) {
      state.trainingActive = false;
      state.mode = 'defense';
      // When leaving training mode, disable auto-demo
      state.autoDemoActive = false;
      logEvent('training', 'deactivated', {
        url: sender.tab?.url
      });
      saveState();
    }
    
    sendResponse({
      success: true,
      trainingActive: state.trainingActive,
      mode: state.mode
    });
  }
  
  // Handle auto-demo mode activation/deactivation
  if (message.action === 'setAutoDemo') {
    state.autoDemoActive = message.autoDemo;
    
    logEvent('training', message.autoDemo ? 'autoDemoEnabled' : 'autoDemoDisabled', {
      url: sender.tab?.url
    });
    
    saveState();
    sendResponse({
      success: true,
      autoDemoActive: state.autoDemoActive
    });
  }
  
  // Handle attack demonstration requests
  if (message.action === 'demonstrateAttack') {
    if (!state.trainingActive) {
      sendResponse({
        success: false,
        error: 'Training mode must be active to demonstrate attacks'
      });
      return true;
    }
    
    logEvent('training', 'demonstrationRequested', {
      url: sender.tab?.url,
      attackType: message.attackType
    });
    
    // Forward the demonstration request to the content script
    if (sender.tab && sender.tab.id) {
      chrome.tabs.sendMessage(sender.tab.id, {
        action: 'runDemonstration',
        attackType: message.attackType,
        options: message.options
      }, (response) => {
        if (response && response.success) {
          logEvent('training', 'demonstrationCompleted', {
            url: sender.tab?.url,
            attackType: message.attackType
          });
        } else {
          logEvent('training', 'demonstrationFailed', {
            url: sender.tab?.url,
            attackType: message.attackType,
            error: response?.error
          });
        }
      });
    }
    
    sendResponse({success: true});
  }
  
  // Handle state requests from popup
  if (message.action === 'getState') {
    sendResponse({
      success: true,
      state: state
    });
  }
  
  // Handle log clearing
  if (message.action === 'clearLogs') {
    state.logs = [];
    saveState();
    sendResponse({success: true});
  }
  
  return true; // Required for async response
});

// Handle installation and updates
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    logEvent('system', 'installed', {
      version: chrome.runtime.getManifest().version
    });
  } else if (details.reason === 'update') {
    logEvent('system', 'updated', {
      version: chrome.runtime.getManifest().version,
      previousVersion: details.previousVersion
    });
  }
});
