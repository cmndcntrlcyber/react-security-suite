/**
 * React Security Suite - Defender Module
 * 
 * This module is responsible for applying protection measures to React applications
 * to prevent exploitation of vulnerabilities.
 */

/**
 * Apply protection measures to the React application
 * @returns {boolean} True if protection was applied successfully
 */
export function applyProtection() {
  // Check if React is present
  if (!window.React && !window.ReactDOM) {
    console.warn('[React Security Suite] No React detected, nothing to protect');
    return false;
  }
  
  let protectionApplied = false;
  
  // Apply all protection measures
  protectionApplied = protectReactInternals() || protectionApplied;
  protectionApplied = protectReactDOMMethods() || protectionApplied;
  protectionApplied = monitorDOMChanges() || protectionApplied;
  protectionApplied = protectLocalStorage() || protectionApplied;
  protectionApplied = protectCookieAccess() || protectionApplied;
  
  return protectionApplied;
}

/**
 * Protect React internals from being accessed
 * @returns {boolean} True if protection was applied
 */
function protectReactInternals() {
  let isProtected = false;
  
  // Protect React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED
  if (window.React && window.React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED) {
    const originalInternals = window.React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED;
    
    // Replace with a proxy to monitor access
    Object.defineProperty(window.React, '__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED', {
      get: function() {
        console.warn('[React Security Suite] Attempted access to React internals detected');
        logSecurityEvent('access_attempt', 'react_internals', {
          stack: new Error().stack
        });
        return {}; // Return empty object instead of actual internals
      },
      configurable: false
    });
    
    isProtected = true;
    console.info('[React Security Suite] Protected React internals');
  }
  
  // Protect ReactDOM.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED
  if (window.ReactDOM && window.ReactDOM.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED) {
    const originalDOMInternals = window.ReactDOM.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED;
    
    // Replace with a proxy to monitor access
    Object.defineProperty(window.ReactDOM, '__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED', {
      get: function() {
        console.warn('[React Security Suite] Attempted access to ReactDOM internals detected');
        logSecurityEvent('access_attempt', 'reactdom_internals', {
          stack: new Error().stack
        });
        return {}; // Return empty object instead of actual internals
      },
      configurable: false
    });
    
    isProtected = true;
    console.info('[React Security Suite] Protected ReactDOM internals');
  }
  
  return isProtected;
}

/**
 * Protect ReactDOM methods from being misused
 * @returns {boolean} True if protection was applied
 */
function protectReactDOMMethods() {
  let isProtected = false;
  
  // Store original methods if they exist
  const originalMethods = {
    render: window.ReactDOM?.render,
    createRoot: window.ReactDOM?.createRoot,
    hydrateRoot: window.ReactDOM?.hydrateRoot,
    findDOMNode: window.ReactDOM?.findDOMNode
  };
  
  // Protect ReactDOM.render
  if (window.ReactDOM && window.ReactDOM.render && !window.ReactDOM.render.isProtected) {
    window.ReactDOM.render = function(...args) {
      console.info('[React Security Suite] ReactDOM.render intercepted');
      
      // Check if the call is legitimate
      const callStack = new Error().stack;
      const isLegitimate = isLegitimateCall(callStack);
      
      // Only allow if legitimate
      if (isLegitimate) {
        return originalMethods.render.apply(this, args);
      } else {
        console.error('[React Security Suite] Blocked suspicious ReactDOM.render call');
        logSecurityEvent('blocked_call', 'reactdom_render', {
          stack: callStack,
          args: safeStringify(args[0])
        });
        return null;
      }
    };
    window.ReactDOM.render.isProtected = true;
    isProtected = true;
    console.info('[React Security Suite] Protected ReactDOM.render');
  }
  
  // Protect ReactDOM.createRoot (React 18+)
  if (window.ReactDOM && window.ReactDOM.createRoot && !window.ReactDOM.createRoot.isProtected) {
    window.ReactDOM.createRoot = function(...args) {
      console.info('[React Security Suite] ReactDOM.createRoot intercepted');
      
      const callStack = new Error().stack;
      const isLegitimate = isLegitimateCall(callStack);
      
      if (isLegitimate) {
        const root = originalMethods.createRoot.apply(this, args);
        
        // Also protect the root.render method
        const originalRootRender = root.render;
        root.render = function(...renderArgs) {
          console.info('[React Security Suite] root.render intercepted');
          
          const renderCallStack = new Error().stack;
          const isRenderLegitimate = isLegitimateCall(renderCallStack);
          
          if (isRenderLegitimate) {
            return originalRootRender.apply(this, renderArgs);
          } else {
            console.error('[React Security Suite] Blocked suspicious root.render call');
            logSecurityEvent('blocked_call', 'root_render', {
              stack: renderCallStack,
              args: safeStringify(renderArgs[0])
            });
            return null;
          }
        };
        
        return root;
      } else {
        console.error('[React Security Suite] Blocked suspicious ReactDOM.createRoot call');
        logSecurityEvent('blocked_call', 'reactdom_createRoot', {
          stack: callStack,
          args: safeStringify(args[0])
        });
        return {
          render: function() { return null; }
        };
      }
    };
    window.ReactDOM.createRoot.isProtected = true;
    isProtected = true;
    console.info('[React Security Suite] Protected ReactDOM.createRoot');
  }
  
  // Protect ReactDOM.findDOMNode
  if (window.ReactDOM && window.ReactDOM.findDOMNode && !window.ReactDOM.findDOMNode.isProtected) {
    window.ReactDOM.findDOMNode = function(...args) {
      console.info('[React Security Suite] ReactDOM.findDOMNode intercepted');
      
      const callStack = new Error().stack;
      logSecurityEvent('call', 'reactdom_findDOMNode', {
        stack: callStack
      });
      
      return originalMethods.findDOMNode.apply(this, args);
    };
    window.ReactDOM.findDOMNode.isProtected = true;
    isProtected = true;
    console.info('[React Security Suite] Monitoring ReactDOM.findDOMNode');
  }
  
  return isProtected;
}

/**
 * Monitor DOM changes for suspicious activity
 * @returns {boolean} True if monitoring was set up
 */
function monitorDOMChanges() {
  // Only set up monitoring once
  if (window.__reactSecuritySuiteMonitoring) {
    return false;
  }
  
  try {
    // Set up a MutationObserver to monitor DOM changes
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        // Check for suspicious additions
        if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
          for (const node of mutation.addedNodes) {
            if (node.nodeType === Node.ELEMENT_NODE) {
              // Check for suspicious elements
              if (isSuspiciousElement(node)) {
                console.warn('[React Security Suite] Suspicious DOM element detected:', node);
                logSecurityEvent('suspicious_element', 'dom_mutation', {
                  element: node.outerHTML.substring(0, 200),
                  parentElement: mutation.target.tagName
                });
              }
            }
          }
        }
      }
    });
    
    // Start observing the document
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
    
    window.__reactSecuritySuiteMonitoring = true;
    console.info('[React Security Suite] DOM monitoring active');
    return true;
  } catch (error) {
    console.error('[React Security Suite] Error setting up DOM monitoring:', error);
    return false;
  }
}

/**
 * Protect localStorage from unauthorized access
 * @returns {boolean} True if protection was applied
 */
function protectLocalStorage() {
  // Only protect once
  if (window.__reactSecuritySuiteLocalStorageProtected) {
    return false;
  }
  
  try {
    // Store original methods
    const originalSetItem = Storage.prototype.setItem;
    const originalGetItem = Storage.prototype.getItem;
    const originalRemoveItem = Storage.prototype.removeItem;
    const originalClear = Storage.prototype.clear;
    
    // Override setItem
    Storage.prototype.setItem = function(key, value) {
      // Log sensitive keys
      if (isSensitiveKey(key)) {
        console.warn(`[React Security Suite] Sensitive data being stored in localStorage: ${key}`);
        logSecurityEvent('sensitive_storage', 'localStorage_setItem', {
          key: key,
          stack: new Error().stack
        });
      }
      
      return originalSetItem.call(this, key, value);
    };
    
    // Override getItem
    Storage.prototype.getItem = function(key) {
      // Log access to sensitive keys
      if (isSensitiveKey(key)) {
        console.info(`[React Security Suite] Access to sensitive localStorage key: ${key}`);
        logSecurityEvent('access', 'localStorage_getItem', {
          key: key,
          stack: new Error().stack
        });
      }
      
      return originalGetItem.call(this, key);
    };
    
    // Override removeItem
    Storage.prototype.removeItem = function(key) {
      // Log removal of sensitive keys
      if (isSensitiveKey(key)) {
        console.info(`[React Security Suite] Removing sensitive localStorage key: ${key}`);
        logSecurityEvent('removal', 'localStorage_removeItem', {
          key: key,
          stack: new Error().stack
        });
      }
      
      return originalRemoveItem.call(this, key);
    };
    
    // Override clear
    Storage.prototype.clear = function() {
      console.warn('[React Security Suite] localStorage.clear() called');
      logSecurityEvent('clear', 'localStorage_clear', {
        stack: new Error().stack
      });
      
      return originalClear.call(this);
    };
    
    window.__reactSecuritySuiteLocalStorageProtected = true;
    console.info('[React Security Suite] localStorage monitoring active');
    return true;
  } catch (error) {
    console.error('[React Security Suite] Error setting up localStorage protection:', error);
    return false;
  }
}

/**
 * Protect cookie access
 * @returns {boolean} True if protection was applied
 */
function protectCookieAccess() {
  // Only protect once
  if (window.__reactSecuritySuiteCookieProtected) {
    return false;
  }
  
  try {
    // Store original cookie property descriptor
    const originalCookieDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    
    // Override cookie getter
    Object.defineProperty(Document.prototype, 'cookie', {
      get: function() {
        console.info('[React Security Suite] Cookie access detected');
        logSecurityEvent('access', 'document_cookie', {
          stack: new Error().stack
        });
        return originalCookieDescriptor.get.call(this);
      },
      set: function(value) {
        console.info('[React Security Suite] Cookie modification detected');
        logSecurityEvent('modification', 'document_cookie', {
          value: value,
          stack: new Error().stack
        });
        return originalCookieDescriptor.set.call(this, value);
      },
      configurable: true
    });
    
    window.__reactSecuritySuiteCookieProtected = true;
    console.info('[React Security Suite] Cookie access monitoring active');
    return true;
  } catch (error) {
    console.error('[React Security Suite] Error setting up cookie protection:', error);
    return false;
  }
}

/**
 * Check if a call is legitimate based on the call stack
 * @param {string} callStack - The call stack as a string
 * @returns {boolean} True if the call is legitimate
 */
function isLegitimateCall(callStack) {
  // This is a simple heuristic - in reality this would be more sophisticated
  // For demo purposes, we're checking if the call originated from browser extensions
  // or from event handlers which might indicate malicious injection
  
  const suspiciousPatterns = [
    'chrome-extension://',
    'moz-extension://',
    'eval',
    'Function',
    'injected',
    'inject.js'
  ];
  
  // Exclude our own extension
  const ownExtensionId = chrome.runtime.id;
  const ownExtensionPattern = `chrome-extension://${ownExtensionId}`;
  
  // True = legitimate, False = suspicious
  return !suspiciousPatterns.some(pattern => 
    callStack.includes(pattern) && !callStack.includes(ownExtensionPattern)
  );
}

/**
 * Check if an element looks suspicious
 * @param {Element} element - The DOM element to check
 * @returns {boolean} True if the element looks suspicious
 */
function isSuspiciousElement(element) {
  // Check for common attack patterns
  
  // Check for form elements that might be phishing
  if (element.tagName === 'FORM') {
    const inputs = element.querySelectorAll('input');
    const passwordInputs = element.querySelectorAll('input[type="password"]');
    
    // Forms with password fields might be phishing attempts
    if (passwordInputs.length > 0) {
      return true;
    }
  }
  
  // Check for iframe injections
  if (element.tagName === 'IFRAME') {
    // Iframes without sandbox attribute might be suspicious
    if (!element.hasAttribute('sandbox')) {
      return true;
    }
  }
  
  // Check for script injections
  if (element.tagName === 'SCRIPT') {
    // Inline scripts might be suspicious
    if (element.textContent && !element.src) {
      return true;
    }
  }
  
  // Check for suspicious attributes
  const suspiciousAttributes = ['javascript:', 'data:', 'vbscript:'];
  for (const attr of element.attributes) {
    const value = attr.value.toLowerCase();
    if (suspiciousAttributes.some(pattern => value.includes(pattern))) {
      return true;
    }
  }
  
  return false;
}

/**
 * Check if a localStorage key might contain sensitive data
 * @param {string} key - The key to check
 * @returns {boolean} True if the key might contain sensitive data
 */
function isSensitiveKey(key) {
  const sensitivePatterns = [
    'token',
    'auth',
    'key',
    'secret',
    'password',
    'credential',
    'session',
    'jwt',
    'api'
  ];
  
  const lowerKey = key.toLowerCase();
  return sensitivePatterns.some(pattern => lowerKey.includes(pattern));
}

/**
 * Log a security event to the extension
 * @param {string} action - The action that occurred
 * @param {string} target - The target of the action
 * @param {Object} details - Additional details about the event
 */
function logSecurityEvent(action, target, details = {}) {
  chrome.runtime.sendMessage({
    action: 'securityEvent',
    securityEvent: {
      action,
      target,
      details,
      timestamp: new Date().toISOString(),
      url: window.location.href
    }
  });
}

/**
 * Safely stringify an object for logging
 * @param {any} obj - The object to stringify
 * @returns {string} A string representation of the object
 */
function safeStringify(obj) {
  try {
    return JSON.stringify(obj, (key, value) => {
      if (value instanceof Element) {
        return `[Element ${value.tagName}]`;
      }
      if (value instanceof Function) {
        return `[Function ${value.name || 'anonymous'}]`;
      }
      return value;
    });
  } catch (error) {
    return String(obj);
  }
}
