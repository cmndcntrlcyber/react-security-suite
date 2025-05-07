/**
 * React Security Suite - Vulnerability Scanner
 * 
 * This module is responsible for scanning React applications for security
 * vulnerabilities and potential attack vectors.
 */

/**
 * Scan for React-related security vulnerabilities
 * @returns {Promise<Array>} Array of vulnerability objects
 */
export async function scanForVulnerabilities() {
  const vulnerabilities = [];
  
  // Only scan if React is detected
  if (!isReactDetected()) {
    return vulnerabilities;
  }
  
  // Run all scanners
  const scanners = [
    scanForExposedReactInternals,
    scanForExposedReactDOMInternals,
    scanForUnprotectedRenderMethods,
    scanForDangerousInnerHTML,
    scanForExposedCredentials,
    scanForInsecureContexts,
    scanForUnsafeLifecycleMethods
  ];
  
  for (const scanner of scanners) {
    try {
      const results = await scanner();
      if (results && results.length) {
        vulnerabilities.push(...results);
      }
    } catch (error) {
      console.error(`Error in scanner ${scanner.name}:`, error);
    }
  }
  
  return vulnerabilities;
}

/**
 * Check if React is detected on the page
 * @returns {boolean} True if React is detected
 */
export function isReactDetected() {
  return !!(
    window.React || 
    window.__REACT_DEVTOOLS_GLOBAL_HOOK__ ||
    document.querySelector('[data-reactroot]') ||
    document.querySelector('[data-reactid]')
  );
}

/**
 * Get React version if available
 * @returns {string} React version or 'unknown'
 */
export function getReactVersion() {
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

/**
 * Scan for exposed React internals
 * @returns {Array} Vulnerabilities found
 */
async function scanForExposedReactInternals() {
  const vulnerabilities = [];
  
  if (window.React && window.React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED) {
    vulnerabilities.push({
      type: 'EXPOSED_REACT_INTERNALS',
      severity: 'HIGH',
      description: 'React internals are exposed, allowing potential DOM manipulation attacks',
      location: window.location.href,
      details: 'The React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED object is accessible'
    });
  }
  
  return vulnerabilities;
}

/**
 * Scan for exposed ReactDOM internals
 * @returns {Array} Vulnerabilities found
 */
async function scanForExposedReactDOMInternals() {
  const vulnerabilities = [];
  
  if (window.ReactDOM && window.ReactDOM.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED) {
    vulnerabilities.push({
      type: 'EXPOSED_REACTDOM_INTERNALS',
      severity: 'HIGH',
      description: 'ReactDOM internals are exposed, allowing potential DOM manipulation attacks',
      location: window.location.href,
      details: 'The ReactDOM.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED object is accessible'
    });
  }
  
  return vulnerabilities;
}

/**
 * Scan for unprotected render methods
 * @returns {Array} Vulnerabilities found
 */
async function scanForUnprotectedRenderMethods() {
  const vulnerabilities = [];
  
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
  
  return vulnerabilities;
}

/**
 * Scan for dangerouslySetInnerHTML usage
 * @returns {Array} Vulnerabilities found
 */
async function scanForDangerousInnerHTML() {
  const vulnerabilities = [];
  
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
  
  return vulnerabilities;
}

/**
 * Scan for exposed credentials in script tags
 * @returns {Array} Vulnerabilities found
 */
async function scanForExposedCredentials() {
  const vulnerabilities = [];
  
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

/**
 * Scan for insecure contexts (non-HTTPS)
 * @returns {Array} Vulnerabilities found
 */
async function scanForInsecureContexts() {
  const vulnerabilities = [];
  
  // Check if the page is loaded over HTTPS
  if (window.location.protocol !== 'https:' && window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1') {
    vulnerabilities.push({
      type: 'INSECURE_CONTEXT',
      severity: 'HIGH',
      description: 'Application is running in an insecure context (non-HTTPS)',
      location: window.location.href,
      details: 'Running React applications over HTTP can expose them to man-in-the-middle attacks'
    });
  }
  
  return vulnerabilities;
}

/**
 * Scan for unsafe lifecycle methods
 * @returns {Array} Vulnerabilities found
 */
async function scanForUnsafeLifecycleMethods() {
  const vulnerabilities = [];
  
  // This is a more advanced scan that would require analyzing component code
  // For demonstration purposes, we'll check for common patterns in the global scope
  
  const unsafeLifecycleMethods = [
    'componentWillMount',
    'componentWillReceiveProps',
    'componentWillUpdate'
  ];
  
  // Check if any of these methods are defined in the global scope
  for (const method of unsafeLifecycleMethods) {
    if (window[method] || (window.React && window.React[method])) {
      vulnerabilities.push({
        type: 'UNSAFE_LIFECYCLE_METHODS',
        severity: 'LOW',
        description: `Potentially unsafe lifecycle method "${method}" detected`,
        location: window.location.href,
        details: 'These methods are deprecated and may lead to bugs in concurrent rendering'
      });
      break; // Only report once
    }
  }
  
  return vulnerabilities;
}
