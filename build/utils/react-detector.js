/**
 * React Security Suite - React Detector Utility
 * 
 * This utility provides functions for detecting React and its features
 * in web applications.
 */

/**
 * Check if React is present on the page
 * @returns {boolean} True if React is detected
 */
export function isReactPresent() {
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
 * Check if React hooks are available
 * @returns {boolean} True if React hooks are detected
 */
export function areHooksAvailable() {
  return !!(
    window.React && 
    typeof window.React.useState === 'function' &&
    typeof window.React.useEffect === 'function'
  );
}

/**
 * Detect React hooks in the current page
 * @returns {Array} Array of detected hooks
 */
export function detectReactHooks() {
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
      },
      { 
        name: 'useImperativeHandle', 
        description: 'Customized ref value hook',
        check: () => typeof window.React.useImperativeHandle === 'function'
      },
      { 
        name: 'useDebugValue', 
        description: 'Debug label hook',
        check: () => typeof window.React.useDebugValue === 'function'
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
 * Find React components in the DOM
 * @returns {Array} Array of detected React component elements
 */
export function findReactComponents() {
  const components = [];
  
  // Find elements with React-specific properties
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
      components.push(el);
    }
  }
  
  return components;
}

/**
 * Extract React component information
 * @param {Element} element - DOM element with React component
 * @returns {Object|null} Component information or null if not a React component
 */
export function extractComponentInfo(element) {
  if (!element) return null;
  
  // Find React fiber key
  const fiberKey = Object.keys(element).find(key => 
    key.startsWith('__reactFiber$') || 
    key.startsWith('__reactInternalInstance$')
  );
  
  if (!fiberKey) return null;
  
  // Access fiber
  const fiber = element[fiberKey];
  if (!fiber) return null;
  
  // Extract component info
  const info = {
    name: fiber.type?.displayName || fiber.type?.name || 'Unknown',
    element: element.tagName.toLowerCase(),
    id: element.id || null,
    className: element.className || null,
    hasState: !!(fiber.stateNode && fiber.stateNode.state),
    hasProps: !!fiber.memoizedProps,
    children: fiber.child ? true : false
  };
  
  return info;
}

/**
 * Check if the application is using React Router
 * @returns {boolean} True if React Router is detected
 */
export function isUsingReactRouter() {
  // Check for common React Router elements
  return !!(
    document.querySelector('a[href][data-reactid]') ||
    document.querySelector('a[href][data-reactroot]') ||
    window.ReactRouter ||
    window.React?.Component?.prototype?.componentWillReceiveProps
  );
}

/**
 * Check if the application is using Redux
 * @returns {boolean} True if Redux is detected
 */
export function isUsingRedux() {
  return !!(
    window.Redux ||
    window.__REDUX_DEVTOOLS_EXTENSION__ ||
    window.__REDUX_DEVTOOLS_EXTENSION_COMPOSED__
  );
}

/**
 * Check if the application is in development mode
 * @returns {boolean} True if React is in development mode
 */
export function isReactInDevMode() {
  return !!(
    window.__REACT_DEVTOOLS_GLOBAL_HOOK__ ||
    window.__REDUX_DEVTOOLS_EXTENSION__ ||
    (window.React && window.React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED)
  );
}

/**
 * Get a comprehensive report of React usage on the page
 * @returns {Object} Report of React usage
 */
export function getReactReport() {
  const isReact = isReactPresent();
  
  if (!isReact) {
    return {
      detected: false
    };
  }
  
  const components = findReactComponents();
  const componentInfos = components.slice(0, 10).map(extractComponentInfo).filter(Boolean);
  
  return {
    detected: true,
    version: getReactVersion(),
    devMode: isReactInDevMode(),
    hooks: {
      available: areHooksAvailable(),
      detected: detectReactHooks()
    },
    routing: {
      usingReactRouter: isUsingReactRouter()
    },
    stateManagement: {
      usingRedux: isUsingRedux()
    },
    components: {
      count: components.length,
      sample: componentInfos
    }
  };
}
