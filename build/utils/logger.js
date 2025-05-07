/**
 * React Security Suite - Logger Utility
 * 
 * This utility provides logging functionality for the extension.
 */

// Log levels
export const LogLevel = {
  DEBUG: 0,
  INFO: 1,
  WARN: 2,
  ERROR: 3,
  NONE: 4
};

// Default configuration
let config = {
  level: LogLevel.INFO,
  enableConsole: true,
  maxLogs: 100,
  logToStorage: true
};

// Log storage
let logs = [];

/**
 * Configure the logger
 * @param {Object} options - Configuration options
 */
export function configure(options = {}) {
  config = { ...config, ...options };
}

/**
 * Log a debug message
 * @param {string} message - The message to log
 * @param {Object} data - Additional data to log
 */
export function debug(message, data = null) {
  logMessage(LogLevel.DEBUG, 'debug', message, data);
}

/**
 * Log an info message
 * @param {string} message - The message to log
 * @param {Object} data - Additional data to log
 */
export function info(message, data = null) {
  logMessage(LogLevel.INFO, 'info', message, data);
}

/**
 * Log a warning message
 * @param {string} message - The message to log
 * @param {Object} data - Additional data to log
 */
export function warn(message, data = null) {
  logMessage(LogLevel.WARN, 'warn', message, data);
}

/**
 * Log an error message
 * @param {string} message - The message to log
 * @param {Object} data - Additional data to log
 */
export function error(message, data = null) {
  logMessage(LogLevel.ERROR, 'error', message, data);
}

/**
 * Log a security event
 * @param {string} action - The security action
 * @param {string} target - The target of the action
 * @param {Object} details - Additional details
 */
export function security(action, target, details = {}) {
  const message = `Security event: ${action} on ${target}`;
  logMessage(LogLevel.WARN, 'security', message, details);
  
  // Send to background script
  try {
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
  } catch (e) {
    // Ignore errors when sending to background script
    console.error('Error sending security event to background script:', e);
  }
}

/**
 * Internal function to log a message
 * @param {number} level - The log level
 * @param {string} type - The log type
 * @param {string} message - The message to log
 * @param {Object} data - Additional data to log
 */
function logMessage(level, type, message, data) {
  // Check if we should log this message
  if (level < config.level) {
    return;
  }
  
  // Create log entry
  const logEntry = {
    timestamp: new Date().toISOString(),
    type,
    message,
    data,
    url: window.location.href
  };
  
  // Log to console if enabled
  if (config.enableConsole) {
    const consoleMethod = type === 'error' ? 'error' : 
                          type === 'warn' ? 'warn' : 
                          type === 'debug' ? 'debug' : 'log';
    
    if (data) {
      console[consoleMethod](`[React Security Suite] ${message}`, data);
    } else {
      console[consoleMethod](`[React Security Suite] ${message}`);
    }
  }
  
  // Store log
  logs.unshift(logEntry);
  
  // Trim logs if needed
  if (logs.length > config.maxLogs) {
    logs = logs.slice(0, config.maxLogs);
  }
  
  // Save to storage if enabled
  if (config.logToStorage) {
    saveLogsToStorage();
  }
}

/**
 * Save logs to storage
 */
function saveLogsToStorage() {
  try {
    chrome.storage.local.set({ reactSecuritySuiteLogs: logs });
  } catch (e) {
    // Ignore storage errors
    console.error('Error saving logs to storage:', e);
  }
}

/**
 * Load logs from storage
 * @returns {Promise<Array>} The loaded logs
 */
export async function loadLogsFromStorage() {
  return new Promise((resolve) => {
    try {
      chrome.storage.local.get(['reactSecuritySuiteLogs'], (result) => {
        if (result.reactSecuritySuiteLogs) {
          logs = result.reactSecuritySuiteLogs;
        }
        resolve(logs);
      });
    } catch (e) {
      console.error('Error loading logs from storage:', e);
      resolve(logs);
    }
  });
}

/**
 * Get all logs
 * @returns {Array} The logs
 */
export function getLogs() {
  return [...logs];
}

/**
 * Clear all logs
 */
export function clearLogs() {
  logs = [];
  
  // Clear from storage if enabled
  if (config.logToStorage) {
    try {
      chrome.storage.local.remove(['reactSecuritySuiteLogs']);
    } catch (e) {
      // Ignore storage errors
      console.error('Error clearing logs from storage:', e);
    }
  }
}

/**
 * Format a log entry for display
 * @param {Object} log - The log entry
 * @returns {string} Formatted log entry
 */
export function formatLogEntry(log) {
  const time = new Date(log.timestamp).toLocaleTimeString();
  let result = `[${time}] [${log.type.toUpperCase()}] ${log.message}`;
  
  if (log.data) {
    try {
      const dataStr = typeof log.data === 'string' ? log.data : JSON.stringify(log.data);
      result += `\n${dataStr}`;
    } catch (e) {
      result += '\n[Data could not be stringified]';
    }
  }
  
  return result;
}

/**
 * Get logs by type
 * @param {string} type - The log type to filter by
 * @returns {Array} Filtered logs
 */
export function getLogsByType(type) {
  return logs.filter(log => log.type === type);
}

/**
 * Get logs by level
 * @param {number} level - The minimum log level
 * @returns {Array} Filtered logs
 */
export function getLogsByLevel(level) {
  const levelMap = {
    'debug': LogLevel.DEBUG,
    'info': LogLevel.INFO,
    'warn': LogLevel.WARN,
    'error': LogLevel.ERROR,
    'security': LogLevel.WARN
  };
  
  return logs.filter(log => levelMap[log.type] >= level);
}

// Initialize by loading logs from storage
loadLogsFromStorage().catch(e => {
  console.error('Error initializing logger:', e);
});
