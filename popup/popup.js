/**
 * React Security Suite - Popup Script
 * 
 * This script handles the popup UI interactions and communicates with the
 * background script and content script.
 */

// DOM Elements
const elements = {
  // Mode toggle
  modeSwitch: document.getElementById('mode-switch'),
  currentMode: document.getElementById('current-mode'),
  
  // Containers
  defenseContainer: document.getElementById('defense-container'),
  trainingContainer: document.getElementById('training-container'),
  vulnerabilitiesContainer: document.getElementById('vulnerabilities-container'),
  vulnerabilitiesList: document.getElementById('vulnerabilities-list'),
  safeContainer: document.getElementById('safe-container'),
  
  // Status elements
  status: document.getElementById('status'),
  protectionStatus: document.getElementById('protection-status'),
  
  // Buttons
  scanButton: document.getElementById('scan-button'),
  protectButton: document.getElementById('protect-button'),
  viewLogsButton: document.getElementById('view-logs-button'),
  clearLogsButton: document.getElementById('clear-logs-button'),
  closeLogsButton: document.getElementById('close-logs-button'),
  stopDemoButton: document.getElementById('stop-demo-button'),
  
  // Modals
  logsModal: document.getElementById('logs-modal'),
  trainingConfirmModal: document.getElementById('training-confirm-modal'),
  
  // Modal buttons
  confirmTrainingButton: document.getElementById('confirm-training-button'),
  cancelTrainingButton: document.getElementById('cancel-training-button'),
  
  // Logs
  logsContainer: document.getElementById('logs-container')
};

// Extension state
let state = {
  mode: 'defense',
  scanResults: [],
  protectionActive: false,
  trainingActive: false,
  detectedReactVersion: null,
  logs: [],
  activeTab: null
};

// Initialize popup
document.addEventListener('DOMContentLoaded', async () => {
  // Get active tab
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  state.activeTab = tabs[0];
  
  // Get extension state from background script
  chrome.runtime.sendMessage({ action: 'getState' }, (response) => {
    if (response && response.success) {
      state = { ...state, ...response.state };
      updateUI();
    }
  });
  
  // Check if protection is active on the current page
  chrome.tabs.sendMessage(state.activeTab.id, { action: 'checkProtection' }, (response) => {
    if (response && response.protected) {
      state.protectionActive = true;
      updateProtectionStatus();
    }
  });
  
  // Set up event listeners
  setupEventListeners();
  
  // Scan the page
  scanPage();
});

// Set up event listeners
function setupEventListeners() {
  // Mode toggle
  elements.modeSwitch.addEventListener('change', handleModeToggle);
  
  // Buttons
  elements.scanButton.addEventListener('click', scanPage);
  elements.protectButton.addEventListener('click', applyProtection);
  elements.viewLogsButton.addEventListener('click', showLogs);
  elements.clearLogsButton.addEventListener('click', clearLogs);
  elements.closeLogsButton.addEventListener('click', hideLogs);
  elements.stopDemoButton.addEventListener('click', stopDemonstration);
  
  // Training confirmation
  elements.confirmTrainingButton.addEventListener('click', confirmTrainingMode);
  elements.cancelTrainingButton.addEventListener('click', cancelTrainingMode);
  
  // Close modals when clicking on X
  document.querySelectorAll('.close-modal').forEach(closeBtn => {
    closeBtn.addEventListener('click', () => {
      elements.logsModal.classList.add('hidden');
      elements.trainingConfirmModal.classList.add('hidden');
    });
  });
  
  // Demo buttons
  document.querySelectorAll('.demo-button').forEach(button => {
    button.addEventListener('click', (e) => {
      const demoType = e.target.getAttribute('data-demo');
      runDemonstration(demoType);
    });
  });
}

// Handle mode toggle
function handleModeToggle() {
  const isTrainingMode = elements.modeSwitch.checked;
  
  if (isTrainingMode && !state.trainingActive) {
    // Show confirmation modal before enabling training mode
    elements.trainingConfirmModal.classList.remove('hidden');
  } else if (!isTrainingMode && state.trainingActive) {
    // Switch back to defense mode
    setMode('defense');
  }
}

// Confirm training mode
function confirmTrainingMode() {
  elements.trainingConfirmModal.classList.add('hidden');
  setMode('training');
}

// Cancel training mode
function cancelTrainingMode() {
  elements.trainingConfirmModal.classList.add('hidden');
  elements.modeSwitch.checked = false;
}

// Set mode (defense or training)
function setMode(mode) {
  // Update UI
  if (mode === 'defense') {
    elements.currentMode.textContent = 'Defense';
    elements.currentMode.style.color = 'var(--defense-color)';
    elements.modeSwitch.checked = false;
    elements.defenseContainer.classList.remove('hidden');
    elements.trainingContainer.classList.add('hidden');
  } else if (mode === 'training') {
    elements.currentMode.textContent = 'Training';
    elements.currentMode.style.color = 'var(--training-color)';
    elements.modeSwitch.checked = true;
    elements.defenseContainer.classList.add('hidden');
    elements.trainingContainer.classList.remove('hidden');
  }
  
  // Update state
  state.mode = mode;
  state.trainingActive = (mode === 'training');
  
  // Send message to background script
  chrome.runtime.sendMessage({
    action: 'setTrainingMode',
    active: state.trainingActive,
    confirmed: true
  });
  
  // Send message to content script
  chrome.tabs.sendMessage(state.activeTab.id, {
    action: 'setMode',
    mode: mode
  });
}

// Scan the page for vulnerabilities
function scanPage() {
  elements.status.textContent = 'Scanning...';
  elements.status.className = 'status';
  
  chrome.tabs.sendMessage(state.activeTab.id, { action: 'scan' }, (response) => {
    if (response && response.vulnerabilities) {
      state.scanResults = response.vulnerabilities;
      updateVulnerabilitiesUI();
    } else {
      // If no response, try to get results from background script
      chrome.runtime.sendMessage({ action: 'getState' }, (response) => {
        if (response && response.success) {
          state.scanResults = response.state.scanResults || [];
          updateVulnerabilitiesUI();
        }
      });
    }
  });
}

// Update vulnerabilities UI
function updateVulnerabilitiesUI() {
  if (state.scanResults.length > 0) {
    // Show vulnerabilities
    elements.status.textContent = `Found ${state.scanResults.length} vulnerability issues`;
    elements.status.className = 'status status-warning';
    
    // Show vulnerabilities container
    elements.vulnerabilitiesContainer.classList.remove('hidden');
    elements.safeContainer.classList.add('hidden');
    
    // Add vulnerabilities to list
    elements.vulnerabilitiesList.innerHTML = '';
    state.scanResults.forEach(vuln => {
      const li = document.createElement('li');
      li.className = `severity-${vuln.severity.toLowerCase()}`;
      li.innerHTML = `
        <span class="vuln-type">${vuln.type}</span>
        <span class="vuln-severity">${vuln.severity}</span>
        <p class="vuln-description">${vuln.description}</p>
        ${vuln.details ? `<p class="vuln-details">${vuln.details}</p>` : ''}
      `;
      elements.vulnerabilitiesList.appendChild(li);
    });
  } else {
    // Show safe message
    elements.status.textContent = 'No vulnerabilities detected';
    elements.status.className = 'status status-safe';
    elements.vulnerabilitiesContainer.classList.add('hidden');
    elements.safeContainer.classList.remove('hidden');
  }
}

// Apply protection
function applyProtection() {
  elements.protectButton.disabled = true;
  elements.protectButton.textContent = 'Applying...';
  
  chrome.tabs.sendMessage(state.activeTab.id, { action: 'applyProtection' }, (response) => {
    if (response && response.protected) {
      state.protectionActive = true;
      updateProtectionStatus();
      
      // Rescan to update vulnerabilities
      setTimeout(scanPage, 500);
    } else {
      elements.protectButton.disabled = false;
      elements.protectButton.textContent = 'Apply Protection';
    }
  });
}

// Update protection status UI
function updateProtectionStatus() {
  if (state.protectionActive) {
    elements.protectionStatus.textContent = 'Applied ✓';
    elements.protectionStatus.style.color = 'var(--success-color)';
    elements.protectButton.disabled = true;
    elements.protectButton.textContent = 'Protection Applied';
  } else {
    elements.protectionStatus.textContent = 'Not Applied';
    elements.protectionStatus.style.color = 'var(--text-color)';
    elements.protectButton.disabled = false;
    elements.protectButton.textContent = 'Apply Protection';
  }
}

// Run demonstration
function runDemonstration(demoType) {
  if (!state.trainingActive) {
    return;
  }
  
  // Disable all demo buttons
  document.querySelectorAll('.demo-button').forEach(button => {
    button.disabled = true;
  });
  
  // Enable stop button
  elements.stopDemoButton.disabled = false;
  
  // Send message to content script
  chrome.tabs.sendMessage(state.activeTab.id, {
    action: 'runDemonstration',
    attackType: demoType
  }, (response) => {
    if (!response || !response.success) {
      // Re-enable buttons if failed
      document.querySelectorAll('.demo-button').forEach(button => {
        button.disabled = false;
      });
      elements.stopDemoButton.disabled = true;
    }
  });
}

// Stop demonstration
function stopDemonstration() {
  chrome.tabs.sendMessage(state.activeTab.id, { action: 'stopDemonstration' }, () => {
    // Re-enable demo buttons
    document.querySelectorAll('.demo-button').forEach(button => {
      button.disabled = false;
    });
    elements.stopDemoButton.disabled = true;
  });
}

// Show logs modal
function showLogs() {
  // Get latest logs from background script
  chrome.runtime.sendMessage({ action: 'getState' }, (response) => {
    if (response && response.success) {
      state.logs = response.state.logs || [];
      updateLogsUI();
      elements.logsModal.classList.remove('hidden');
    }
  });
}

// Hide logs modal
function hideLogs() {
  elements.logsModal.classList.add('hidden');
}

// Clear logs
function clearLogs() {
  chrome.runtime.sendMessage({ action: 'clearLogs' }, (response) => {
    if (response && response.success) {
      state.logs = [];
      updateLogsUI();
    }
  });
}

// Update logs UI
function updateLogsUI() {
  elements.logsContainer.innerHTML = '';
  
  if (state.logs.length === 0) {
    elements.logsContainer.innerHTML = '<p>No logs available.</p>';
    return;
  }
  
  state.logs.forEach(log => {
    const logEntry = document.createElement('div');
    logEntry.className = 'log-entry';
    
    const timestamp = new Date(log.timestamp).toLocaleTimeString();
    
    logEntry.innerHTML = `
      <div>
        <span class="log-timestamp">${timestamp}</span>
        <span class="log-category log-category-${log.category}">${log.category}</span>
        <span class="log-action">${log.action}</span>
      </div>
      ${log.details ? `<div class="log-details">${formatLogDetails(log.details)}</div>` : ''}
    `;
    
    elements.logsContainer.appendChild(logEntry);
  });
}

// Format log details for display
function formatLogDetails(details) {
  if (!details) return '';
  
  let result = '';
  
  if (details.url) {
    result += `URL: ${details.url}<br>`;
  }
  
  if (details.vulnerabilitiesFound !== undefined) {
    result += `Vulnerabilities: ${details.vulnerabilitiesFound}<br>`;
  }
  
  if (details.version) {
    result += `Version: ${details.version}<br>`;
  }
  
  if (details.attackType) {
    result += `Attack Type: ${details.attackType}<br>`;
  }
  
  if (details.error) {
    result += `Error: ${details.error}<br>`;
  }
  
  return result;
}

// Update the entire UI based on current state
function updateUI() {
  // Update mode
  setMode(state.mode);
  
  // Update protection status
  updateProtectionStatus();
  
  // Update vulnerabilities
  updateVulnerabilitiesUI();
}
