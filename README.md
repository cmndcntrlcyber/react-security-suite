# React Security Suite

A comprehensive browser extension for React security training and defense. This extension provides both defensive capabilities to protect React applications and educational demonstrations of security vulnerabilities for training purposes.

## Features

### Defense Mode

- **Vulnerability Scanner**: Detects React security issues like exposed internals, unprotected render methods, and dangerous innerHTML usage
- **Protection Layer**: Implements safeguards against DOM manipulation attacks and monitors for suspicious activity
- **Cookie & Storage Protection**: Monitors access to cookies and local storage for potential data exfiltration
- **Network Monitoring**: Detects suspicious network requests that might indicate data exfiltration

### Training Mode

- **React Internals Demonstration**: Shows how React internals can be accessed and exploited
- **DOM Manipulation Demo**: Demonstrates how React DOM can be hijacked
- **Cookie Access Demo**: Shows how cookies could be accessed and exfiltrated
- **Persistence Techniques**: Demonstrates how attacks can persist through re-renders
- **React Hooks Exploitation**: Shows how React hooks can be exploited
- **Data Exfiltration Techniques**: Demonstrates various methods for exfiltrating data

## Installation

### Chrome

1. Clone this repository or download it as a ZIP file
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode" in the top right corner
4. Click "Load unpacked" and select the `react-security-suite` directory
5. The extension should now be installed and visible in your toolbar

### Firefox

1. Clone this repository or download it as a ZIP file
2. Open Firefox and navigate to `about:debugging#/runtime/this-firefox`
3. Click "Load Temporary Add-on..."
4. Navigate to the `react-security-suite` directory and select the `manifest.json` file
5. The extension should now be installed and visible in your toolbar

## Usage

### Defense Mode (Default)

1. Click the extension icon in your browser toolbar to open the popup
2. The extension will automatically scan the current page for React vulnerabilities
3. If vulnerabilities are found, they will be displayed in the popup
4. Click "Apply Protection" to enable protection measures
5. The extension will monitor for suspicious activity and block potential attacks

### Training Mode

1. Click the extension icon in your browser toolbar to open the popup
2. Toggle the switch at the top to "Training" mode
3. Confirm that you want to enable training mode
4. Select a demonstration from the available options
5. The demonstration will run and display educational information about the vulnerability
6. Click "Stop Demonstration" to end the demonstration

## Warning

The training demonstrations in this extension are for educational purposes only. They demonstrate security vulnerabilities in a controlled environment. Do not use these techniques on websites without proper authorization.

## Development

### Project Structure

```
react-security-suite/
├── manifest.json           # Extension configuration
├── background.js           # Background service worker
├── content.js              # Content script that runs in web pages
├── popup/                  # Extension popup UI
│   ├── popup.html          # Popup HTML
│   ├── popup.js            # Popup JavaScript
│   └── popup.css           # Popup styles
├── defense/                # Defense mode components
│   ├── scanner.js          # Vulnerability scanner
│   └── defender.js         # Protection implementation
├── training/               # Training mode components
│   ├── demonstrator.js     # Demonstration controller
│   ├── react-hooks.js      # React hooks demonstrations
│   └── exfiltration-demo.js # Data exfiltration demonstrations
├── utils/                  # Utility functions
│   ├── react-detector.js   # React detection utilities
│   └── logger.js           # Logging utilities
└── icons/                  # Extension icons
    ├── icon16.png          # 16x16 icon
    ├── icon48.png          # 48x48 icon
    └── icon128.png         # 128x128 icon
```

### Building for Production

For a production build, you may want to:

1. Minify the JavaScript files
2. Bundle the files using a tool like webpack
3. Create a ZIP file for submission to browser extension stores

Example build process:

```bash
# Install dependencies
npm install

# Build the extension
npm run build

# Create a ZIP file
npm run package
```

## Security Considerations

This extension requires broad permissions to function properly, including access to all websites and the ability to modify web page content. These permissions are necessary for the extension to detect and protect against security vulnerabilities.

The extension does not collect or transmit any data outside of your browser. All analysis and protection happens locally.

## License

MIT License

## Acknowledgements

- React and React DOM are trademarks of Meta Platforms, Inc.
- This extension is not affiliated with or endorsed by Meta Platforms, Inc.
- This extension is for educational and security research purposes only.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Contact

If you have any questions or feedback, please open an issue on GitHub.
