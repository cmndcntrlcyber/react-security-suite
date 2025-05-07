ls
#!/bin/bash
# Package the React Security Suite extension for Firefox installation

echo "Packaging React Security Suite extension for Firefox..."

# Create a clean build directory
mkdir -p build
rm -rf build/*

# Copy necessary files
echo "Copying files..."
cp manifest.json build/
cp browser-polyfill.js build/
cp background.js build/
cp content.js build/
cp -r icons build/
cp -r popup build/
cp -r defense build/
cp -r training build/
cp -r utils build/

# Create the extension package
echo "Creating extension package..."
cd build
zip -r ../react-security-suite.xpi *
cd ..

# Check if the file was created
if [ -f "react-security-suite.xpi" ]; then
  echo "Firefox extension package created: react-security-suite.xpi"
  echo "You can install this extension in Firefox by:"
  echo "1. Going to about:debugging in Firefox"
  echo "2. Clicking on 'This Firefox'"
  echo "3. Clicking 'Load Temporary Add-on...'"
  echo "4. Selecting the react-security-suite.xpi file"
  echo ""
  echo "For permanent installation, use about:addons > Install Add-on From File..."
else
  echo "Error creating extension package."
fi
