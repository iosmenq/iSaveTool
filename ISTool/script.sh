#!/bin/bash
echo "Compiling iSaveTool..."

if [ ! -f "iSaveTool.m" ]; then
    echo "Error: iSaveTool.m not found!"
    echo "Current directory: $(pwd)"
    echo "Files in directory:"
    ls -la
    exit 1
fi

clang \
-isysroot /usr/share/SDKs/iPhoneOS.sdk \
-arch arm64 \
-miphoneos-version-min=11.0 \
-fobjc-arc \
-framework UIKit \
-framework Foundation \
-framework AVFoundation \
-framework AudioToolbox \
-framework MobileCoreServices \
-framework CoreMedia \
-framework Security \
-lsqlite3 \
iSaveTool.m \
-o iSaveTool

if [ $? -eq 0 ]; then
    echo "Compilation successful!"
    
    ldid -Sent.xml iSaveTool
    mkdir -p iSaveTool.app
    mv iSaveTool iSaveTool.app/
    cp icon.png iSaveTool.app/
    cp bg.mp3 iSaveTool.app/
    
    cat > iSaveTool.app/Info.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>en</string>
	<key>CFBundleExecutable</key>
	<string>iSaveTool</string>
	<key>CFBundleIconFiles</key>
	<array>
		<string>icon.png</string>
	</array>
	<key>CFBundleIdentifier</key>
	<string>com.isavetool.app</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>iSaveTool</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>1.118</string>
	<key>CFBundleSignature</key>
	<string>????</string>
	<key>CFBundleVersion</key>
	<string>1.118</string>
	<key>LSRequiresIPhoneOS</key>
	<true/>
	<key>MinimumOSVersion</key>
	<string>10.0</string>
	<key>UIRequiredDeviceCapabilities</key>
	<array>
		<string>arm64</string>
	</array>
	<key>UISupportedInterfaceOrientations</key>
	<array>
		<string>UIInterfaceOrientationPortrait</string>
	</array>
</dict>
</plist>

EOF
    
    chmod 755 iSaveTool.app/iSaveTool
    
    echo "Build complete! App bundle: iSaveTool.app"
    
else
    echo "Compilation failed!"
    exit 1
fi