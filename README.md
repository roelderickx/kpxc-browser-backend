# kpxc-browser-backend

A backend serving usernames and passwords from a KeePassXC database to the KeePassXC browser extension.

Note that this is a proof of concept to investigate the KeePassXC-Browser protocol, it will show passwords in a terminal window. Do not use this in a production environment.

## Development information

- Native messaging: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging
- Encryption using pyNaCl: https://pynacl.readthedocs.io/en/latest/public/
- PyKeePass documentation: https://pykeepass.readthedocs.io/en/latest/

## Installation

This is still under development. There are three components to install: the browser plugin, the native messaging proxy and the backend communicating with the proxy.

### Installing the browser plugin

This is straightforward using firefox, chrome or any chromium based browser. The extension you need is called KeePassXC-Browser.

### Installing the proxy

This script will be started by your browser when using the KeePassXC-Browser extension and provides a gateway for messages from the browser to the backend and back.

- Install nativemessaging using `pip install nativemessaging`
- Run `nativemessaging-install.py firefox`

Note that the nativemessaging package is not required for the proxy to run, you can uninstall it afterwards. An integrated solution must be implemented.

### Installing the backend

No installation is required. Just put the script anywhere, modify the KeePassXC database parameters and run it in a terminal.

