# kpxc-browser-backend

A backend serving usernames and passwords from a KeePassXC database to the KeePassXC browser extension.

Note that this is a proof of concept to investigate the KeePassXC-Browser protocol. The communication with the browser is feature-complete and stable, but since there is no frontend default user-interaction is assumed (eg when unlocking the database, allowing passwords to be used, etc). The master password is as such stored as plaintext in a configuration file.

## Development information

- Native messaging: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging
- Encryption using pyNaCl: https://pynacl.readthedocs.io/en/latest/public/
- PyKeePass documentation: https://pykeepass.readthedocs.io/en/latest/
- PyOTP documentation: https://pyauth.github.io/pyotp/

## Installation

There are three components to install: the browser plugin, the native messaging proxy and the backend communicating with the proxy.

### Installing the browser plugin

This is straightforward using firefox, chrome or any chromium based browser. The extension you need is called KeePassXC-Browser.

### Installing the proxy

This script will be started by your browser when using the KeePassXC-Browser extension and provides a gateway for messages from the browser to the backend and back.

You should register the proxy with your browser using the `nativemessaging-install` script provided by the nativemessaging-ng module. Run it with either firefox or chrome as parameter, depending on your browser of choice. For other browsers you have to manually investigate where to install `native-manifest.json`.

Note that you can skip this step, the backend will check if the proxy is registered and if not, it will try to install it for both firefox and chrome. All you need to do is restart the browser after running the backend for the first time.

Also note that the full path to the proxy is saved in your browser's native messaging configuration. This means that if you want to move the proxy to another location after installation you are also required to re-run `nativemessaging-install` with the appropriate parameter.

### Installing the backend

No installation is required. Just put `kpxc-browser-backend.py` and `keepass_database.py` in the same directory. Create a file named `kpxc-browser-backend.json` with your KeePassXC database parameters and run `kpxc-browser-backend.py` in a terminal.

Example KeePassXC database parameters file:
```
{ "database": "test/development.kdbx", "password": "12345" }
```
