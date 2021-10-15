#!/usr/bin/python

# -*- coding: utf-8 -*-

import sys
import os
import platform
import socket
import time
import threading
import queue
import json
import base64
from nacl.public import PublicKey, PrivateKey, Box
import string
import secrets
# KeePassXC libraries
from pykeepass import PyKeePass
import uuid as uuidlib
from urllib.parse import urlparse
import re

SOCKET_NAME = 'org.keepassxc.KeePassXC.BrowserServer'
SOCKET_TIMEOUT = 60
BUFF_SIZE = 4096

GEN_PASSWORD_LENGTH = 32
GEN_PASSWORD_UPPER_LOWER = True
GEN_PASSWORD_NUMERIC = True
GEN_PASSWORD_SPECIAL = True

KEEPASSXC_VERSION = '2.6.6'
KEEPASS_TRUE_STR = 'true'
KEEPASS_FALSE_STR = 'false'
ERROR_KEEPASS_DATABASE_NOT_OPENED = 1
ERROR_KEEPASS_DATABASE_HASH_NOT_RECEIVED = 2
ERROR_KEEPASS_CLIENT_PUBLIC_KEY_NOT_RECEIVED = 3
ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE = 4
ERROR_KEEPASS_TIMEOUT_OR_NOT_CONNECTED = 5
ERROR_KEEPASS_ACTION_CANCELLED_OR_DENIED = 6
ERROR_KEEPASS_CANNOT_ENCRYPT_MESSAGE = 7
ERROR_KEEPASS_ASSOCIATION_FAILED = 8
ERROR_KEEPASS_KEY_CHANGE_FAILED = 9
ERROR_KEEPASS_ENCRYPTION_KEY_UNRECOGNIZED = 10
ERROR_KEEPASS_NO_SAVED_DATABASES_FOUND = 11
ERROR_KEEPASS_INCORRECT_ACTION = 12
ERROR_KEEPASS_EMPTY_MESSAGE_RECEIVED = 13
ERROR_KEEPASS_NO_URL_PROVIDED = 14
ERROR_KEEPASS_NO_LOGINS_FOUND = 15
ERROR_KEEPASS_NO_GROUPS_FOUND = 16
ERROR_KEEPASS_CANNOT_CREATE_NEW_GROUP = 17
ERROR_KEEPASS_NO_VALID_UUID_PROVIDED = 18


class KeePassDatabase:
    # TODO locked means no action is possible

    def __init__(self):
        self.kpdb = PyKeePass('test/development.kdbx', password='12345')
        self.is_locked = True
        self.lock_status_event_handler = None


    def get_hash(self):
        return self.kpdb.kdbx['body'].sha256.hex() # hex() requires python >= 3.5


    def get_name(self):
        return self.kpdb.filename


    def add_lock_status_event_handler(self, lock_status_event_handler):
        self.lock_status_event_handler = lock_status_event_handler


    def __notify_lock_status(self, is_locked):
        if self.lock_status_event_handler:
            self.lock_status_event_handler(is_locked)


    def lock_database(self):
        if not self.is_locked:
            self.is_locked = True
            self.__notify_lock_status(self.is_locked)


    def open_database(self, trigger_unlock):
        if self.is_locked:
            if trigger_unlock:
                # TODO user action is required here
                pass
            self.is_locked = False
            self.__notify_lock_status(self.is_locked)
            # TODO return True if the user unlocked the database
            return True
        else:
            return True


    def __entry_matches(self, entry, site_url, form_url):
        # Use this special scheme to find entries by UUID
        if site_url.startswith('keepassxc://by-uuid/'):
            return site_url.endswith('by-uuid/' + entry.uuid.hex)
        elif site_url.startswith('keepassxc://by-path/'):
            return site_url.endswith('by-path/' + '/'.join(entry.path))
        elif not entry.url:
            return False
        elif site_url.startswith('file://'):
            return entry.url == form_url
        else:
            if '://' in entry.url:
                entry_url = urlparse(entry.url)
            elif entry.url.startswith('//'):
                entry_url = urlparse(entry.url)
                entry_url = entry_url._replace(scheme='https')
            else:
                entry_url = urlparse('//' + entry.url)
                entry_url = entry_url._replace(scheme='https')

            if not entry_url.netloc:
                return False

            parsed_site_url = urlparse(site_url)

            # match port
            if parsed_site_url.port and parsed_site_url.port != entry_url.port:
                return False

            # match scheme
            if entry_url.scheme and parsed_site_url.scheme != entry_url.scheme:
                return False

            # check for illegal characters
            regexp = re.compile('[<>\\^`{|}]')
            if regexp.match(entry.url):
                return False

            # match base domain
            if parsed_site_url.netloc != entry_url.netloc:
                return False

            # match subdomain with limited wildcard
            if parsed_site_url.netloc.endswith(entry_url.netloc):
                return True

            return False


    def get_logins(self, site_url, form_url, http_auth):
        entries = []

        '''
        for group in self.kpdb.groups:
            # exclude groups which are recycled (?) or for wich resolve searching is disabled (?)
            for entry in group.entries:
                # exclude entries which are recycled (?)
        '''
        for entry in self.kpdb.entries:
            if self.__entry_matches(entry, site_url, form_url):
                login = {}
                login['uuid'] = entry.uuid.hex
                login['login'] = entry.username
                login['name'] = '/'.join(entry.path)
                login['password'] = entry.password
                login['group'] = entry.group.name
                if entry.expired:
                    login['expired'] = KEEPASS_TRUE_STR
                # TODO aren't totp and skipAutoSubmit available in entry?
                entries.append(login)

        return entries


    def add_login(self, group_uuid, group, title, username, password, url):
        # TODO create group if necessary?
        grp = self.kpdb.root_group
        if group_uuid:
            grp = self.kpdb.find_groups(uuid=uuidlib.UUID(group_uuid))

        self.kpdb.add_entry(grp, title, username, password, url=url, icon='0')

        try:
            self.kpdb.save()
            return True
        except:
            return False


    def update_login(self, uuid, title, username, password, url):
        existing_entry = self.kpdb.find_entries(uuid=uuidlib.UUID(uuid), first=True)
        if not existing_entry:
            return False

        existing_entry.title = title
        existing_entry.username = username
        existing_entry.password = password
        existing_entry.url = url

        try:
            self.kpdb.save()
            return True
        except:
            return False


    def get_root_group(self):
        return self.kpdb.root_group


    def get_database_groups(self, group):
        return_groups = { 'name': group.name, \
                          'uuid': group.uuid.hex, \
                          'children': [ self.get_database_groups(g) for g in group.subgroups ]
                        }
        return return_groups


    def create_group(self, groupname):
        group_path = groupname.split('/')

        # create recursive
        is_dirty = False
        sub_group = None
        for sub_group_path in [ group_path[:index+1] for (index, g) in enumerate(group_path) ]:
            group = self.kpdb.find_groups(path=sub_group_path[:-1])
            sub_group = self.kpdb.find_groups(path=sub_group_path)

            if sub_group is None:
                sub_group = self.kpdb.add_group(group, sub_group_path[-1])
                is_dirty = True

        if is_dirty:
            self.kpdb.save()

        return_group = { 'name': sub_group.name, \
                         'uuid': sub_group.uuid.hex }
        return return_group


    # https://github.com/fopina/kdbxpasswordpwned
    def check_hash(password):
        password = password.encode('utf-8')
        h = hashlib.sha1(password).hexdigest().upper()
        hh = h[5:]
        for l in requests.get('https://api.pwnedpasswords.com/range/' + h[:5]).content.decode().splitlines():
            ll = l.split(':')
            if hh == ll[0]:
                return int(ll[1])
        return 0



class KeePassXCBrowserClient:
    def __init__(self, client_id, database):
        self.remote_public_key = None
        self.encryption_box = None

        self.client_id = client_id

        # TODO in theory it should be possible to connect to more than 1 database
        self.database = database
        self.associated_id_key = None
        self.associated_name = None


    def __log_json_message(self, prefix, message):
        current_time = time.localtime()
        print(time.strftime('%Y-%m-%d %H:%M:%S', current_time), end='')
        for k, v in message.items():
            if k == 'action':
                print(' %s %s: %s' % (prefix, k, v))


    def __get_incremented_nonce(self, nonce):
        next_nonce = list(nonce)
        assert(isinstance(nonce, bytes))

        c_state = 1
        for i, x in enumerate(next_nonce):
            c_state += x
            c_state %= 256
            next_nonce[i] = c_state
            c_state >>= 8

        return bytes(next_nonce)


    def __get_decrypted_message(self, message):
        try:
            encrypted_msg = base64.b64decode(message['nonce'] + message['message'])
            decrypted_msg = self.encryption_box.decrypt(encrypted_msg)
            json_decrypted_msg = json.loads(decrypted_msg)
            return json_decrypted_msg
        except:
            return None


    def __get_encrypted_response(self, response, return_nonce):
        try:
            flat_response = json.dumps(response).encode('utf-8')
            encrypted_response = self.encryption_box.encrypt(flat_response, return_nonce)
            return encrypted_response[Box.NONCE_SIZE:]
        except:
            return None


    def __get_error_message(self, error_code):
        if error_code == ERROR_KEEPASS_DATABASE_NOT_OPENED:
            return 'Database not opened'
        elif error_code == ERROR_KEEPASS_DATABASE_HASH_NOT_RECEIVED:
            return 'Database hash not available'
        elif error_code == ERROR_KEEPASS_CLIENT_PUBLIC_KEY_NOT_RECEIVED:
            return 'Client public key not received'
        elif error_code == ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE:
            return 'Cannot decrypt message'
        elif error_code == ERROR_KEEPASS_ACTION_CANCELLED_OR_DENIED:
            return 'Action cancelled or denied'
        elif error_code == ERROR_KEEPASS_CANNOT_ENCRYPT_MESSAGE:
            return 'Message encryption failed.'
        elif error_code == ERROR_KEEPASS_ASSOCIATION_FAILED:
            return 'KeePassXC association failed, try again'
        elif error_code == ERROR_KEEPASS_ENCRYPTION_KEY_UNRECOGNIZED:
            return 'Encryption key is not recognized'
        elif error_code == ERROR_KEEPASS_INCORRECT_ACTION:
            return 'Incorrect action'
        elif error_code == ERROR_KEEPASS_EMPTY_MESSAGE_RECEIVED:
            return 'Empty message received'
        elif error_code == ERROR_KEEPASS_NO_URL_PROVIDED:
            return 'No URL provided'
        elif error_code == ERROR_KEEPASS_NO_LOGINS_FOUND:
            return 'No logins found'
        elif error_code == ERROR_KEEPASS_NO_GROUPS_FOUND:
            return 'No groups found'
        elif error_code == ERROR_KEEPASS_CANNOT_CREATE_NEW_GROUP:
            return 'Cannot create new group'
        elif error_code == ERROR_KEEPASS_NO_VALID_UUID_PROVIDED:
            return 'No valid UUID provided'
        else:
            return 'Unknown error'


    def __get_error_reply(self, action, error_code):
        response = {}
        response['action'] = action
        response['errorCode'] = error_code
        response['error'] = self.__get_error_message(error_code)
        return response


    def __build_message(self, nonce):
        message = {}
        message['version'] = KEEPASSXC_VERSION
        message['success'] = KEEPASS_TRUE_STR
        message['nonce'] = base64.b64encode(nonce).decode('utf-8')
        return message


    def __build_response(self, action, message, nonce):
        encrypted_response = self.__get_encrypted_response(message, nonce)

        if not encrypted_response:
            return self.__get_error_reply(action, ERROR_KEEPASS_CANNOT_ENCRYPT_MESSAGE)

        response = {}
        response['action'] = action
        response['message'] = base64.b64encode(encrypted_response).decode('utf-8')
        response['nonce'] = base64.b64encode(nonce).decode('utf-8')
        return response


    def __change_public_keys(self, action, message):
        nonce = base64.b64decode(message['nonce'] if 'nonce' in message else '')
        remote_public_key = base64.b64decode(message['publicKey'] if 'publicKey' in message else '')

        if not remote_public_key or not nonce:
            return self.__get_error_reply(action, ERROR_KEEPASS_CLIENT_PUBLIC_KEY_NOT_RECEIVED)

        self.remote_public_key = remote_public_key
        private_key = PrivateKey.generate()
        public_key = private_key.public_key

        if not private_key or not public_key:
            return self.__get_error_reply(action, ERROR_KEEPASS_ENCRYPTION_KEY_UNRECOGNIZED)

        self.encryption_box = Box(private_key, PublicKey(self.remote_public_key))

        response = self.__build_message(self.__get_incremented_nonce(nonce))
        response['action'] = action
        response['publicKey'] = base64.b64encode(bytes(public_key)).decode('utf-8')
        return response


    def __get_databasehash(self, action, message):
        decrypted_msg = self.__get_decrypted_message(message)

        if not decrypted_msg:
            return self.__get_error_reply(action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE)

        nonce = base64.b64decode(message['nonce'])

        database_hash = self.database.get_hash()
        if not database_hash:
            return self.__get_error_reply(action, ERROR_KEEPASS_DATABASE_HASH_NOT_RECEIVED)

        if action == 'get-databasehash':
            return_nonce = self.__get_incremented_nonce(nonce)
            message = self.__build_message(return_nonce)
            message['hash'] = database_hash

            if 'connectedKeys' in decrypted_msg and database_hash in decrypted_msg['connectedKeys']:
                message['oldHash'] = database_hash

            return self.__build_response(action, message, return_nonce)
        else:
            return self.__get_error_reply(action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE)


    def __test_associate(self, action, message):
        decrypted_msg = self.__get_decrypted_message(message)

        if not decrypted_msg:
            return self.__get_error_reply(action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE)

        nonce = base64.b64decode(message['nonce'])

        response_key = decrypted_msg['key'] if 'key' in decrypted_msg else None
        database_id = decrypted_msg['id'] if 'id' in decrypted_msg else None

        if not response_key or not database_id:
            return self.__get_error_reply(action, ERROR_KEEPASS_DATABASE_NOT_OPENED)
        
        if not self.associated_name or \
           database_id != self.associated_name or \
           response_key != self.associated_id_key:
            return self.__get_error_reply(action, ERROR_KEEPASS_ASSOCIATION_FAILED)
        else:
            return_nonce = self.__get_incremented_nonce(nonce)
            message = self.__build_message(return_nonce)
            message['hash'] = self.database.get_hash();
            message['id'] = self.associated_name;
            return self.__build_response(action, message, return_nonce)


    def __associate(self, action, message):
        decrypted_msg = self.__get_decrypted_message(message)

        if not decrypted_msg:
            return self.__get_error_reply(action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE)

        nonce = base64.b64decode(message['nonce'])

        key = decrypted_msg['key'] if 'key' in decrypted_msg else None
        if not key:
            return self.__get_error_reply(action, ERROR_KEEPASS_ASSOCIATION_FAILED)

        response = None
        if base64.b64decode(key) == self.remote_public_key:
            self.associated_id_key = decrypted_msg['idKey']
            self.associated_name = self.database.get_name() # TODO ask user via pop-up window

            if not self.associated_name:
                return self.__get_error_reply(action, ERROR_KEEPASS_ACTION_CANCELLED_OR_DENIED)

            return_nonce = self.__get_incremented_nonce(nonce)
            message = self.__build_message(return_nonce)
            message['hash'] = self.database.get_hash();
            message['id'] = self.associated_name;
            return self.__build_response(action, message, return_nonce)
        else:
            return self.__get_error_reply(action, ERROR_KEEPASS_ASSOCIATION_FAILED)


    def __generate_password(self, action, message):
        nonce = base64.b64decode(message['nonce'])

        alphabet = string.ascii_lowercase
        if GEN_PASSWORD_UPPER_LOWER:
            alphabet += string.ascii_uppercase
        if GEN_PASSWORD_NUMERIC:
            alphabet += string.digits
        if GEN_PASSWORD_SPECIAL:
            alphabet += string.punctuation

        generated_login = 1 # TODO should be entropy for backwards compatibility
        generated_password = ''.join(secrets.choice(alphabet) for i in range(GEN_PASSWORD_LENGTH))

        return_nonce = self.__get_incremented_nonce(nonce)
        message = self.__build_message(return_nonce)
        message['entries'] = [ { 'login': generated_login, 'password': generated_password } ]
        return self.__build_response(action, message, return_nonce)


    def __get_logins(self, action, message):
        if not self.associated_id_key or not self.associated_name:
            return self.__get_error_reply(action, ERROR_KEEPASS_ASSOCIATION_FAILED)

        decrypted_msg = self.__get_decrypted_message(message)

        if not decrypted_msg:
            return self.__get_error_reply(action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE)
        
        nonce = base64.b64decode(message['nonce'])

        site_url = decrypted_msg['url'] if 'url' in decrypted_msg else None

        if not site_url:
            return self.__get_error_reply(action, ERROR_KEEPASS_NO_URL_PROVIDED)

        '''keys = decrypted_msg['keys'] if 'keys' in decrypted_msg else None
        key_list = {}
        for key in keys:
            key_id = key['id'] if 'id' in decrypted_msg else None
            key_key = key['key'] if 'key' in decrypted_msg else None
            if key_id and key_key:
                key_list[key_id] = key_key'''

        database_id = decrypted_msg['id'] if 'id' in decrypted_msg else None
        form_url = decrypted_msg['submitUrl'] if 'submitUrl' in decrypted_msg else None
        auth = decrypted_msg['httpAuth'] if 'httpAuth' in decrypted_msg else None
        http_auth = auth == KEEPASS_TRUE_STR

        if database_id == self.associated_name:
            logins = self.database.get_logins(site_url, form_url, auth)

            if len(logins) == 0:
                return self.__get_error_reply(action, ERROR_KEEPASS_NO_LOGINS_FOUND)
            else:
                return_nonce = self.__get_incremented_nonce(nonce)
                message = self.__build_message(return_nonce)
                message['count'] = len(logins)
                message['entries'] = logins
                message['hash'] = self.database.get_hash()
                message['id'] = self.associated_name
                return self.__build_response(action, message, return_nonce)
        else:
            return self.__get_error_reply(action, ERROR_KEEPASS_NO_LOGINS_FOUND)


    def __set_login(self, action, message):
        if not self.associated_id_key or not self.associated_name:
            return self.__get_error_reply(action, ERROR_KEEPASS_ASSOCIATION_FAILED)

        decrypted_msg = self.__get_decrypted_message(message)

        if not decrypted_msg:
            return self.__get_error_reply(action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE)
        
        nonce = base64.b64decode(message['nonce'])

        url = decrypted_msg['url'] if 'url' in decrypted_msg else None

        if not url:
            return self.__get_error_reply(action, ERROR_KEEPASS_NO_URL_PROVIDED)
        
        database_id = decrypted_msg['id'] if 'id' in decrypted_msg else None
        uuid = decrypted_msg['uuid'] if 'uuid' in decrypted_msg else None
        title = urlparse(url).netloc
        username = decrypted_msg['login'] if 'login' in decrypted_msg else None
        password = decrypted_msg['password'] if 'password' in decrypted_msg else None
        submit_url = decrypted_msg['submitUrl'] if 'submitUrl' in decrypted_msg else None
        group_uuid = decrypted_msg['groupUuid'] if 'groupUuid' in decrypted_msg else None
        group = decrypted_msg['group'] if 'group' in decrypted_msg else None

        result = False
        if uuid:
            result = self.database.update_login(uuid, title, username, password, url)
        else:
            result = self.database.add_login(group_uuid, group, title, username, password, url)

        return_nonce = self.__get_incremented_nonce(nonce)
        message = self.__build_message(return_nonce)
        message['count'] = None
        message['entries'] = None
        message['error'] = 'success' if result else 'error'
        message['hash'] = self.database.get_hash()
        return self.__build_response(action, message, return_nonce)


    def __get_database_groups(self, action, message):
        if not self.associated_id_key or not self.associated_name:
            return self.__get_error_reply(action, ERROR_KEEPASS_ASSOCIATION_FAILED)

        decrypted_msg = self.__get_decrypted_message(message)

        if not decrypted_msg:
            return self.__get_error_reply(action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE)

        nonce = base64.b64decode(message['nonce'])

        action = decrypted_msg['action']
        if not action or action != 'get-database-groups':
            return self.__get_error_reply(action, ERROR_KEEPASS_INCORRECT_ACTION)

        root_group = self.database.get_root_group()
        groups = self.database.get_database_groups(root_group)

        if len(groups) == 0:
            return self.__get_error_reply(action, ERROR_KEEPASS_NO_GROUPS_FOUND)

        return_nonce = self.__get_incremented_nonce(nonce)
        message = self.__build_message(return_nonce)
        message['groups'] = groups
        return self.__build_response(action, message, return_nonce)


    def __create_new_group(self, action, message):
        if not self.associated_id_key or not self.associated_name:
            return self.__get_error_reply(action, ERROR_KEEPASS_ASSOCIATION_FAILED)

        decrypted_msg = self.__get_decrypted_message(message)

        if not decrypted_msg:
            return self.__get_error_reply(action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE)

        nonce = base64.b64decode(message['nonce'])

        action = decrypted_msg['action']
        if not action or action != 'create-new-group':
            return self.__get_error_reply(action, ERROR_KEEPASS_INCORRECT_ACTION)

        group_name = decrypted_msg['groupName'] if 'groupName' in decrypted_msg else None
        new_group = self.database.create_group(group_name)

        if not newGroup or \
           'name' not in new_group or not new_group['name'] or \
           'uuid' not in new_group or not new_group['uuid']:
            return self.__get_error_reply(action, ERROR_KEEPASS_CANNOT_CREATE_NEW_GROUP);

        return_nonce = self.__get_incremented_nonce(nonce)
        message = self.__build_message(return_nonce)
        message.update(groups)
        return self.__build_response(action, message, return_nonce)


    def __lock_database(self, action, message):
        database_hash = self.database.get_hash()
        if not database_hash:
            return self.__get_error_reply(action, ERROR_KEEPASS_DATABASE_HASH_NOT_RECEIVED)

        decrypted_msg = self.__get_decrypted_message(message)

        if not decrypted_msg:
            return self.__get_error_reply(action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE)

        nonce = base64.b64decode(message['nonce'])

        action = decrypted_msg['action']
        if not action or action != 'lock-database':
            return self.__get_error_reply(action, ERROR_KEEPASS_INCORRECT_ACTION)

        self.database.lock_database()

        return_nonce = self.__get_incremented_nonce(nonce)
        message = self.__build_message(return_nonce)
        return self.__build_response(action, message, return_nonce)


    def process_message(self, message):
        if not message:
            return self.__get_error_reply(action, ERROR_KEEPASS_EMPTY_MESSAGE_RECEIVED)

        self.__log_json_message('IN', message)
        action = message['action'] if 'action' in message else None

        if not action:
            return self.__get_error_reply(action, ERROR_KEEPASS_INCORRECT_ACTION)
        elif action != 'change-public-keys' and 'triggerUnlock' in message:
            trigger_unlock = message['triggerUnlock'] == KEEPASS_TRUE_STR
            if trigger_unlock:
                if not self.remote_public_key:
                    return self.__get_error_reply(action, ERROR_KEEPASS_CLIENT_PUBLIC_KEY_NOT_RECEIVED)
                elif not self.database.open_database(trigger_unlock):
                    return self.__get_error_reply(action, ERROR_KEEPASS_DATABASE_NOT_OPENED)

        response = None
        if action == 'change-public-keys':
            response = self.__change_public_keys(action, message)
        elif action == 'get-databasehash':
            response = self.__get_databasehash(action, message)
        elif action == 'test-associate':
            response = self.__test_associate(action, message)
        elif action == 'associate':
            response = self.__associate(action, message)
        elif action == 'generate-password':
            response = self.__generate_password(action, message)
        elif action == 'get-logins':
            response = self.__get_logins(action, message)
        elif action == 'set-login':
            response = self.__set_login(action, message)
        elif action == 'get-database-groups':
            response = self.__get_database_groups(action, message)
        elif action == 'create-new-group':
            response = self.__create_new_group(action, message)
        elif action == 'lock-database':
            response = self.__lock_database(action, message)
        else:
            # TODO
            # get-totp
            # delete-entry (undocumented)
            return self.__get_error_reply(action, ERROR_KEEPASS_INCORRECT_ACTION)

        self.__log_json_message('OUT', response)

        # return the response
        flat_response = json.dumps(response).encode('utf-8')
        return flat_response


    def __database_locked(self):
        response = { 'action': 'database-locked' }
        return response


    def __database_unlocked(self):
        response = { 'action': 'database-unlocked' }
        return response


    def send_message(self, action):
        message = None
        if action == 'database-locked':
            message = self.__database_locked()
        elif action == 'database-unlocked':
            message = self.__database_unlocked()
        else:
            sys.stderr.write('UNKNOWN MESSAGE\n')

        self.__log_json_message('OUT', message)

        # return the response
        flat_message = json.dumps(message).encode('utf-8')
        return flat_message



class KeePassXCBrowserDaemon:
    def __init__(self, database):
        self.message_thread = None
        self.process_thread = None
        self.sock = None
        self.queue = queue.Queue()

        self.database = database
        self.database.add_lock_status_event_handler(self.notify_database_lock_status)
        self.message_clients = {}


    def __open_unix_server_socket(self):
        # Check if macos user specific directory exists - issue 1811
        # https://github.com/keepassxreboot/keepassxc/pull/1811
        if platform.system() == "Darwin" and \
           os.path.exists(os.path.join(os.getenv('TMPDIR'), SOCKET_NAME)):
            server_address = os.path.join(os.getenv('TMPDIR'), SOCKET_NAME)
        # For systemd - check if /tmp/kpxc_server exists - if not use systemd runtime dir
        elif os.getenv('XDG_RUNTIME_DIR') is not None:
            server_address = os.path.join(os.getenv('XDG_RUNTIME_DIR'), SOCKET_NAME)
        elif os.path.exists(os.path.join('/', 'tmp', SOCKET_NAME)):
            server_address = os.path.join('/', 'tmp', SOCKET_NAME)
        else:
            raise OSError('Unknown path for keepassxc socket.')

        # Make sure the socket does not already exist
        try:
            os.unlink(server_address)
        except OSError:
            if os.path.exists(server_address):
                raise

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(str(server_address))
        self.sock.listen(1)


    def __get_message_client(self, client_id):
        # search message_client, create if not found
        if client_id not in self.message_clients:
            self.message_clients[client_id] = KeePassXCBrowserClient(client_id, self.database)

        return self.message_clients[client_id]


    def __process_connection(self, connection):
        try:
            while True:
                message = connection.recv(BUFF_SIZE)
                if message:
                    json_message = json.loads(message.decode('utf-8'))

                    client_id = json_message['clientID']
                    message_client = self.__get_message_client(client_id)
                    response = message_client.process_message(json_message)
                    connection.sendall(response)
                else:
                    break
        finally:
            connection.close()
            del self.message_clients[client_id]


    def start(self):
        # 01 open the unix socket
        self.__open_unix_server_socket()
        
        # 02 accept connections; read and process messages
        while True:
            connection, client_address = self.sock.accept()

            thread = threading.Thread(target=self.__process_connection, args=(connection, ))
            thread.daemon = True
            thread.start()


    def notify_database_lock_status(self, is_locked):
        for client_id in self.message_clients:
            if is_locked:
                self.message_clients[client_id].send_message('database-locked')
            else:
                self.message_clients[client_id].send_message('database-unlocked')


    def shutdown(self):
        if self.sock:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()


# create a permanent connection to a keepass database for testing purposes
database = KeePassDatabase()

# start a daemon listening on the unix socket
daemon = KeePassXCBrowserDaemon(database)
try:
    daemon.start()
finally:
    daemon.shutdown()

