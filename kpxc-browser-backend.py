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
import nativemessaging
from nacl.public import PublicKey, PrivateKey, Box
from keepass_database import *
import watchfiles

SOCKET_NAME = 'org.keepassxc.KeePassXC.BrowserServer'
SOCKET_TIMEOUT = 60
BUFF_SIZE = 4096

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


class KeePassXCBrowserClient:
    def __init__(self, connection, client_id, database):
        self.connection = connection
        self.message_lock = threading.Lock()

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
        
        if not self.associated_id_key or \
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
            self.associated_name = self.database.get_name()

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

        generated_login, generated_password = self.database.generate_password()

        return_nonce = self.__get_incremented_nonce(nonce)
        message = self.__build_message(return_nonce)
        message['password'] = generated_password
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
        message['groups'] = { 'groups': [ groups ] }
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

        if not new_group or \
           'name' not in new_group or not new_group['name'] or \
           'uuid' not in new_group or not new_group['uuid']:
            return self.__get_error_reply(action, ERROR_KEEPASS_CANNOT_CREATE_NEW_GROUP);

        return_nonce = self.__get_incremented_nonce(nonce)
        message = self.__build_message(return_nonce)
        message['name'] = new_group['name']
        message['uuid'] = new_group['uuid']
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


    def __get_totp(self, action, message):
        if not self.associated_id_key or not self.associated_name:
            return self.__get_error_reply(action, ERROR_KEEPASS_ASSOCIATION_FAILED)

        decrypted_msg = self.__get_decrypted_message(message)

        if not decrypted_msg:
            return self.__get_error_reply(action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE)

        nonce = base64.b64decode(message['nonce'])

        action = decrypted_msg['action']
        if not action or action != 'get-totp':
            return self.__get_error_reply(action, ERROR_KEEPASS_INCORRECT_ACTION)

        uuid = decrypted_msg['uuid'] if 'uuid' in decrypted_msg else None
        if not uuid:
            return self.__get_error_reply(action, ERROR_KEEPASS_NO_VALID_UUID_PROVIDED)

        totp = self.database.get_current_totp(uuid)

        return_nonce = self.__get_incremented_nonce(nonce)
        message = self.__build_message(return_nonce)
        message['totp'] = totp
        return self.__build_response(action, message, return_nonce)


    def __delete_entry(self, action, message):
        if not self.associated_id_key or not self.associated_name:
            return self.__get_error_reply(action, ERROR_KEEPASS_ASSOCIATION_FAILED)

        decrypted_msg = self.__get_decrypted_message(message)

        if not decrypted_msg:
            return self.__get_error_reply(action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE)

        nonce = base64.b64decode(message['nonce'])

        action = decrypted_msg['action']
        if not action or action != 'delete-entry':
            return self.__get_error_reply(action, ERROR_KEEPASS_INCORRECT_ACTION)

        uuid = decrypted_msg['uuid'] if 'uuid' in decrypted_msg else None
        if not uuid:
            return self.__get_error_reply(action, ERROR_KEEPASS_NO_VALID_UUID_PROVIDED)

        result = self.database.delete_login(uuid)

        return_nonce = self.__get_incremented_nonce(nonce)
        message = self.__build_message(return_nonce)
        message['success'] = KEEPASS_TRUE_STR if result else KEEPASS_FALSE_STR
        return self.__build_response(action, message, return_nonce)


    def __process_message(self, message):
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
        elif action == 'get-totp':
            response = self.__get_totp(action, message)
        elif action == 'delete-entry':
            # the plugin does not send this message currently but it is implemented in KeePassXC
            response = self.__delete_entry(action, message)
        else:
            return self.__get_error_reply(action, ERROR_KEEPASS_INCORRECT_ACTION)

        self.__log_json_message('OUT', response)

        return response


    def process_message(self, message):
        with self.message_lock:
            response = self.__process_message(message)
            self.connection.sendall(json.dumps(response).encode('utf-8'))


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
            return

        with self.message_lock:
            self.__log_json_message('OUT', message)
            self.connection.sendall(json.dumps(message).encode('utf-8'))



class KeePassXCBrowserDaemon:
    def __init__(self, database):
        self.message_thread = None
        self.process_thread = None
        self.sock = None
        self.queue = queue.Queue()

        self.database = database
        self.message_clients = {}
        self.shutdown_event = threading.Event()


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


    def __change_watchdog(self):
        while not self.shutdown_event.is_set():
            for changes in watchfiles.watch(self.database.database_file, \
                                            stop_event=self.shutdown_event):
                print('Password file change detected, reloading...', end='')
                self.database.reload()
                print('done')
                # Secrets seems to recreate the file, restart watching
                break


    def __get_message_client(self, connection, client_id):
        # search message_client, create if not found
        if client_id not in self.message_clients:
            self.message_clients[client_id] = \
                        KeePassXCBrowserClient(connection, client_id, self.database)

        return self.message_clients[client_id]


    def __process_connection(self, connection):
        try:
            while True:
                message = connection.recv(BUFF_SIZE)
                if message:
                    json_message = json.loads(message.decode('utf-8'))

                    client_id = json_message['clientID']
                    message_client = self.__get_message_client(connection, client_id)
                    message_client.process_message(json_message)
                else:
                    break
        finally:
            connection.close()
            del self.message_clients[client_id]


    def start(self):
        # 01 open the unix socket
        self.__open_unix_server_socket()

        # 02 listen for database changes
        thread = threading.Thread(target=self.__change_watchdog)
        thread.daemon = True
        thread.start()

        # 03 accept connections; read and process messages
        while True:
            try:
                connection, client_address = self.sock.accept()

                thread = threading.Thread(target=self.__process_connection, args=(connection, ))
                thread.daemon = True
                thread.start()
            except KeyboardInterrupt:
                self.shutdown_event.set()
                break


    def __notify_database_lock_status(self, is_locked):
        for client_id in self.message_clients:
            if is_locked:
                self.message_clients[client_id].send_message('database-locked')
            else:
                self.message_clients[client_id].send_message('database-unlocked')


    def notify_database_lock_status(self, is_locked):
        thread = threading.Thread(target=self.__notify_database_lock_status, args=(is_locked, ))
        thread.daemon = True
        thread.start()


    def shutdown(self):
        if self.sock:
            self.sock.shutdown(socket.SHUT_RDWR)


# check if proxy is installed
if len(nativemessaging.is_installed('org.keepassxc.keepassxc_browser')) == 0:
    nativemessaging.install(['firefox', 'chrome'], 'native-manifest.json')

# create a permanent connection to a keepass database for testing purposes
database = KeePassDatabase()

# start a daemon listening on the unix socket
daemon = KeePassXCBrowserDaemon(database)
database.add_lock_status_event_handler(daemon.notify_database_lock_status)
try:
    daemon.start()
finally:
    daemon.shutdown()

