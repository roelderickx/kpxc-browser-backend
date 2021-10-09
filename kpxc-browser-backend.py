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
import nacl.utils
from nacl.public import PublicKey, PrivateKey, Box
# KeePassXC libraries
from pykeepass import PyKeePass
import uuid
from urllib.parse import urlparse

SOCKET_NAME = 'kpxc_server'
SOCKET_TIMEOUT = 60
BUFF_SIZE = 4096
KEEPASSXC_VERSION = '2.6.6'

class KeePassDatabase:
    def __init__(self):
        self.kpdb = PyKeePass('test/development.kdbx', password='12345')


    def get_hash(self):
        return self.kpdb.kdbx['body'].sha256.hex() # hex() requires python >= 3.5


    def get_name(self):
        return self.kpdb.filename


    def get_logins(self, base_url):
        entries = self.kpdb.find_entries(url=base_url)
        
        return_list = []
        for entry in entries:
            login = { 'login': entry.username, \
                      'name': entry.title, \
                      'password': entry.password }
            if entry.expired:
                login['expired'] = 'true'
            return_list.append(login)
        return return_list


    def set_login(self, group_uuid, title, username, password, url):
        group = self.kpdb.root_group
        if group_uuid:
            group = self.kpdb.find_groups(uuid=uuid.UUID(group_uuid))

        # always update existing records
        entries = self.kpdb.find_entries(title=title)
        if len(entries) > 0:
            self.kpdb.delete_entry(entries[0])
        
        self.kpdb.add_entry(group, title, username, password, url=url, icon='0')
        self.kpdb.save()

        return [ { 'login': username, \
                   'name': title, \
                   'password': password } ]


    def get_root_group(self):
        return self.kpdb.root_group


    def get_database_groups(self, group):
        return_groups = { 'name': group.name, \
                          'uuid': group.uuid.hex, \
                          'children': [ self.get_database_groups(g) for g in group.subgroups ]
                        }
        return return_groups



class NativeMessagingClient:
    def __init__(self, client_id, database):
        self.remote_public_key = None
        self.encryption_box = None

        self.client_id = client_id

        self.database = database
        self.associated_id_key = None
        self.associated_name = None


    def __log_json_message(self, prefix, message):
        current_time = time.localtime()
        sys.stderr.write(time.strftime('%Y-%m-%d %H:%M:%S\n', current_time))
        for k, v in message.items():
            sys.stderr.write('%s %s: %s\n' % (prefix, k, v))


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
        encrypted_msg = base64.b64decode(message['nonce'] + message['message'])
        decrypted_msg = self.encryption_box.decrypt(encrypted_msg)
        json_decrypted_msg = json.loads(decrypted_msg)
        self.__log_json_message('DECRYPTED IN', json_decrypted_msg)

        return json_decrypted_msg


    def __get_encrypted_response(self, response, return_nonce):
        self.__log_json_message('DECRYPTED OUT', response)
        flat_response = json.dumps(response).encode('utf-8')
        encrypted_response = self.encryption_box.encrypt(flat_response, return_nonce)

        return encrypted_response[Box.NONCE_SIZE:]


    def __change_public_keys(self, message):
        self.remote_public_key = base64.b64decode(message['publicKey'])

        # generate our encryption keys
        private_key = PrivateKey.generate()
        self.encryption_box = Box(private_key, PublicKey(self.remote_public_key))

        response = { 'action': 'change-public-keys', \
                     'version': KEEPASSXC_VERSION, \
                     'publicKey': base64.b64encode(bytes(private_key.public_key)).decode('utf-8'), \
                     'success': 'true' }
        return response


    def __get_databasehash(self, message):
        decrypted_msg = self.__get_decrypted_message(message)

        response = { 'action': 'hash', \
                     'version': KEEPASSXC_VERSION, \
                     'hash': self.database.get_hash(), \
                     'success': 'true' }
        return response


    def __test_associate(self, message):
        decrypted_msg = self.__get_decrypted_message(message)

        response = None        
        if self.associated_name and \
           decrypted_msg['id'] == self.associated_name and \
           decrypted_msg['key'] == self.associated_id_key:
            response = { 'action': 'test-associate', \
                         'version': KEEPASSXC_VERSION, \
                         'hash': self.database.get_hash(), \
                         'id': self.associated_name, \
                         'success': 'true' }
        else:
            response = { 'action': 'test-associate', \
                         'version': KEEPASSXC_VERSION, \
                         'errorCode': 8, \
                         'error': 'Database not associated', \
                         'success': 'false' }
        return response


    def __associate(self, message):
        decrypted_msg = self.__get_decrypted_message(message)
        
        response = None
        if base64.b64decode(decrypted_msg['key']) == self.remote_public_key:
            self.associated_id_key = decrypted_msg['idKey']
            self.associated_name = self.database.get_name()

            response = { 'action': 'associate', \
                         'version': KEEPASSXC_VERSION, \
                         'hash': self.database.get_hash(), \
                         'id': self.associated_name, \
                         'success': 'true' }
        else:
            response = { 'action': 'associate', \
                         'version': KEEPASSXC_VERSION, \
                         'errorCode': 8, \
                         'error': 'Database not associated', \
                         'success': 'false' }
        return response


    def __generate_password(self, message):
        # TODO implement real password generation based on parameters
        # length, upper/lower, numeric, special characters
        generated_login = 1
        generated_password = 'qwerty12345'
        response = { 'action': 'generate-password', \
                     'version': KEEPASSXC_VERSION, \
                     'entries': [ { 'login': generated_login, 'password': generated_password } ], \
                     'success': 'true' }
        return response


    def __get_logins(self, message):
        decrypted_msg = self.__get_decrypted_message(message)
        
        response = None
        if decrypted_msg['keys'][0]['key'] == self.associated_id_key:
            base_url = decrypted_msg['url']
            qmark_pos = base_url.find('?')
            if qmark_pos > 0:
                base_url = base_url[:qmark_pos]

            logins = self.database.get_logins(base_url)

            if len(logins) == 0:
                response = { 'action': 'get-logins', \
                             'version': KEEPASSXC_VERSION, \
                             'errorCode': 15, \
                             'error': 'No logins found', \
                             'success': 'true' }
            else:
                response = { 'action': 'get-logins', \
                             'version': KEEPASSXC_VERSION, \
                             'hash': self.database.get_hash(), \
                             'count': len(logins), \
                             'entries': logins, \
                             'success': 'true' }
        else:
            response = { 'action': 'associate', \
                         'version': KEEPASSXC_VERSION, \
                         'errorCode': 8, \
                         'error': 'Database not associated', \
                         'success': 'false' }
        return response


    def __set_login(self, message):
        decrypted_msg = self.__get_decrypted_message(message)
        
        group_uuid = decrypted_msg['groupUuid'] if 'groupUuid' in decrypted_msg else None
        title = urlparse(decrypted_msg['url']).netloc
        logins = self.database.set_login(group_uuid, \
                                         title, \
                                         decrypted_msg['login'], \
                                         decrypted_msg['password'], \
                                         decrypted_msg['url'])

        if len(logins) == 0:
            response = { 'action': 'set-login', \
                         'version': KEEPASSXC_VERSION, \
                         'errorCode': 6, \
                         'error': 'Login could not be saved', \
                         'success': 'true' }
        else:
            response = { 'action': 'set-login', \
                     'version': KEEPASSXC_VERSION, \
                     'hash': self.database.get_hash(), \
                     'count': len(logins), \
                     'entries': logins, \
                     'error': '', \
                     'success': 'true' }
        return response


    def __get_database_groups(self, message):
        decrypted_msg = self.__get_decrypted_message(message)

        root_group = self.database.get_root_group()
        groups = self.database.get_database_groups(root_group)
        response = { 'action': 'get-database-groups', \
                     'version': KEEPASSXC_VERSION, \
                     'defaultGroup': root_group.name, \
                     'defaultGroupAlwaysAllow': 'false', \
                     'groups': groups, \
                     'success': 'true' }
        return response


    def __lock_database(self, message):
        decrypted_msg = self.__get_decrypted_message(message)

        response = { 'action': 'lock-database', \
                     'version': KEEPASSXC_VERSION, \
                     'errorCode': 1, \
                     'error': 'Database not opened', \
                     'success': 'false' }
        return response


    def process_message(self, message):
        self.__log_json_message('IN', message)
        nonce = base64.b64decode(message['nonce'])
        return_nonce = self.__get_incremented_nonce(nonce)
        
        response = None
        if message['action'] == 'change-public-keys':
            response = self.__change_public_keys(message)
        elif message['action'] == 'get-databasehash':
            response = self.__get_databasehash(message)
        elif message['action'] == 'test-associate':
            response = self.__test_associate(message)
        elif message['action'] == 'associate':
            response = self.__associate(message)
        elif message['action'] == 'generate-password':
            response = self.__generate_password(message)
        elif message['action'] == 'get-logins':
            response = self.__get_logins(message)
        elif message['action'] == 'set-login':
            response = self.__set_login(message)
        elif message['action'] == 'get-database-groups':
            response = self.__get_database_groups(message)
        elif message['action'] == 'lock-database':
            response = self.__lock_database(message)
        elif message['action'] == '__database-locked':
            pass # this is a reply but we can ignore the message
        elif message['action'] == '__database-unlocked':
            pass # this is a reply but we can ignore the message
        else:
            # TODO
            # create-new-group
            # get-totp
            sys.stderr.write('UNKNOWN MESSAGE\n')

        # sign the response - this seems necessary for encrypted messages too
        response['nonce'] = base64.b64encode(return_nonce).decode('utf-8')
        response['clientID'] = self.client_id

        # encrypt the response if required and sign again
        if message['action'] != 'change-public-keys':
            encrypted_response = self.__get_encrypted_response(response, return_nonce)
            response = { 'action': message['action'], \
                         'message': base64.b64encode(encrypted_response).decode('utf-8'), \
                         'nonce': base64.b64encode(return_nonce).decode('utf-8'), \
                         'clientID': self.client_id }

        self.__log_json_message('OUT', response)

        # return the response
        flat_response = json.dumps(response).encode('utf-8')
        return flat_response


    def __database_locked(self):
        response = { 'action': 'database-locked', \
                     'version': KEEPASSXC_VERSION }
        return response


    def __database_unlocked(self):
        response = { 'action': 'database-unlocked', \
                     'version': KEEPASSXC_VERSION }
        return response


    def send_message(self, action, client_id):
        nonce = nacl.utils.random(Box.NONCE_SIZE)
        #return_nonce = self.__get_incremented_nonce(nonce)
        
        message = None
        if action == 'database-locked':
            message = self.__database_locked()
        elif action == 'database-unlocked':
            message = self.__database_unlocked()
        else:
            sys.stderr.write('UNKNOWN MESSAGE\n')

        # sign the response - this seems necessary for encrypted messages too
        message['nonce'] = base64.b64encode(nonce).decode('utf-8')
        message['clientID'] = self.client_id

        # encrypt the response if required and sign again
        encrypted_message = self.__get_encrypted_response(message, nonce)
        message = { 'action': message['action'], \
                    'message': base64.b64encode(encrypted_message).decode('utf-8'), \
                    'nonce': base64.b64encode(nonce).decode('utf-8'), \
                    'clientID': self.client_id }

        self.__log_json_message('OUT', message)

        # return the response
        flat_message = json.dumps(message).encode('utf-8')
        return flat_message



class UnixSocketDaemon:
    def __init__(self, database):
        self.message_thread = None
        self.process_thread = None
        self.sock = None
        self.queue = queue.Queue()

        self.database = database
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
            self.message_clients[client_id] = NativeMessagingClient(client_id, self.database)

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
                    
                    #if json_message['action'] == 'get-databasehash':
                    #    message = message_client.send_message('database-unlocked', client_id)
                    #    connection.sendall(message)
                else:
                    break
        finally:
            connection.close()


    def start(self):
        # 01 open the unix socket
        self.__open_unix_server_socket()
        
        # 02 accept connections; read and process messages
        while True:
            connection, client_address = self.sock.accept()

            thread = threading.Thread(target=self.__process_connection, args=(connection, ))
            thread.daemon = True
            thread.start()


    def shutdown(self):
        if self.sock:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()


# create a permanent connection to a keepass database for testing purposes
database = KeePassDatabase()

# start a daemon listening on the unix socket
daemon = UnixSocketDaemon(database)
try:
    daemon.start()
finally:
    daemon.shutdown()

