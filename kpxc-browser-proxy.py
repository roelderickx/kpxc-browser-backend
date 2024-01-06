#!/usr/bin/python

# -*- coding: utf-8 -*-

import sys
import os
import platform
import struct
import time
import threading
import queue
import socket
import json
import nativemessaging

SOCKET_NAME = 'org.keepassxc.KeePassXC.BrowserServer'
SOCKET_TIMEOUT = 60
BUFF_SIZE = 4096

class NativeMessagingDaemon:
    def __init__(self):
        self.message_thread = None
        self.queue = queue.Queue()
        self.sock = None


    def __message_reader(self):
        while True:
            try:
                text = nativemessaging.get_message()
                self.queue.put(text)
            except:
                self.queue.put(None)


    def __send_failure_native_message(self, action):
        json_response = { 'action': action, \
                          'error': 'Not connected with KeePassXC.', \
                          'errorCode': 5 }
        nativemessaging.send_message(json_response)


    def __open_unix_socket(self):
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

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(SOCKET_TIMEOUT)
        self.sock.connect(server_address)

        # On Windows, the default I/O mode is O_TEXT. Set this to O_BINARY
        # to avoid unwanted modifications of the input/output streams.
        if sys.platform == "win32":
            import msvcrt

            msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
            msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)


    def __process_messages(self):
        while not self.queue.empty():
            message = self.queue.get_nowait()
            if message == None:
                return False

            try:
                self.sock.send(json.dumps(message).encode('utf-8'))
                response = self.sock.recv(BUFF_SIZE)
                nativemessaging.send_message(json.loads(response))
            except socket.timeout:
                sys.stderr.write('ERROR: No communication to host application\n')
                self.__send_failure_native_message(json_message['action'])
                raise

        return True


    def start(self):
        # 01 create a thread to read messages and put them on the queue
        self.message_thread = threading.Thread(target = self.__message_reader)
        self.message_thread.daemon = True
        self.message_thread.start()

        # 02 open unix socket for communication with host application
        try:
            self.__open_unix_socket()
        except:
            sys.stderr.write('ERROR: socket cannot be opened\n')
            self.__send_failure_native_message('unknown')
            raise

        # 03 process messages on the queue
        while self.__process_messages():
            time.sleep(0.1)


    def shutdown(self):
        if self.sock:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()


daemon = NativeMessagingDaemon()
try:
    daemon.start()
finally:
    daemon.shutdown()

