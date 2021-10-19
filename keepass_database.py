#!/usr/bin/python

# -*- coding: utf-8 -*-

from pykeepass import PyKeePass
import uuid as uuidlib
from urllib.parse import urlparse
import json
import re
import string
import secrets
import pyotp

KEEPASS_DATABASE = 'test/development.kdbx'
KEEPASS_PASSWORD = '12345'

GEN_PASSWORD_LENGTH = 32
GEN_PASSWORD_UPPER_LOWER = True
GEN_PASSWORD_NUMERIC = True
GEN_PASSWORD_SPECIAL = True

KEEPASSXC_VERSION = '2.6.6'

KEEPASS_TRUE_STR = 'true'
KEEPASS_FALSE_STR = 'false'

KEEPASSXC_BROWSER_SETTINGS = 'KeePassXC-Browser Settings'
KEEPASS_OPTION_SKIP_AUTO_SUBMIT = 'BrowserSkipAutoSubmit'
KEEPASS_OPTION_HIDE_ENTRY = 'BrowserHideEntry'
KEEPASS_OPTION_ONLY_HTTP_AUTH = 'BrowserOnlyHttpAuth'
KEEPASS_OPTION_NOT_HTTP_AUTH = 'BrowserNotHttpAuth'
KEEPASS_ADDITIONAL_URL = 'KP2A_URL'

# extend the PyKeePass.Entry class to fetch CustomData
# https://github.com/libkeepass/pykeepass/issues/197
'''
class Entry:
    def _get_item_field(self, key):
        field = self._xpath('CustomData/Item/Key[text()="{}"]/../Value'.format(key), first=True)
        if field is not None:
            return field.text


    # does not work, field is not a child of self._element
    def _set_item_field(self, key, value):
        field = self._xpath('CustomData/Item/Key[text()="{}"]/..'.format(key), first=True)
        if field is not None:
            self._element.remove(field)
        self._element.append(E.String(E.Key(key), E.Value(value)))


    def _get_item_field_keys(self):
        items = [ x.findall('Item') for x in self._element.findall('CustomData') ][0]
        results = [ y.find('Key').text for y in items ]
        return results


    def set_custom_data(self, key, value):
        self._set_item_field(key, value)


    def get_custom_data(self, key):
        return self._get_item_field(key)


    def delete_custom_property(self, key):
        if key not in self._get_item_field_keys():
            raise AttributeError('No such key: {}'.format(key))
        prop = self._xpath('CustomData/Item/Key[text()="{}"]/..'.format(key), first=True)
        if prop is None:
            raise AttributeError('Could not find property element')
        self._element.remove(prop)


    @property
    def custom_data(self):
        keys = self._get_item_field_keys(exclude_reserved=True)
        props = {}
        for k in keys:
            props[k] = self._get_item_field(k)
        return props
'''



class KeePassDatabase:
    # TODO locked means no action is possible

    def __init__(self):
        self.kpdb = PyKeePass(KEEPASS_DATABASE, password=KEEPASS_PASSWORD)
        self.is_locked = True
        self.lock_status_event_handler = None


    def get_hash(self):
        return self.kpdb.kdbx['body'].sha256.hex() # hex() requires python >= 3.5


    def get_name(self):
        # TODO user interaction: You have received an association request.
        #                        Please enter a unique name for this connection.
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


    def open_database(self, trigger_unlock=False):
        if self.is_locked:
            if trigger_unlock:
                # TODO user interaction: Database is locked: please enter your password to unlock.
                self.is_locked = False
                self.__notify_lock_status(self.is_locked)
                return True
            else:
                return False
        else:
            return True


    def generate_password(self):
        alphabet = string.ascii_lowercase
        if GEN_PASSWORD_UPPER_LOWER:
            alphabet += string.ascii_uppercase
        if GEN_PASSWORD_NUMERIC:
            alphabet += string.digits
        if GEN_PASSWORD_SPECIAL:
            alphabet += string.punctuation

        generated_login = 1 # TODO should be entropy for backwards compatibility
        generated_password = ''.join(secrets.choice(alphabet) for i in range(GEN_PASSWORD_LENGTH))
        
        return generated_login, generated_password


    def __group_is_recycled(self, group):
        if group == self.kpdb.root_group:
            return False
        elif group == self.kpdb.recyclebin_group:
            return True
        else:
            return self.__group_is_recycled(group.group)


    def __get_entry_custom_data(self, entry):
        items = [ x.findall('Item') for x in entry._element.findall('CustomData') ]
        flattened_items = [ item for item_list in items for item in item_list ]
        custom_data = { y.find('Key').text: y.find('Value').text for y in flattened_items }

        return custom_data


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


    def get_logins(self, site_url, form_url, http_auth, realm=''):
        entries = []

        for group in self.kpdb.groups:
            if self.__group_is_recycled(group):
                continue
            elif group.expired:
                continue

            for entry in group.entries:
                if self.__group_is_recycled(entry.group):
                    continue

                custom_data = self.__get_entry_custom_data(entry)

                login = {}
                login['uuid'] = entry.uuid.hex
                login['login'] = entry.username
                login['name'] = entry.title
                login['password'] = entry.password
                login['group'] = entry.group.name
                if entry.expired:
                    login['expired'] = KEEPASS_TRUE_STR
                if 'otp' in entry.custom_properties:
                    login['totp'] = self.get_current_totp(entry.uuid.hex)
                if KEEPASS_OPTION_SKIP_AUTO_SUBMIT in custom_data:
                    login['skipAutoSubmit'] = custom_data[KEEPASS_OPTION_SKIP_AUTO_SUBMIT]

                # search for additional url's starting with KP2A_URL
                additional_url_match = False
                # TODO  __entry_matches should not take entry but entry.url
                '''
                for prop_key in entry.custom_properties:
                    if prop.startswith(KEEPASS_ADDITIONAL_URL) \
                       and self.__entry_matches(entry.custom_properties[prop_key], site_url, form_url) \
                       and login not in entries:
                        entries.append(login)
                        additional_url_match = True
                '''

                if additional_url_match:
                    continue

                option_hide_entry = custom_data[KEEPASS_OPTION_HIDE_ENTRY] \
                            if KEEPASS_OPTION_HIDE_ENTRY in custom_data else None
                option_only_http_auth = custom_data[KEEPASS_OPTION_ONLY_HTTP_AUTH] \
                            if KEEPASS_OPTION_ONLY_HTTP_AUTH in custom_data else None
                option_not_http_auth = custom_data[KEEPASS_OPTION_NOT_HTTP_AUTH] \
                            if KEEPASS_OPTION_NOT_HTTP_AUTH in custom_data else None

                if option_hide_entry == KEEPASS_TRUE_STR:
                    continue
                elif not http_auth and option_only_http_auth == KEEPASS_TRUE_STR:
                    continue
                elif http_auth and option_not_http_auth == KEEPASS_TRUE_STR:
                    continue

                if KEEPASSXC_BROWSER_SETTINGS in custom_data:
                    settings = json.loads(custom_data[KEEPASSXC_BROWSER_SETTINGS])
                    allowed_hosts = settings['Allow'] if 'Allow' in settings else []
                    denied_hosts = settings['Deny'] if 'Deny' in settings else []
                    realm_setting = settings['Realm'] if 'Realm' in settings else []

                    site_host = urlparse(site_url).netloc
                    form_host = urlparse(form_url).netloc

                    if site_host in allowed_hosts and (not form_host or form_host in allowed_hosts):
                        pass # allowed
                    elif site_host in denied_hosts or (form_host and form_host in denied_hosts):
                        continue # denied
                    elif not realm and realm != realm_setting:
                        continue # denied

                # TODO if expired then only add when expired credentials are allowed
                #      according to user settings

                if self.__entry_matches(entry, site_url, form_url):
                    entries.append(login)

        return entries


    def add_login(self, group_uuid, group_name, title, username, password, url):
        group = self.kpdb.root_group
        if group_uuid:
            group = self.kpdb.find_groups(uuid=uuidlib.UUID(group_uuid), first=True)

        existing_entry = self.kpdb.find_entries(group=group, title=title, username=username, \
                                                url=url, recursive=False, first=True)
        if existing_entry:
            return self.update_login(existing_entry.uuid.hex, title, username, password, url)
        else:
            self.kpdb.add_entry(group, title, username, password, url=url, icon='0')

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


    def delete_login(self, uuid):
        existing_entry = self.kpdb.find_entries(uuid=uuidlib.UUID(uuid), first=True)
        if not existing_entry:
            return False

        try:
            self.kpdb.trash_entry(existing_entry)
            self.kpdb.save()
            return True
        except:
            return False


    def get_root_group(self):
        return self.kpdb.root_group


    def get_database_groups(self, group):
        return_group = {}
        return_group['name'] = group.name
        return_group['uuid'] = group.uuid.hex
        sub_groups = [ g for g in group.subgroups if g != self.kpdb.recyclebin_group ]
        return_group['children'] = [ self.get_database_groups(g) for g in sub_groups ]
        return return_group


    def create_group(self, groupname):
        # TODO user interaction: Are you sure you want to create {groupname}? Yes - No
        group_path = groupname.split('/')
        sub_group = None
        is_dirty = False
        for sub_group_path in [ group_path[:index+1] for (index, g) in enumerate(group_path) ]:
            group = self.kpdb.find_groups(path=sub_group_path[:-1], first=True)
            sub_group = self.kpdb.find_groups(path=sub_group_path, first=True)

            if sub_group is None:
                sub_group = self.kpdb.add_group(group, sub_group_path[-1])
                is_dirty = True

        if not sub_group:
            return {}

        if is_dirty:
            try:
                self.kpdb.save()
            except:
                return {}

        return_group = {}
        return_group['name'] = sub_group.name
        return_group['uuid'] = sub_group.uuid.hex
        return return_group


    def get_current_totp(self, uuid):
        existing_entry = self.kpdb.find_entries(uuid=uuidlib.UUID(uuid), first=True)
        if not existing_entry:
            return None

        if 'otp' not in existing_entry.custom_properties:
            return None

        otp_auth = existing_entry.custom_properties['otp']
        totp = pyotp.parse_uri(otp_auth)
        return totp.now()


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

