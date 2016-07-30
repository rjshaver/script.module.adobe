import urlparse
import urllib
import uuid
import hashlib
import hmac
import base64
import urllib2
import time
import json
import gzip
import os
import cookielib
from StringIO import StringIO

import xbmc
import xbmcaddon

ADDON_PATH_PROFILE = xbmc.translatePath(xbmcaddon.Addon().getAddonInfo('profile')).decode('utf-8')
if not os.path.exists(ADDON_PATH_PROFILE):
        os.makedirs(ADDON_PATH_PROFILE)

SETTINGS_FILE_SUFFIX = 'adobe.json'
COOKIES_FILE_SUFFIX = 'adobe-cookies.lwp'
UA_ATV = 'AppleCoreMedia/1.0.0.13Y234 (Apple TV; U; CPU OS 9_2 like Mac OS X; en_us)'
TAG = 'adobe-api: '


class AdobeActivateApi:

    def __init__(self, requestor_id, requestor_public_key, requestor_key):
        self.requestor_id = requestor_id
        self.requestor_public_key = requestor_public_key
        self.requestor_key = requestor_key
        self.settings = {}
        requestor_path = os.path.join(ADDON_PATH_PROFILE, self.requestor_id)
        if not os.path.exists(requestor_path):
            os.makedirs(requestor_path)
        self.cookie_file_path = os.path.join(requestor_path, COOKIES_FILE_SUFFIX)
        self.settings_file_path = os.path.join(requestor_path, SETTINGS_FILE_SUFFIX)
        self._init_cookie()
        self._load_settings()

    def _init_cookie(self):
        self.cj = cookielib.LWPCookieJar()
        if not os.path.isfile(self.cookie_file_path):
            self._save_cookies()
        else:
            try:
                self.cj.load(self.cookie_file_path, ignore_discard=True)
            except IOError:
                os.remove(self.cookie_file_path)
                self._init_cookie()

    # Fixes an issue with 32bit systems not supporting times after 2038
    def _save_cookies(self):
        for cookie in self.cj:
            if cookie.expires > 2000000000:
                cookie.expires = 2000000000
        self.cj.save(self.cookie_file_path, ignore_discard=True, ignore_expires=True)

    def reset_settings(self):
        self.settings = {}
        self._save_settings()

    def _save_settings(self):
        with open(self.settings_file_path, 'w') as fp:
            json.dump(self.settings, fp, sort_keys=False, indent=4)

    def _load_settings(self):
        xbmc.log(TAG + ' Loading settings from %s' % self.settings_file_path)
        if not os.path.isfile(self.settings_file_path):
            self.reset_settings()
        with open(self.settings_file_path, 'r') as fp:
            self.settings = json.load(fp)

    def get_device_id(self):
        if 'device_id' not in self.settings:
            self.settings['device_id'] = str(uuid.uuid1())
            self._save_settings()
        return self.settings['device_id']

    def _get_url_response(self, url, message, body=None, method=None):
        xbmc.log(TAG + 'url %s message %s' % (url, message), xbmc.LOGDEBUG)
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.cj))
        opener.addheaders = [
            ("Accept", "application/json"),
            ("Accept-Encoding", "gzip, deflate"),
            ("Accept-Language", "en-us"),
            ("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8"),
            ("Connection", "close"),
            ("User-Agent", UA_ATV),
            ("Authorization", message)]
        if method == 'DELETE':
            request = urllib2.Request(url)
            request.get_method = lambda: method
            resp = opener.open(request)
        else:
            resp = opener.open(url, body)
            resp = _read_response(resp)
        self._save_cookies()
        return resp

    def _generate_message(self, method, path):
        nonce = str(uuid.uuid4())
        today = str(int(time.time() * 1000))
        message = method + ' requestor_id=' + self.requestor_id + ', nonce=' + nonce\
                  + ', signature_method=HMAC-SHA1, request_time='\
                  + today + ', request_uri=' + path
        signature = hmac.new(self.requestor_key, message, hashlib.sha1)
        signature = base64.b64encode(signature.digest())
        message = message + ', public_key=' + self.requestor_public_key + ', signature=' + signature
        return message

    def is_reg_code_valid(self):
        if 'generateRegCode' not in self.settings:
            xbmc.log(TAG + 'Unable to find reg code', xbmc.LOGDEBUG)
            return False
        # Check code isn't expired
        expiration = self.settings['generateRegCode']['expires']
        if _is_expired(expiration):
            xbmc.log(TAG + 'Reg code is expired at %s' % expiration, xbmc.LOGDEBUG)
            return False
        return True

    # Gets called when the user wants to authorize this device, it returns a registration code to enter
    # on the activation website page
    # Sample : '{"id":"","code":"","requestor":"ESPN","generated":1463616806831,"expires":1463618606831,"info":{"deviceId":"","deviceType":"appletv","deviceUser":null,"appId":null,"appVersion":null,"registrationURL":null}}'
    # (generateRegCode)
    def get_regcode(self):
        if self.is_reg_code_valid():
            xbmc.log(TAG + 'Loading reg code from cache', xbmc.LOGDEBUG)
            return self.settings['generateRegCode']['code']

        params = urllib.urlencode(
            {'deviceId': self.get_device_id(),
             'deviceType': 'appletv',
             'ttl': '1800'})

        path = '/regcode'
        url = _make_url('reggie/v1/' + self.requestor_id + path, params)

        message = self._generate_message('POST', path)

        resp = self._get_url_response(url, message, dict())

        self.settings['generateRegCode'] = resp
        self._save_settings()
        return resp['code']

    # Authenticates the user after they have been authenticated on the activation website (authenticateRegCode)
    # Sample: '{"mvpd":"","requestor":"ESPN","userId":"","expires":"1466208969000"}'
    def authenticate(self):
        if not self.is_reg_code_valid():
            xbmc.log(TAG + 'reg code is invalid', xbmc.LOGDEBUG)
            raise ValueError('Registration code is invalid, please restart the authentication process')

        reg_code = self.get_regcode()

        params = urllib.urlencode({'requestor': self.requestor_id})

        path = '/authenticate/' + reg_code
        url = _make_url('api/v1' + path, params)

        message = self._generate_message('GET', path)

        resp = self._get_url_response(url, message)
        self.settings['authenticateRegCode'] = resp
        self._save_settings()

    # Get authn token (re-auth device after it expires), getAuthnToken
    def re_authenticate(self):
        params = urllib.urlencode({'requestor': 'ESPN',
                                   'deviceId': self.get_device_id()})

        path = '/tokens/authn'
        url = _make_url('api/v1' + path, params)

        message = self._generate_message('GET', path)

        resp = self._get_url_response(url, message)
        self.settings['authenticateRegCode'] = resp
        if 'authorize' in self.settings:
            del self.settings['authorize']
        self._save_settings()



    # Sample '{"resource":"resource","mvpd":"","requestor":"ESPN","expires":"1463621239000"}'
    def authorize(self, resource):
        if self.is_authorized(resource):
            xbmc.log(TAG + 'already authorized', xbmc.LOGDEBUG)
            return
        params = urllib.urlencode({'requestor': self.requestor_id,
                                   'deviceId': self.get_device_id(),
                                   'resource': resource})

        path = '/authorize'
        url = _make_url('api/v1' + path, params)

        message = self._generate_message('GET', path)

        resp = self._get_url_response(url, message)
        if 'authorize' not in self.settings:
            self.settings['authorize'] = dict()
        xbmc.log(TAG + 'resource %s' % resource, xbmc.LOGDEBUG)
        self.settings['authorize'][resource.decode('iso-8859-1').encode('utf-8')] = resp
        self._save_settings()

    def deauthorize(self):
        params = urllib.urlencode({'deviceId': self.get_device_id()})

        path = '/logout'
        url = _make_url('api/v1' + path, params)

        message = self._generate_message('DELETE', path)

        resp = self._get_url_response(url, message, body = None, method = 'DELETE')
        if 'authorize' in self.settings:
            del self.settings['authorize']
        if 'authenticateRegCode' in self.settings:
            del self.settings['authenticateRegCode']
        self._save_settings()

    # getShortMediaToken
    # Sample '{"mvpdId":"","expires":"1463618218000","serializedToken":"+++++++=","userId":"","requestor":"ESPN","resource":" resource"}'
    def get_short_media_token(self, resource):
        if self.has_to_reauthenticate():
            xbmc.log(TAG + 're-authenticating device', xbmc.LOGDEBUG)
            self.re_authenticate()
        self.authorize(resource)
        params = urllib.urlencode({'requestor': self.requestor_id,
                                   'deviceId': self.get_device_id(),
                                   'resource': resource})

        path = '/mediatoken'
        url = _make_url('api/v1' + path, params)

        message = self._generate_message('GET', path)

        resp = self._get_url_response(url, message)
        self.settings['getShortMediaToken'] = resp
        self._save_settings()
        return resp['serializedToken']

    def is_authenticated(self):
        xbmc.log(TAG + ' settings %s' % self.settings)
        return 'authenticateRegCode' in self.settings

    def has_to_reauthenticate(self):
        return _is_expired(self.settings['authenticateRegCode']['expires'])

    def is_authorized(self, resource):
        if 'authorize' in self.settings and \
                        resource.decode('iso-8859-1').encode('utf-8') in self.settings['authorize']:
            return not _is_expired(self.settings['authorize'][resource.decode('iso-8859-1')
                                    .encode('utf-8')]['expires'])

    def _get_expires_time(self, key):
        if key in self.settings:
            expires = self.settings[key]['expires']
            expires_time = time.localtime(int(expires) / 1000)
            return time.strftime('%Y-%m-%d %H:%M', expires_time)
        return 'Missing Key %s' % key

    def get_authentication_expires(self):
        return self._get_expires_time('authenticateRegCode')

    def get_authorization_expires(self):
        return self._get_expires_time('authorize')

    def clean_up_authorization_tokens(self):
        keys_to_delete = list()
        if 'authorize' in self.settings:
            for key in self.settings['authorize']:
                if 'expires' in self.settings['authorize'][key]:
                    if _is_expired(self.settings['authorize'][key]['expires']):
                        keys_to_delete.append(key)
                else:
                    keys_to_delete.append(key)
        for key in keys_to_delete:
            del self.settings['authorize'][key]
        self._save_settings()

    def get_user_metadata(self):
        params = urllib.urlencode({'requestor': self.requestor_id,
                                   'deviceId': self.get_device_id()})

        path = '/tokens/usermetadata'
        url = _make_url('api/v1' + path, params)

        message = self._generate_message('GET', path)

        resp = self._get_url_response(url, message)
        return resp

def _read_response(resp):
    if resp.info().get('Content-Encoding') == 'gzip':
        buf = StringIO(resp.read())
        f = gzip.GzipFile(fileobj=buf)
        content = f.read()
    else:
        content = resp.read()
    return json.loads(content)


def _is_expired(expiration):
    return (time.time() * 1000) >= int(expiration)


def _make_url(path, params):
    return urlparse.urlunsplit(['https', 'api.auth.adobe.com',
                                path,
                                params, ''])

def get_resource(channel, event_name, event_guid, event_parental_rating):
    return '<rss version="2.0" xmlns:media="http://search.yahoo.com/mrss/"><channel><title><![CDATA[' \
           + channel + "]]></title><item><title><![CDATA[" + event_name + "]]></title><guid><![CDATA[" \
           + event_guid + ']]></guid><media:rating scheme="urn:v-chip"><![CDATA[' \
           + event_parental_rating + "]]></media:rating></item></channel></rss>"
