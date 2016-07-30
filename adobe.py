import sys
import urllib2

import xbmc
import xbmcaddon
import xbmcgui

from lib.adobe_activate_api import adobe_activate_api

selfAddon = xbmcaddon.Addon()
translation = selfAddon.getLocalizedString

count = len(sys.argv) - 1

TAG = 'adobe-main: '

if count >= 4:
    requestor_id = sys.argv[1]
    public_key = sys.argv[2]
    key = sys.argv[3]
    command = sys.argv[4]

    xbmc.log(TAG + 'RequestorId: %s command: %s' % (requestor_id, command))

    adobe_instance = adobe_activate_api.AdobeActivateApi(
        requestor_id, public_key, key)

    if command == 'AUTHENTICATION_DETAILS':
        xbmc.log(TAG + ' Authentication details')
        dialog = xbmcgui.Dialog()
        if adobe_instance.is_authenticated():
            ok = dialog.yesno(translation(30380),
                              translation(30390) % adobe_instance.get_authentication_expires(),
                              nolabel=translation(30360),
                              yeslabel=translation(30430))
            if ok:
                adobe_instance.deauthorize()

        else:
            dialog.ok(translation(30380), translation(30440))
    elif command == 'AUTHENTICATE_DEVICE':
        xbmc.log(TAG + ' Authenticating device')
        if adobe_instance.is_authenticated():
            xbmc.log(TAG + 'Device already authenticated, skipping authentication', xbmc.LOGDEBUG)
        else:
            regcode = adobe_instance.get_regcode()
            dialog = xbmcgui.Dialog()
            ok = dialog.yesno(translation(30310),
                              translation(30320),
                              translation(30330) % regcode,
                              translation(30340),
                              translation(30360),
                              translation(30350))
            if ok:
                try:
                    adobe_instance.authenticate()
                    dialog.ok(translation(30310), translation(30370))
                except urllib2.HTTPError as e:
                    dialog.ok(translation(30037), translation(30420) % e)
    else:
        xbmc.log(TAG + ' Unable to process command %s' % command)
