### Author:  Aaron W Morris <aaron@aarmor.net>
###
### This script allows integration of DUO directly into freeradius
###
### Optional:  Slack webhook for notifying when an authentication occurs
###            Slack communication occurs within a thread to prevent notification failures from affecting authentication

import radiusd
import sys
import socket
import json
import requests
import re
#import threading
#import pprint
sys.path.append('/usr/local/virtualenv/duo_python/lib/3.11/site-packages')
import duo_client


DUO_IKEY = 'IIIIIIIIIIIIIIIIIIII'
DUO_SKEY = 'SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS'
DUO_HOST = 'api-abcd1234.duosecurity.com'


SLACK_WEBHOOK_URL = 'https://slack_webhook_url'


def getDuoAuthClient():
    duo_auth_api = duo_client.Auth(
        ikey=DUO_IKEY,
        skey=DUO_SKEY,
        host=DUO_HOST,
    )

    return duo_auth_api


def slackNotify(message):
    message_data = {
        'text' : message,
    }

    try:
        requests.post(
            SLACK_WEBHOOK_URL,
            headers={
                'Content-Type' : 'application/json',
            },
            timeout=3.0,
            data=json.dumps(message_data),
        )
    except requests.exceptions.Timeout:
        radiusd.radlog(radiusd.L_WARN, 'Slack web service API timed out')
    except requests.exceptions.RequestException as e:
        radiusd.radlog(radiusd.L_WARN, 'Slack web service error: {0:s}', str(e))


def getDuoDevice(i, p_dict):
    # return auto when no index is passed, or 0
    if (not i):
        radiusd.radlog(radiusd.L_WARN, "Using 'auto' device for DUO")
        return 'auto'


    # convert to array index
    idx = int(i) - 1

    if isinstance(p_dict['Duo-User-Devices'], str):
        device = p_dict['Duo-User-Devices']

        radiusd.radlog(radiusd.L_WARN, 'Using {0:s} for DUO'.format(device))
        return p_dict['Duo-User-Devices']

    elif isinstance(p_dict['Duo-User-Devices'], list):
        # if index is empty, just use auto
        try:
            device = p_dict['Duo-User-Devices'][idx]
            radiusd.radlog(radiusd.L_WARN, "Using {0:s} for DUO".format(device))
            return device

        except IndexError:
            radiusd.radlog(radiusd.L_WARN, "No such device, using 'auto' device for DUO")
            return 'auto'


    # Failsafe
    radiusd.radlog(radiusd.L_WARN, "Failsafe, using 'auto' device for DUO")
    return 'auto'


def instantiate(p):
    #print("*** instantiate ***")
    #print(p)
    # return 0 for success or -1 for failure
    return 0


def authorize(p):
    #print("*** authorize ***")

    p_dict = dict(p)

    try:
        duo_username = p_dict['Stripped-User-Name']
    except KeyError:
        duo_username = p_dict['User-Name']


    duo_preauth_params = {
        'username' : duo_username,
    }

    duo_auth_api = getDuoAuthClient()
    r = duo_auth_api.preauth(**duo_preauth_params)


    # values to update
    update_request = list()
    update_reply = list()
    update_config = list()

    if r['result'] == 'auth':
        radiusd.radlog(radiusd.L_WARN, 'DUO Auth enabled for {0:s}'.format(duo_username))

        # Add all devices to list for later reference
        for device in r['devices']:
            update_request.append(('Duo-User-Devices', '+=', device['device']))

        update_dict = {
            'request' : tuple(update_request),
            'reply'   : tuple(update_reply),
            'config'  : tuple(update_config),
        }

        return radiusd.RLM_MODULE_OK, update_dict

    elif r['result'] == 'allow':
        # 2FA bypass enabled
        radiusd.radlog(radiusd.L_WARN, 'DUO Auth 2FA bypass enabled for {0:s}'.format(duo_username))
        update_request.append(('Duo-2fa-Bypass', '=', 'bypass'))

        update_dict = {
            'request' : tuple(update_request),
            'reply'   : tuple(update_reply),
            'config'  : tuple(update_config),
        }

        return radiusd.RLM_MODULE_OK, update_dict


    radiusd.radlog(radiusd.L_WARN, 'DUO Auth problem for {0:s} on {1:s}: {2:s}'.format(duo_username, socket.gethostname(), r['status_msg']))

    #slack_thread = threading.Thread(target=slackNotify, args=('DUO Auth problem for {0:s} on {1:s}: {2:s}'.format(duo_username, socket.gethostname(), r['status_msg'])))
    #slack_thread.start()

    return radiusd.RLM_MODULE_REJECT



def authenticate(p):
    #print("*** authenticate ***")
    #radiusd.radlog(radiusd.L_INFO, '*** log call in authenticate ***')

    p_dict = dict(p)
    #print(pprint.pformat(p_dict))

    #print(radiusd.config)

    if p_dict.get('Duo-2fa-Bypass', '') == 'bypass':
        radiusd.radlog(radiusd.L_WARN, '*** DUO Bypass Enabled ***')
        return radiusd.RLM_MODULE_OK


    try:
        duo_username = p_dict['Stripped-User-Name']
    except KeyError:
        duo_username = p_dict['User-Name']


    duo_otp = p_dict.get('User-Password-Otp')


    duo_auth_params = {
        'username' : duo_username,
    }


    # extract device index out of string if it exists
    m = re.search(r'^([a-z]+)(\d+)$', duo_otp)
    if m:
        factor = m.group(1)
        idx = m.group(2)
    else:
        factor = duo_otp
        idx = None



    if factor == 'phone':
        radiusd.radlog(radiusd.L_INFO, 'Using DUO phone method')

        device = getDuoDevice(idx, p_dict)
        duo_auth_params['factor'] = 'phone'
        duo_auth_params['device'] = device
    elif factor == 'sms':
        radiusd.radlog(radiusd.L_INFO, 'Using DUO sms method')

        device = getDuoDevice(idx, p_dict)
        duo_auth_params['factor'] = 'sms'
        duo_auth_params['device'] = device
    elif factor == 'push':
        radiusd.radlog(radiusd.L_INFO, 'Using DUO push method')

        device = getDuoDevice(idx, p_dict)
        duo_auth_params['factor'] = 'push'
        duo_auth_params['device'] = device
    elif factor:
        radiusd.radlog(radiusd.L_INFO, 'Using DUO pincode method')

        duo_auth_params['factor'] = 'passcode'
        duo_auth_params['passcode'] = duo_otp
    else:
        radiusd.radlog(radiusd.L_INFO, 'Using DUO auto (default) method')
        duo_auth_params['factor'] = 'auto'
        duo_auth_params['device'] = 'auto'


    #radiusd.radlog(radiusd.L_INFO, 'Starting DUO API auth call')

    duo_auth_api = getDuoAuthClient()
    r = duo_auth_api.auth(**duo_auth_params)

    #radiusd.radlog(radiusd.L_INFO, 'DUO API auth call complete')

    if r['result'] == 'allow':
        radiusd.radlog(radiusd.L_WARN, 'DUO Auth Successful for {0:s} using {1:s} factor on {2:s}'.format(duo_username, duo_auth_params['factor'], socket.gethostname()))

        #slack_thread = threading.Thread(target=slackNotify, args=('DUO Auth Successful for {0:s} on {1:s}'.format(duo_username, socket.gethostname())))
        #slack_thread.start()

        return radiusd.RLM_MODULE_OK


    radiusd.radlog(radiusd.L_WARN, 'DUO Auth Failure for {0:s} using {1:s} factor on {2:s}: {3:s}'.format(duo_username, duo_auth_params['factor'], socket.gethostname(), r['status_msg']))

    #slack_thread = threading.Thread(target=slackNotify, args=('DUO Auth Failure for {0:s} on {1:s}: {2:s}'.format(duo_username, socket.gethostname(), r['status_msg'])))
    #slack_thread.start()

    return radiusd.RLM_MODULE_REJECT



def preacct(p):
    #print("*** preacct ***")
    #print(p)
    return radiusd.RLM_MODULE_OK


def accounting(p):
    #print("*** accounting ***")
    #radiusd.log(radiusd.L_INFO, '*** log call in accounting (0) ***')
    #print("")
    #print(p)
    return radiusd.RLM_MODULE_OK


def pre_proxy(p):
    #print("*** pre_proxy ***")
    #print(p)
    return radiusd.RLM_MODULE_OK


def post_proxy(p):
    #print("*** post_proxy ***")
    #print(p)
    return radiusd.RLM_MODULE_OK


def post_auth(p):
    #print("*** post_auth ***")
    #print(p)
    return radiusd.RLM_MODULE_OK


def recv_coa(p):
    #print("*** recv_coa ***")
    #print(p)
    return radiusd.RLM_MODULE_OK


def send_coa(p):
    #print("*** send_coa ***")
    #print(p)
    return radiusd.RLM_MODULE_OK


def detach():
    #print("*** goodbye from example.py ***")
    return radiusd.RLM_MODULE_OK


