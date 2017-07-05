#!/usr/bin/python

import sys
from Mimecast import Mimecast

APP_ID = ''
APP_KEY = ''
USER = ''
PASS = ''
AUTH_TYPE = "Basic-Cloud" 

mc = Mimecast(USER, PASS, APP_ID, APP_KEY, AUTH_TYPE)

try:
	messagesInHoldQueue = mc.getHoldList(3)
	if len(messagesInHoldQueue["data"][0]["id"]) > 0:
		events = messagesInHoldQueue["data"]
		for event in events:
			if event['hasAttachments'] is True:
				IGNORED_REASON_IDS = ['ADMIN_MESSAGE_HOLD_APPLIED_SPAM_SIGNATURE_POLICY','ADMIN_MESSAGE_HOLD_APPLIED_SPAM_SIGNATURE_POLICY']
				if event['reasonId'] not in IGNORED_REASON_IDS:
					messageDetail = mc.getMessageDetail(event['id'])
					if len(messageDetail["data"][0]["attachments"]) > 0:
						for x in messageDetail["data"][0]["attachments"]:
							IGNORE_CONTENT_TYPE = ['application/pdf', 'application/x-pkcs7-signature', 'application/gzip', 'application/x-rar-compressed']
							if 'application' in x['contentType'] and x['contentType'] not in IGNORE_CONTENT_TYPE:
								print 'Downloading %s with content-type %s' % (x['filename'], x['contentType'])
								mc.downloadFile(x['id'], x['filename'])
							else:
								print 'Ignoring %s with content-type %s' % (x['filename'], x['contentType'])
				else:
					print 'Ignoring reasonId: %s' % event['reasonId']
except:
	for error in sys.exc_info():
		print error
finally:
	mc.logout()
