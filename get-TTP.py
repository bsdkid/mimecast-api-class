#!/usr/bin/env python3

import os
import sys
import Mimecast
import logging
from pprint import pprint
import time

USER = ''
PASS = ''
APP_ID = ''
APP_KEY = ''

mc = Mimecast.Mimecast(USER, PASS, APP_ID, APP_KEY)
messagesInHoldQueue =  mc.getRollingHoldList(poll_minutes = 1)

for cur_msg in messagesInHoldQueue:
    print('MSG: ' + cur_msg.reason_id)
    if cur_msg.has_attachments:
        print('Found message with attachments: ' + cur_msg.reason_id + ' - ' + str(cur_msg.date_received))
        attachments = cur_msg.getAttachments()
        if cur_msg.reason_id == ADMIN_MESSAGE_HOLD_APPLIED_ATTACHMENT_SANDBOX_FAILURE:
            for cur_attachment in attachments:
                if cur_attachment.content_type not in Mimecast.SAFE_CONTENT_TYPE:
                    print('Saving potentially unsafe attachment as: ' + cur_attachment.filename)
                    cur_attachment.save()
                else:
                    pass
                    #print('Skipping attachment in SAFE_CONTENT_TYPE')
