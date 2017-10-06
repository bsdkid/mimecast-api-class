import requests
import uuid
import json
import hmac
import base64
import hashlib
import datetime
import threading
import time
import pytz
from pprint import pprint

SAFE_CONTENT_TYPE = ['image/png', 'image/jpeg', 'image/gif', 'text/plain', 'application/pdf', 'application/pkcs7-signature', 'application/x-pkcs7-signature', 'application/gzip', 'application/x-rar-compressed']

#MESSAGE_HOLD_APPLIED_ATTACHMENT_TYPE_POLICY
#ADMIN_MESSAGE_HOLD_APPLIED_SPAM_SIGNATURE_POLICY
#ADMIN_MESSAGE_HOLD_APPLIED_ATTACHMENT_SANDBOX_FAILURE

''' Mimecast class file - Written by Marc Silver <marcs@bsdkid.com> '''

class Mimecast:

    ''' Initialise the class and login to the Mimecast API
     @param string user_name
      Mimecast username
    
     @param string user_pass
      Mimecast password
    
     @param string app_id
      Mimecast application ID
    
     @param string app_key
      Mimecast application secret key
     
     @param string auth_type
      Mimecast authentication method '''

    def __init__(self, user_name, user_pass, app_id, app_key, auth_type="Basic-Cloud"):

        self.user_name = user_name
        self.user_pass = user_pass
        self.app_id = app_id
        self.app_key = app_key
        self.auth_type = auth_type

        self.baseUrl = self._discoverAuthentication()

        if self._login() == False:
            raise ValueError('Unable to login. Are the credentials correct?')
        
    def __del__(self):
        self._logout()
    
    def _createSignature(self, dataToSign, secretKey):
        
        ''' Used to create a signature used in the Authorization header
         @param string dataToSign
          Data which we wish to sign
        
         @param string secretKey
          The secret key passed to us by Mimecast upon login
        
         @return string 
          A base 64 encoding of the signed data '''

        digest = hmac.new(base64.b64decode(secretKey), dataToSign.encode(), digestmod=hashlib.sha1).digest()
        return base64.b64encode(digest).decode()
    
    def _getHdrDate(self):
        
        ''' Provides a date
         @return string returnDt
          Formatted date string '''        
        
        date = datetime.datetime.utcnow()
        dt = date.strftime('%a, %d %b %Y %H:%M:%S')
        return dt + ' UTC'
    
    def _discoverAuthentication(self):
        
        ''' Discover which URL to use depending on our creds.
         @return string 
          The FQDN of the Mimecast region we must connect to '''        
        
        fullURI = 'https://api.mimecast.com/api/login/discover-authentication'
     
        requestId = str(uuid.uuid4())
        requestDate = self._getHdrDate()
        headers = {'x-mc-app-id': self.app_id, 'x-mc-req-id': requestId, 'x-mc-date': requestDate}
        params = {'data': [{'emailAddress': self.user_name}]}
        response = requests.post(fullURI, data=json.dumps(params), headers=headers)
        
        if response.status_code == 200:
            return response.json()['data'][0]['region']['api'].split('//')[1]

    def _login(self):
        
        ''' Login to Mimecast
         @return bool 
          Returns TRUE if login is successful and FALSE if other' '''
        
        uri = '/api/login/login'
        fullURI = 'https://' + self.baseUrl + uri

        request_id = str(uuid.uuid4())
        auth_str = self.user_name + ':' + self.user_pass
        auth_str = base64.b64encode(auth_str.encode()).decode("utf-8")
        headers = {'Authorization': self.auth_type + ' ' + auth_str, 'x-mc-app-id': self.app_id, 'x-mc-req-id': request_id}
        params = {'data': [{'username': self.user_name}]}
        response = requests.post(fullURI, data=json.dumps(params), headers=headers)
        
        if response.status_code == 200:
            jsonr = response.json()
            self.accessKey = jsonr['data'][0]['accessKey']
            self.secretKey = jsonr['data'][0]['secretKey']
            return True
        else:
            return False

    def _logout(self):

        ''' Logout of Mimecast
         @return bool 
          Returns TRUE if logout is successful and FALSE if other '''
        
        uri = '/api/login/logout'
        fullURI = 'https://' + self.baseUrl + uri
     
        requestId = str(uuid.uuid4())
        requestDate = self._getHdrDate()
        signature = 'MC ' + self.accessKey + ':' + self._createSignature(':'.join([requestDate, requestId, uri, self.app_key]), self.secretKey)
        headers = {'Authorization': signature, 'x-mc-app-id': self.app_id, 'x-mc-req-id': requestId, 'x-mc-date': requestDate}
        params = {'data': [{'accessKey': self.accessKey}]}
        response = requests.post(fullURI, data=params, headers=headers)
        
        return response.status_code == 200

    def _apiRequest(self, uri, params, stream = False):
        
        ''' Make a request to the Mimecast API and return data
         @param string uri
          The applicable URL/route we are connecting to
        
         @param dict params
          A dict object that will be converted to JSON
        
         @param bool stream
          Indicates whether we want the raw response from the server or not
        
         @return json
          Returns the JSON output if stream is False
        
         @return raw
          Returns the raw output if stream is True '''        
        
        fullURI = 'https://' + self.baseUrl + uri

        requestId = str(uuid.uuid4())
        requestDate = self._getHdrDate()
        signature = 'MC ' + self.accessKey + ':' + self._createSignature(':'.join([requestDate, requestId, uri, self.app_key]), self.secretKey)
        headers = {'Authorization': signature, 'x-mc-app-id': self.app_id, 'x-mc-req-id': requestId, 'x-mc-date': requestDate}
        response = requests.post(fullURI, data=json.dumps(params), headers=headers, stream=stream)

        if response.status_code == 200:
            return response.content if stream else response.json()

    def getRollingHoldList(self, window_minutes = 30, poll_minutes = 5, poll = True):
        return RollingHoldList(self, window_minutes, poll_minutes, poll)

    def getHoldList(self, minutes = 30):

        ''' Request a list of messages in the hold queue from Mimecast
         @param int MINUTES
          The amount of minutes back from datetime.datetime.now() we want to look at
        
         @return json 
          A JSON object of data recieved '''        
        
        uri = '/api/gateway/get-hold-message-list'

        endTime = datetime.datetime.now(tz=pytz.utc)
        startTime = endTime - datetime.timedelta(minutes = minutes)
        end = endTime.strftime("%Y-%m-%dT%H:%M:%S%z")
        start = startTime.strftime("%Y-%m-%dT%H:%M:%S%z")

        held_messages = []
        pagination_next = None

        while True:
            if pagination_next == None:
                params = {'meta': {'pagination': {'pageSize': 10}}, 'data': [{'start': start, 'end': end, 'admin': 'true'}]}
            else:
                params = {'meta': {'pagination': {'pageSize': 10, 'pageToken': pagination_next}}, 'data': [{'start': start, 'end': end, 'admin': 'true'}]}
            msg_data = self._apiRequest(uri, params)
            held_messages += [ HeldMessage(self, x) for x in msg_data['data'] ]
            try:
                pagination_next = msg_data['meta']['pagination']['next']
            except KeyError:
                break
            
        return held_messages
    
    def getMessageDetail(self, m_id):

        ''' Request details related to a specific message
         @param string id
          The ID of the message which we are interested in
        
         @return json 
          A JSON object of data recieved '''        
        
        uri ='/api/gateway/message/get-message-detail'

        params = {'data': [{'id': m_id}]}
        return self._apiRequest(uri, params)

    def downloadFile(self, m_id):
        
        ''' Download a file relating to a specific ID
         @param string id
          The ID of the message which we are interested in
        
         @return bool 
          Returns TRUE if successful and False if other '''
        
        uri = '/api/gateway/message/get-file'
        
        params = {'data': [{'id': m_id}]}
        return self._apiRequest(uri, params, True)

    def createUser(self, emailAddress, name, password, accountCode, forcePasswordChange=True):
        uri = '/api/user/create-user'

        params = {'data': [{'emailAddress': emailAddress, 'password': password, 'accountCode': accountCode, 'forcePasswordChange': forcePasswordChange, 'name': name} ] }
        return self._apiRequest(uri, params)


    def getUserList(self, domain):
        uri = '/api/user/get-internal-users'

        user_list = []
        pagination_next = None

        while True:
            if pagination_next == None:
                params = {'meta': {'pagination': {'pageSize': 50}}, 'data': [{'domain': domain}]}
            else:
                params = {'meta': {'pagination': {'pageSize': 50, 'pageToken': pagination_next}}, 'data': [{'domain': domain}]}
            api_response = self._apiRequest(uri, params)

            for x in (api_response['data']):
                user_list += [ User(self,y) for y in x['users'] ]

            try:
                pagination_next = api_response['meta']['pagination']['next']
            except KeyError:
                break

        #print('Getting attributes...')
        #for user in user_list:
        #    print(user.emailAddress)
        #    user.getUserAttributes()

        return user_list

    def getUserAttributes(self, emailAddress):
        uri = '/api/user/get-attributes'

        attributes = []
        pagination_next = None

        while True:
            if pagination_next == None:
                params = {'meta': {'pagination': {'pageSize': 50}}, 'data': [{'emailAddress': emailAddress}]}
            else:
                params = {'meta': {'pagination': {'pageSize': 50, 'pageToken': pagination_next}}, 'data': [{'emailAddress': emailAddress}]}
            api_response = self._apiRequest(uri, params)
            print(emailAddress, api_response)

            if api_response != None:
                for x in (api_response['data']):
                    print( x )
                    attributes += [ user.setAttribute(y) for y in x['users'] ]

            try:
                pagination_next = api_response['meta']['pagination']['next']
            except KeyError:
                break

        return


class RollingHoldList:
    
    def __init__(self, mimecast, window_minutes = 30, poll_minutes = 5, poll = True):
        self._mimecast = mimecast
        self._window_minutes = window_minutes
        self._poll_minutes = poll_minutes
        self._poll = poll
        self._new_messages = []
        self._known_ids = {}
        self._thread = threading.Thread(target=self._check_hold_list)
        self._thread.start()
    
    def __iter__(self):
        return self
    
    def __next__(self):
        if self._poll:
            while not len(self._new_messages):
                time.sleep(60 * self._poll_minutes)
        else:
            raise StopIteration
        return self._new_messages.pop()
    
    def _check_hold_list(self):
        poll_start = 0
        while True:
            poll_start = poll_start + self._poll_minutes
            poll_start = poll_start if poll_start < self._window_minutes else self._window_minutes
            latest_poll = self._mimecast.getHoldList(poll_start)
            for held_message in latest_poll:
                if held_message.id not in self._known_ids:
                    self._known_ids[held_message.id] = held_message.date_received
                    self._new_messages += [held_message]
            window_start = datetime.datetime.now(tz=pytz.utc) - datetime.timedelta(minutes = poll_start)
            tmp_known_ids = {}
            for known_id, known_time in self._known_ids.items():
                if known_time > window_start:
                    tmp_known_ids[known_id] = known_time
            self._known_ids = tmp_known_ids
            time.sleep(60 * self._poll_minutes)
    
    def latest(self):
        tmp_new_messages = self._new_messages
        self._new_messages = []
        return tmp_new_messages

class HeldMessage:
    
    ''' Message object returned by getHoldList '''
    
    def __init__(self, mimecast, message_brief):
                
        self._mimecast = mimecast
        self._raw_brief = message_brief
        self.id = self._raw_brief['id']
        self.reason_id = self._raw_brief['reasonId']
        self.has_attachments = self._raw_brief['hasAttachments']
        self.date_received = datetime.datetime.strptime(self._raw_brief['dateReceived'], "%Y-%m-%dT%H:%M:%S%z")
        self._message_details = None
        self._attachments = None
        
    def getAttachments(self):
        if self._message_details == None:
            self._message_details = self._mimecast.getMessageDetail(self.id)
        if self._attachments == None:
            self._attachments = []
            for cur_attachment in self._message_details['data'][0]['attachments']:
                self._attachments += [MessageAttachment(self._mimecast, cur_attachment)]

        return self._attachments
        
class MessageAttachment:
    
    ''' Attachment for given message object '''
    
    def __init__(self, mimecast, attachment_desc):
        
        self._mimecast = mimecast
        self._raw_brief = attachment_desc
        self.content_type = self._raw_brief['contentType']
        self.filename = self._raw_brief['filename']
        self._content = None
    
    def download(self):
        if not self._content:
            self._content = self._mimecast.downloadFile(self._raw_brief['id'])
        return self._content
    
    def save(self, path = None):
        if path == None:
            path = self.filename
        with open(path, "wb") as fout:
            fout.write(self.download())

class User:

    ''' Message object returned by getUserList '''

    def __init__(self, mimecast, user):

        self._mimecast = mimecast
        self._raw_user = user
        self.emailAddress = self._raw_user['emailAddress']
        self.addressType = self._raw_user['addressType']
        self.alias = self._raw_user['alias']
        self.userAttributes = None

    def getUserAttributes(self):
        if self.userAttributes == None:
            self.userAttributes = self._mimecast.getUserAttributes(self.emailAddress)

