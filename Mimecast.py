import os
import sys
import requests
import logging
import uuid
import datetime
import json
import hmac
import base64
import hashlib

# Mimecast class file
#
# Written by Marc Silver <marcs@bsdkid.com>
#

class Mimecast:

	# Initialise the class and login to the Mimecast API
	#
	# @param string USER
	#  Mimecast username
	#
	# @param string PASS
	#  Mimecast password
	#
	# @param string APP_ID
	#  Mimecast application ID
	#
	# @param string APP_KEY
	#  Mimecast application secret key
	# 
	# @param string AUTH_TYPE
	#  Mimecast authentication method
	#
	def __init__(self, USER=None, PASS=None, APP_ID=None, APP_KEY=None, AUTH_TYPE=None):

		FORMAT = '[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s'
		# Set logging to DEBUG for more information
		logging.basicConfig(filename='mimecast.log', format=FORMAT, level=logging.INFO)

		self.USER = USER
		self.PASS = PASS
		self.APP_ID = APP_ID
		self.APP_KEY = APP_KEY
		self.AUTH_TYPE = AUTH_TYPE

		if USER is None or PASS is None or APP_ID is None or APP_KEY is None or AUTH_TYPE is None:
			print 'Credentials and/or application variables not set.  Exiting.'
			sys.exit(1)
		else:
			self.baseUrl = self.discoverAuthentication()

			if self.login() is False:
				print 'Unable to login.  Are credentials set and correct?'

	# Used to create a signature used in the Authorization header
	#
	# @param string dataToSign
	#  Data which we wish to sign
	#
	# @param string secretKey
	#  The secret key passed to us by Mimecast upon login
	#
	# @return string 
	#  A base 64 encoding of the signed data
	#
	def createSignature(self, dataToSign, secretKey):
	    digest = hmac.new(secretKey.decode('base64'), dataToSign, digestmod=hashlib.sha1).digest()
	    sig = base64.encodestring(digest).rstrip()
	    return sig

	# Provides a date
	#
	# @return string returnDt
	#  Formatted date string.
	#
	def getHdrDate(self):
	    date = datetime.datetime.utcnow()
	    dt = date.strftime('%a, %d %b %Y %H:%M:%S')
	    returnDt = dt + ' UTC'
	    return returnDt

	# Discover which URL to use depending on our creds.
	#
	# @return string 
	#  The FQDN of the Mimecast region we must connect to.
	#
	def discoverAuthentication(self):
	    fullURI = 'https://api.mimecast.com/api/login/discover-authentication'
	 
	    requestId = str(uuid.uuid4())
	    requestDate = self.getHdrDate()
	 
	    headers = {'x-mc-app-id': self.APP_ID, 'x-mc-req-id': requestId, 'x-mc-date': requestDate}
	    params = {'data': [{'emailAddress': self.USER}]}

	    response = requests.post(fullURI, data=json.dumps(params), headers=headers)
	    if response.status_code == 200:
	        logging.info('discoverAuthentication() successful')
	        return response.json()['data'][0]['region']['api'].split('//')[1]
	    else:
	        logging.info('discoverAuthentication failed with status code %s' % response.status_code)

	# Login to Mimecast
	#
	# @return bool 
	#  Returns TRUE if login is successful and FALSE if other.
	#
	def login(self):
		import json
		uri = '/api/login/login'
		fullURI = 'https://' + self.baseUrl + uri

		requestId = str(uuid.uuid4())

		headers = {'Authorization': self.AUTH_TYPE + ' ' + base64.b64encode(self.USER + ':' + self.PASS), 'x-mc-app-id': self.APP_ID, 'x-mc-req-id': requestId}
		params = '{"data":[{"username": "' + self.USER + '"}]}'

		response = requests.post(fullURI, data=params, headers=headers)
		if response.status_code == 200:
			logging.info('Login successful.')
			json = response.json()
			self.accessKey = json['data'][0]['accessKey']
			self.secretKey = json['data'][0]['secretKey']
			return True
		else:
			logging.info('Login failed with status code %s' % response.status_code)
			return False

	# Logout of Mimecast
	#
	# @return bool 
	#  Returns TRUE if logout is successful and FALSE if other.
	#
	def logout(self):
		uri = '/api/login/logout'
		fullURI = 'https://' + self.baseUrl + uri
	 
		requestId = str(uuid.uuid4())
		requestDate = self.getHdrDate()
		signature = 'MC ' + self.accessKey + ':' + self.createSignature(':'.join([requestDate, requestId, uri, self.APP_KEY]), self.secretKey)

		headers = {'Authorization': signature, 'x-mc-app-id': self.APP_ID, 'x-mc-req-id': requestId, 'x-mc-date': requestDate, 'Content-Type': 'application/json'}
		params = {'data': [{'accessKey': self.accessKey}]}
		response = requests.post(fullURI, data=params, headers=headers)
		if response.status_code == 200:
			logging.info('Logout successful.')
			return True
		else:
			logging.info('Logout failed with status code %s' % response.status_code)
			return False

	# Make a request to the Mimecast API and return data.
	#
	# @param string uri
	#  The applicable URL/route we are connecting to.
	#
	# @param dict params
	#  A dict object that will be converted to JSON.
	#
	# @param bool stream
	#  Indicates whether we want the raw response from the server or not.
	#
	# @return json
	#  Returns the JSON output if stream is False
	#
	# @return raw
	#  Returns the raw output is stream is True
	#
	def apiRequest(self, uri, params, stream=False):
		logging.debug('Connecting to %s' % uri)
		logging.debug('stream is set to %s' % stream)
		fullURI = 'https://' + self.baseUrl + uri

		requestId = str(uuid.uuid4())
		requestDate = self.getHdrDate()
		signature = 'MC ' + self.accessKey + ':' + self.createSignature(':'.join([requestDate, requestId, uri, self.APP_KEY]), self.secretKey)

		headers = {'Authorization': signature, 'x-mc-app-id': self.APP_ID, 'x-mc-req-id': requestId, 'x-mc-date': requestDate}

		logging.debug('sent headers: %s' % headers)
		logging.debug('sent params: %s' % params)
		
		response = requests.post(fullURI, data=json.dumps(params), headers=headers, stream=stream)
		logging.debug('rcvd response status code: %s' % response.status_code)
		logging.debug('rcvd response status text: %s' % response.text)
		if response.status_code == 200:
			logging.info('apirequest() successful.')
			if stream is True:
				return response
			else:
				return response.json()
		else:
			logging.debug('apirequest() failed with status code %s' % response.status_code)

	# Request a list of messages in the hold queue from Mimecast
	#
	# @param int MINUTES
	#  The amount of minutes back from datetime.datetime.now() we want to look at.
	#
	# @return json 
	#  A JSON object of data recieved.
	#
	def getHoldList(self, MINUTES):
		uri = '/api/gateway/get-hold-message-list'
		fullURI = 'https://' + self.baseUrl + uri

		endTime = datetime.datetime.now()
		startTime = datetime.datetime.now() - datetime.timedelta(minutes=MINUTES)
		end = endTime.strftime("%Y-%m-%dT%H:%M:%S+0200")
		start = startTime.strftime("%Y-%m-%dT%H:%M:%S+0200")

		params = {'meta': {'pagination': {'pageSize': 100}}, 'data': [{'start': start, 'end': end, 'admin': 'true'}]}
		data = self.apiRequest(uri, params)
		return data
	
	# Request details related to a specific message.
	#
	# @param string id
	#  The ID of the message which we are interested in.
	#
	# @return json 
	#  A JSON object of data recieved.
	#
	def getMessageDetail(self, id):
		uri ='/api/gateway/message/get-message-detail'
		fullURI = 'https://' + self.baseUrl + uri

		params = {'data': [{'id': id}]}
		response = self.apiRequest(uri, params)
		return response

	# Download a file relating to a specific ID
	#
	# @param string id
	#  The ID of the message which we are interested in.
	#
	# @param string filename
	#  The filename we wish to output to.
	#
	# @return bool 
	#  Returns TRUE if successful and False if other.
	#
	def downloadFile(self, id, filename):
		uri = '/api/gateway/message/get-file'
		fullURI = 'https://' + self.baseUrl + uri
		
		params = {'data': [{'id': id}]}
		# stream=True since we want the raw content back.
		data = self.apiRequest(uri, params, True)

		try:
			logging.info('Attempting to write file: %s' % filename)
			with open(filename, 'wb') as fd:
				for chunk in data.iter_content(chunk_size=128):
					fd.write(chunk)
			return True
		except:
			logging.info('Unable to write file.')
			return False