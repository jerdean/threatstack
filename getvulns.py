from mohawk import Sender
import argparse
from configparser import SafeConfigParser
import requests , json, sys
from datetime import datetime, timedelta

def main():
	apikey = raw_input("Enter API Key: ")
	userid = raw_input("Enter userid: ")
	nDays = raw_input("Enter number of Days to review: ")

	#Sanitize inputs
	if nDays == None:
		nDays = 1
	else:
		nDays = int(nDays)


	#These will be consistent for all requests for hawk
	credentials = {
			'id': userid,
			'key': apikey,
			'algorithm': 'sha256'
		}

	date_N_days_ago = datetime.now() - timedelta(days=nDays)
	#these are for the from/until parameters in the api call
	fromDate = (str(date_N_days_ago).split(' ')[0])

	
	ORGANIZATION_ID = raw_input("Enter Org ID: ")
	token = None
	status , severity = 'active' , 1
	allAlerts = []

	while True:
		if token == None:
			URL = 'https://api.threatstack.com/v2/alerts?status=%s&from=%s&severity%s' % (status , fromDate , severity)
		else:
			URL = 'https://api.threatstack.com/v2/alerts?status=%s&from=%s&severity%s&token=%s' % (status, fromDate , severity , token)

		sender = Sender(credentials, URL, "GET", always_hash_content=False, ext=ORGANIZATION_ID)
		response = requests.get(URL, headers={'Authorization': sender.request_header})
		
		vals = response.json()
		token = vals.get('token')
		alerts = vals.get('alerts')

		#have our alerts, now do stuff
		for alert in alerts:
			if alert != None:
				allAlerts.append(alert)
			
		if vals['token'] == None:
			break

	#You have all the alerts, do whatever next, example below is print out the first 10		
	print (allAlerts[:10])
	
if __name__ == '__main__':
	main()

