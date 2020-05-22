#!/usr/bin/env python

import sys,os,getopt
import traceback
import os
import urllib2
import cookielib
import base64
import os.path
import datetime
import json


sys.path.insert(0, 'ds-integration')
from DefenseStorm import DefenseStorm

class integration(object):

    
    def usage(self):
        print
        print os.path.basename(__file__)
        print
        print '  No Options: Run a normal cycle'
        print
        print '  -t    Testing mode.  Do all the work but do not send events to GRID via '
        print '        syslog Local7.  Instead write the events to file \'output.TIMESTAMP\''
        print '        in the current directory'
        print
        print '  -l    Log to stdout instead of syslog Local6'
        print
    
    def __init__(self, argv):

        self.testing = False
        self.send_syslog = True
        self.ds = None
    
        try:
            opts, args = getopt.getopt(argv,"htnld:",["datedir="])
        except getopt.GetoptError:
            self.usage()
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                self.usage()
                sys.exit()
            elif opt in ("-t"):
                self.testing = True
            elif opt in ("-l"):
                self.send_syslog = False
    
        try:
            self.ds = DefenseStorm('symanteccloudEventLogs', testing=self.testing, send_syslog = self.send_syslog)
        except Exception ,e:
            traceback.print_exc()
            try:
                self.ds.log('ERROR', 'ERROR: ' + str(e))
            except:
                pass


        # Load the config file
        #with open('NdfConfig.json') as config_file:    
            #self.config = json.load(config_file)
        # Load your username from the config file
        self.user = self.ds.config_get('symanteccloud', 'user')
        # Load your password from the config file
        self.password = self.ds.config_get('symanteccloud', 'password')
        # Filenames
        # Filename of the cookies file. Directory will be loaded from config file 
        self.cookieFile = self.ds.config_get('symanteccloud', 'cookiesFilePath') + '/cookies.txt'
        # Filename of the logs file, Directory will be loaded from config file 
        # (this format is day_month_year)
        # Format details can be found at https://docs.python.org/2/library/datetime.html#strftime-strptime-behavior
        #self.logFile = self.config['files']['logsFilePath'] + '/%s-datafeed.json' % datetime.datetime.now().strftime('%d_%m_%Y-%H_%M_%S_%f')
        # Request Uri
        self.uri = self.ds.config_get('symanteccloud', 'uri').lower()
    
        # Encode the username/password for HTTP Basic Authentication
        self.base64string = base64.b64encode('%s:%s' % (self.user, self.password))
    
    # Function that checks if a cookie exists by name in the cookie jar
    # Takes the name of the cookie and the cookie jar object 
    def cookieExists(self, name, cookies) :
        for cookie in cookies :
            if cookie.name == name :
                return True
        return False
                
    
    # Function that makes the request to API
    def fetch(self, opener, uri):
        req = urllib2.Request(uri)
        req.add_header('Authorization', 'Basic %s' % self.base64string)
        req.add_header('Accept', 'application/json')
        return opener.open(req)
    
    # Function that saves the response to a file and saves cookies to file
    def saveFiles(self, response, cookies, cookieFile):
        # Create a filename if no path is included it will save to the same directory the script is located
        # (this format is day_month_year-24hour_minute_second_Microsecond)
        # Format details can be found at https://docs.python.org/2/library/datetime.html#strftime-strptime-behavior
        #filename = logFile
        # Save the Json response as a variable
        filecontent = response.read()
        # Create a file
        #fileIo = open(filename,'w')
        # Write json to file
        #fileIo.write(filecontent)
        # Close the file 
        #fileIo.close()

        self.writeData(filecontent)


        # You may want to set permissions on the file here 
        # Details https://docs.python.org/2/library/os.html#os.chmod
        # Save cookies to a seperate file
        cookies.save(cookieFile,ignore_discard=True)


    def flatten_json(self, y):
        out = {}
    
        def flatten(x, name=''):
            if type(x) is dict:
                for a in x:
                    flatten(x[a], name + a + '_')
            elif type(x) is list:
                i = 0
                for a in x:
                    flatten(a, name + str(i) + '_')
                    i += 1
            else:
                out[name[:-1]] = x

        flatten(y)
        return out


    def writeData(self, filecontent):
        if "Reset successfully" not in filecontent:
            myData = json.loads(filecontent)
            for line in myData:
                if 'emailInfo' in line.keys() and line['emailInfo'] != None: 
                    newOut = {}
                    newOut['message_id'] = line['emailInfo']['xMsgRef']
                    newOut['subject'] = line['emailInfo']['subject']
                    newOut['smtp_mail_from'] = line['emailInfo']['envFrom']
                    newOut['smtp_from'] = line['emailInfo']['headerFrom']
                    newOut['message'] = "Email Received: " + newOut['subject']
                    self.ds.writeJSONEvent(newOut)
                if 'incidents' in line.keys() and line['incidents'] != None: 
                    for incident in line['incidents']:
                        newOut = {}
                        newOut['severity'] = incident['severity']
                        newOut['rule_type'] = incident['securityService']
                        newOut['rule_name'] = incident['detectionMethod']
                        newOut['rule_result'] = incident['verdict']
                        newOut['action'] = incident['action']
                        newOut['reason'] = incident['reason']
                        newOut['message_id'] = incident['xMsgRef']
                        newOut['message'] = newOut['rule_result'] + ' - ' + newOut['message_id']
                        self.ds.writeJSONEvent(newOut)
    
    def run(self):
        self.ds.log('INFO', 'Starting Run')
        # Create a cookie container
        cookies = cookielib.LWPCookieJar()
        # Load cookies from file if file exists
        if os.path.isfile(self.cookieFile) :
            cookies.load(self.cookieFile, ignore_discard=True)
            # Check if we have the cursor for the feed we are calling
            if ('all' in self.uri and self.cookieExists('ALL', cookies) is False) or ('malware' in self.uri and self.cookieExists('MALWARE', cookies) is False) :
                # Since we do not have a cursor use the reset uri
                self.uri = self.ds.config_get('symanteccloud', 'resetUri')
        # If cookie file is not on disk and you are not
        # calling the test feed use the reset call to obtain cookie
        elif 'test' not in self.uri:
            self.uri = self.ds.config_get('symanteccloud', 'resetUri')
    
        # Create HTTP handlers
        handlers = [
            urllib2.HTTPHandler(),
            urllib2.HTTPSHandler(),
            urllib2.HTTPCookieProcessor(cookies)
            ]
        # Build URL opener object and pass handelers
        opener = urllib2.build_opener(*handlers)

        try:
            # Make the request
            res = self.fetch(opener, self.uri)
            # Save the response/cookies
            self.saveFiles(res, cookies, self.cookieFile)
        
            # Keep making requests if 206 - partial content response is returned
            while res.getcode() == 206:
                #logFile = self.config['files']['logsFilePath'] + '/%s-datafeed.json' % datetime.datetime.now().strftime('%d_%m_%Y-%H_%M_%S_%f')
                res = None
                res = self.fetch(opener, self.uri)
                self.saveFiles(res, cookies, self.cookieFile)
        # Catch http errors and write them to the log file. Response errors will be in json format
        except urllib2.HTTPError, ex:
            errorResponse = ex.read()
            #fileIo = open(self.logFile,'w')
            #fileIo.write(errorResponse)
            #fileIo.close()
            self.ds.log('ERROR', str(ex))
        # Catch url errors and write them to the log file. Fails before response so create json formatted error
        except urllib2.URLError, ex:
            errorResponse = '{"error": "%s"}' % ex.reason
            #fileIo = open(logFile,'w')
            #fileIo.write(errorResponse)
            #fileIo.close() 
            self.ds.log('ERROR', str(ex))
            self.ds.log('ERROR', errorResponse)
        #self.ds.writeCEFEvent()


if __name__ == "__main__":
    i = integration(sys.argv[1:]) 
    i.run()
