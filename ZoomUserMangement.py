'''
To Do to finish app and make a true Zoom Enterprise support app:

Code Cleanup
Yes, this should have been part of the natural programming workflow, but
I just sort of started writing code in a time crunch and organically grew the program.
I was writing code to deal with support issues I had  or concepts that stemmed from
my primary goal of writing the program to update inactive users to Basic licenses.

-Method comments
-Add classes
-PEP8 Cleanup


pull color theme from : http://www.colr.org/json/scheme/random via post
http://www.colr.org/json/schemes/random/10
but this requires the full tkinter code to be recallable easily (separate gui class)

Settings
Pull Group Settings and store
Build Settings Page dynamically
Build CSV with Group settings to compare with User settings CSV

-Ops/Sign in/out Log
- Add multiple page scanning

-Improve performance of Backup of User Settings

-Fix cancel button action
-Ensure "Options that Prevent user updates" gets checked for any type of user update

-User Configuration
-Toggle buttons to appropriate state

GUI
-Adjust GUI to accomodate buttons in a better format
- Use style formatting on buttons, for a more modern look
- Add ability to collapse and open frames
- Add threading to each button for better performance
- Add confirmation dialog box
- Add Tool tips
- Add about page
- Add help


Relicense Process
- relicense
- Check user if in active meeting/webinar
- Force logout (revoke sSO token)

LDAP
-Build list of LDAP attributes for users
-Select Attribute and value to be used as a filter
to update users
- Add button to update user based on LDAP attribute filter
to specific license type (Basic/Licensed/Delete)




Email Frame:
- Add checkbox to email user before change will happen
- I.E. User will have account deleted, please retrieve all cloud recordings
- within X days.

'''

## IMPORTS ##


#from PIL import Image, ImageTk
#from io import BytesIO
import os, sys
#basePath = os.path.dirname( os.path.abspath( sys.argv[0] ) )
#sys.path.insert( 0, basePath )

import csv
import json
import jwt
import linecache

import requests

#from urllib.request import urlopen
#from urllib.request import urlretrieve
#import wget
#import cgi
#import cgitb
import pytz
import ctypes
import tzlocal
import webbrowser
import datetime
import time
import calendar
from dateutil.relativedelta import relativedelta
from dateutil import tz
from tkinter import *
from tkinter import ttk
from tkinter import filedialog

#import threading


#cgitb.enable(display=0, logdir="/")

## GLOBAL CONSTANTS ##
FROM_ZONE = tz.tzutc()
TO_ZONE = tz.tzlocal()

API_SCIM2_USER = 'https://api.zoom.us/scim2/Users'
USER_DB_FILE = "ZoomRetrievedUserList.csv"
EMAIL_FILE = 'email-list.csv'
RECDATA_FILE = "Zoom-UserRecMetaData"
RECDATA_FIELDS = ["MeetingID","Topic","StartTime","ShareLink","RecordingIDs","FileType","Host","Participants","Names","ExtraMeetingID","DownloadURL","FileSize","Cameras","Mics"]
API_FILE = 'ZoomAPI.json'
ACCT_ID_ALT = None
SETTINGS_FILE = "Zoom Group Setting Tracking"
## GLOBAL VARIABLES ##
maxMonths = 0
maxNum = 0
roles = {}
indexList = []
menuButtonList = []
cancelAction = False
fileLog = ""
statusZoom = ""
defaultFolder = ""
presets = {}
tokenError = True
localTimeZone = tzlocal.get_localzone().zone
dateInactiveThreshold = datetime.datetime.now()
leaseTime = 2
colors = {
           'blue':'#51608C',
           'gray':'#8697A6',
           'blue-gray':'#BFCDD9',
           'light-brown':'#BF8756',
           'brown':'#8C4F2B'
        }


colorScheme = {
           '0':'#000000',
           '1':'#FFFFFF',
           '22':'#BFBDBC',
           '3':'#696969',
           '33':'#31353D',
           '2':'#403F3F',
           '4':'#FFFDFB',
           '5':'#7F7E7D',
           '6':'#E5E3E1',
           '20':'#51608C',
           '30':'#8697A6',
           '40':'#BFCDD9',
           '50':'#BF8756',
           '60':'#8C4F2B'
        }


dateStr= {
        'log':'%m/%d/%y %H:%M:%S.%f',
        'std':'%m/%d/%Y %H:%M:%S',
        'user':'%m/%d/%YT%H:%M:%S',
        'file':'%Y-%m-%dT%H-%M-%S',
        '12h':'%m/%d/%Y %I:%M:%S %p %Z',
        'epoch':'%Y-%m-%dT%H:%M:%SZ',
        'calendar': "%Y-%m-%d",

    }

headerURL = 'https://api.zoom.us/'
apiVer = 'v2'
apiURL = {
        'users': 'v2/users',
        'user':'v2/users/@',
        'groups': 'v2/groups',
        'scim2': 'scim2/Users/@',
        'plan': 'v2/accounts/@/plans/usage',
        'account':'v2/accounts/@',
        'roles':'v2/roles',
        'role':'v2/roles/@/members',
        'meetings':'v2/users/@/meetings',
        'subaccount':'v2/accounts',
        'recording':'v2/users/@/recordings',
        'settings':'v2/users/@/settings',
        'acctSettings':'v2/accounts/@/settings',
        'logout':'v2/users/@/token',
        'logs':'v2/report/operationlogs',
        'signin':'v2/report/activities',
        'trackingList':'v2/tracking_fields',
        'trackingGet':'v2/tracking_fields/@',
        'emailUpdate':'v2/users/@/email',
        'groupSettings':'v2/groups/@/settings',
        'lockSettings': 'v2/accounts/@/lock_settings',
        'acctRecordings':'v2/accounts/@/recordings',
        'recRegistrants':'v2/meetings/@/recordings/registrants',
        'mtgParticipants':'v2/past_meetings/@/participants',
        'db_mtgParticipants':'v2/metrics/meetings/@/participants'       
    }

userDB = []
userRawDB = {}
groupDB = {}
userInactiveDB = []
logConfig = {}
acctRec = {}

invalidChar = [':', ';', '|', ',', '?', '<', '>', '*', '.', '"', '/', '\\', '[', ']']
####################################


def guiUpdate():
    global root
    if cancelAction is True:
        root.update()



def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False



def logging(logText ,save=True, debugOnly = False):
    """Method meant to display text in Tkinter listbox and print data, with a
        timestamp then make a call to save the listbox contents
       
    Args:  text (string), data to be logged
            save (bool), whether or not saving of listbox contents should occur
            immediately after listbox is updated.
    
    Returns:  None
    """        
    global logData
    global listbox
    global root
    global fileLog
    today = datetime.datetime.now()

    lineLenMax = 89   
    
    if debugOnly == False:
        try:
            if listbox.size() == 0:
                fileLog = f"ZoomAppLog-{datetime.datetime.strftime(today, dateStr['file'])}.txt"    
        except:
            fileLog = f"ZoomAppLog.txt"
                
        if len(logText) > 0:
            todayStr = ""
            if logConfig['timestamp'].get() == 1:
                todayStr = f'[{datetime.datetime.strftime(today, dateStr["log"])[:-3]}] ' 
            logText = f'{todayStr}{logText}'
         
            if len(logText) >= lineLenMax and logConfig['wrap'].get() == 1:
                if logText is not list:
                    if '{' in logText:
                        try:
                            logText = logText.split("Response:")
                            logText = logText[1]
                        except Exception as e:
                            print(f'!!!!!!Error in Logging: {e}, \nMessage:{logText}')
                        try:
                            if type(logText) is not list:
                                logText = logText.replace('{', '')
                                logText = logText.replace('}','')
                                logText = logText.replace('[','')
                                logText = logText.replace(']','')
                                logText = logText.replace("'",'')
                                logText = logText.replace("_",' ')
                        
                                texthalf = logText.split(",")
                                for i in range(len(texthalf) -1, -1, -1):
                                    listbox.insert(0,texthalf[i])
                            else:
                                logText = f'{logText}'
                                texthalf = logText.split(",")
                                for i in range(len(texthalf) -1, -1, -1):
                                    listbox.insert(0,texthalf[i])
                                listbox.insert(0,f'{logText}')   
                        except Exception as e:
                            print(f'!!!!!!Error in Logging: {e}, \nMessage:{logText}')
                            PrintException(e)
                    else:                
                        #logText.replace('{', '{\n')  
                        #if '}' in logText:
                        #    logText.replace('}', '}\n')
                        
                        textChunk = [logText[i:i+lineLenMax] for i in range(0, len(logText), lineLenMax)]
                        #print(f' Dated Text {len(textChunk)}:{textChunk}')
                        for i in range(len(textChunk) - 1, -1, -1):
                            #logData.set(textChunk[i])
                            listbox.insert(0, textChunk[i])
            else:
                #logData.set(logText)
                listbox.insert(0, logText)
            
            print(f"Log:  {logText}")
            root.update()
            if save == True and logConfig['save'].get() == 1:
                logSave()

def PrintException(error, errMsg = ""):
    """Method meant to display exception error type and message with line number
       and send to logging function if tkinter checkbox debug is enabled  
    Args:  None
    
    Returns:  None
    """            
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    msg = f"++Error: {errMsg}: {error},  Exception in ({filename}, LINE {lineno}, {line.strip()}: {exc_obj}, {exc_type}"
    if logConfig['debug'].get() == 1:
        logging(msg)
    else:
        print(msg)


def FolderPath():
    global defaultFolder
    global eTxtFolderPath
    
    defaultFolder = filedialog.askdirectory()
    eTxtFolderPath.delete(0,END)
    eTxtFolderPath.insert(END, defaultFolder)
    os.chdir(defaultFolder)
    logging(f"Files will be stored in: {defaultFolder}")
    logging(f"Trying to open API Command List File...")
    openAPIListDetailed()
    #tkinter.filedialog.askdirectory(**options)
    #Prompt user to select a directory.
    #Additional keyword option:
    #mustexist - determines if selection must be an existing directory.
    
def logSave():
    """Saves contents of tkinter listbox generated by logging function
    to a cleartext file in local folder
       
    Args:  None
    
    Returns:  None
    """        
    try:
        with open(fileLog, 'w') as f:
            text = '\n'.join(listbox.get(0, END))
            f.write(text)
            #f.write('\n')
            #print(f'saving file {fileLog} with: {text}')
    except Exception as e:
        #Do not use logging function here
        PrintException(e)

def timeLocal(utcTimeStr, typeval = "string"):
    
    localTZ = utcTimeStr
    
    try:
        # utc = datetime.utcnow()
        utc = datetime.datetime.strptime(utcTimeStr, dateStr["epoch"])
        
        # Tell the datetime object that it's in UTC time zone since 
        # datetime objects are 'naive' by default
        utc = pytz.utc.localize(utc)

        # Convert time zone
        localTZ = utc.astimezone(pytz.timezone(localTimeZone))
        
        if typeval == "string":
            localTZ = datetime.datetime.strftime(localTZ, dateStr["12h"])
    except Exception as e:
        pass
        #PrintException(e)
    
    return localTZ
    
def _sub(origData, header, delimiter, values):
    '''
    substitues origData string contents between hmatching header and delimiter 
    with sequential values (replaces importing regular expresssions library)
 
    Args:
      origData (string): string containing message that has contents to be substituted
      header (string):  starting character to look for 
      delimiter (string): end character to look for
      *values (dictionary): strings that will replace the contents between the header and delimiter

    Returns:
      (string) updated origData string that has the replaced values
    '''        
    data = origData.split(header)
    newData = data[0]
    for x in range(0,len(data)):
        if delimiter in data[x]:
            varId = data[x].split(delimiter)
            ##?? add management of uppercase/lowercase mismatch errors??
            if varId[0] in values:
                varId[0] = values[varId[0]]
                for item in varId:
                    newData = f'{newData}{item}' 
    return newData


def ldapAttributes():
    #from ldap3 import Server, Connection

    s = Server('my_server')
    c = Connection(s, 'my_user', 'my_password')
    c.bind()
    print(c.result)
    c.search('my_base', 'my_filter', attributes=['*'])
    print(c.result)
    print(c.response)
    c.unbind()    
        
def ldapConnect():
    #assert 'ad_user' in secrets, f"ActiveDirectory user ID secret for {params['resource_name']} is missing."
    #assert secrets['ad_user'] is not None, f"ActiveDirectory user ID secret for {params['resource_name']} is missing."
    #assert 'ad_password' in secrets, f"ActiveDirectory password secret for {params['resource_name']} is missing."
    #assert secrets['ad_password'] is not None, f"ActiveDirectory passwordsecret for {params['resource_name']} is missing."
    #assert 'ad_host' in params, f"ActiveDirectory host for {params['resource_name']} is missing."
    #assert params['ad_host'] is not None, f"ActiveDirectory host for {params['resource_name']} is missing. host={params['ad_host']}"
    #print(f"AD host:{params['ad_host']}, user:{secrets['ad_user']}, password:{secrets['ad_password']}")
    ad_conn = ldap3.Connection(
        ldap3.Server(eLDAPHost.get(), port=389, use_ssl=False, get_info=ldap3.NONE),
        auto_bind=ldap3.AUTO_BIND_NO_TLS,
        check_names=False,
        user=eLDAPUser.get(),
        password=eLDAPPass.get()
        )
    #assert ad_conn is not None, f"Unable to open Active Directory connection for {params['resource_name']} agent"

    #assert 'EnrolledUserGroupName' in params, f"Enrolled User group name configuration for {params['resource_name']} is missing."
    #assert params['EnrolledUserGroupName'] is not None, f"GEnrolled User group name configuration for  {params['resource_name']} is missing. group name={params['EnrolledUserGroupName']}"
    #assert 'GroupOu' in params, f"Group OU configuration for {params['resource_name']} is missing."
    #assert params['GroupOu'] is not None, f"Group OU configuration for {params['resource_name']} is missing. group ou={params['GroupOu']}"
    #params['GroupOu'] = f"{params['GroupOu']},{params['base_DN']}"
    #print(f"AD Group is {params['EnrolledUserGroupName']} located at {params['GroupOu']}")

    #assert 'UserOu' in params, f"User OU configuration for {params['resource_name']} is missing."
    #assert params['UserOu'] is not None, f"User OU configuration for {params['resource_name']} is missing. user ou={params['UserOu']}"
    #params['UserOu'] = f"{params['UserOu']},{params['base_DN']}"
    #print(f"User OU is {params['UserOu']}")    

    def ldapGet():
        """Callback method that retrieves actuals from the source of truth system for this provisioning resource (Active Directory via LDAP interface)
            this method:
            * creates a resource doc in the proper format for this provisioning resource
            * saves the retrieved actuals
            Actuals are retrieved in pages containing multiple entries.
        Returns:
            Integer: count of actuals retrieved

        """
        # Begin Agent implementation   ---------------------------------------------------------------------
        assert ad_conn is not None, f"ERROR.  Active Directory connection for {params['resource_name']} agent is missing"
        count = 0
        save_page_count = 0

        query = f"(memberOf=cn={params['EnrolledUserGroupName']},{params['GroupOu']})"
        # print(f"AD query: {query}")
        entry_generator = ad_conn.extend.standard.paged_search(
            search_base=params['UserOu'],
            search_filter=query,
            search_scope=ldap3.SUBTREE,
            attributes=['*'],
            paged_size=100,
            generator=True)
        entries = []
        for entry in entry_generator:
            # print(f"""ad entry:
            # {entry}""")
            doc = _create_actuals_doc(entry)
            entries.append(doc)
            if len(entries) >= int(params['AdPageSize']):
                # commit full pages
                count += save_actuals(entries)
                save_page_count += 1
                entries.clear()

        if len(entries) > 0:
            # commit partial page
            count += save_actuals(entries)
            save_page_count += 1
            entries.clear()

        print(f"LDAP query of {params['EnrolledUserGroupName']} returned {count} entries, save_page_count={save_page_count}")
        # End Agent implementation   ---------------------------------------------------------------------
        return count
 
 
def JWT_Token2(key,secret, leaseTime = 2, tokenOnly = False): 
    authHeader = ""
    
    try:
        #today = datetime.datetime.now()
        seconds = time.time()
        # Seconds since epoch

        expTime = seconds + leaseTime
        #logging (f"JWT Token generated, token Expiration {leaseTime}s: {expTime},{datetime.datetime.strftime(expTime, dateStr['epoch'])}")
        
        payload =\
                {
                    "iss":key,
                    "exp":expTime
                }
        
        encoded_jwt = jwt.encode(payload, secret, algorithm='HS256')
        
        
        ## If pyjwt version > 2.0 than comment out the line
        try:
            jwtToken = encoded_jwt.decode("utf-8")
        except:
            jwtToken = encoded_jwt
        
        
        if tokenOnly:
            return jwtToken
        
        accessToken = f'Bearer {jwtToken}'
        authHeader = {'Authorization': accessToken}
    
    except Exception as e:
        logging(f"Error in JWT Token creation: {e}")
    return authHeader

def JWT_Token(key,secret, leaseTime = 2):    
    
    today = datetime.datetime.now()
    expTime = today + datetime.timedelta(seconds=leaseTime)
    
    logging (f"Token Start: {today}")
    logging (f"Token Expiration: {expTime}")
    
    payload =\
            {
                "iss":key,
                "exp":expTime
            }
    
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256')
    
    return encoded_jwt.decode("utf-8")


    

def openCredentials():
    
    try:
        creds = csvOpen2()
        eAPIKey.set(creds[0])
        eAPISecret.set(creds[1])
        eDomain.set(creds[2])
        eLDAPHost.set(creds[3])
        eLDAPUser.set(creds[4])
        eLDAPPass.set(creds[5])
    except:
        logging("Invalid credentials file.")
 

def csvOpen2(fileDefault="", fileType = "csv", fileDesc = "CSV file", fieldNames = ""):    
    try:
        root.filename = filedialog.askopenfilename(initialdir = "./",title = "Select file",filetypes = ((f"{fileDesc}",f"*.{fileType}"),("all files","*.*")))
        fileName = root.filename
    except Exception as e:
        logging (f"Error opening file: {e}")
        fileName = fileDefault

    return csvRead(fileName, fieldNames)
    
    
def csvRead(fileName, fieldNames = ""):
    global cancelAction
    
    cancelActions(False)
    csvData = []
    
    try:
        with open(fileName, encoding="utf-8", newline='') as file:
            logging (f"Scanning file: {fileName}")
            readFile = csv.reader(file, delimiter=',')
            
            for row in readFile:
                if cancelAction is True:
                    cancelAction = False
                    break
                csvData.append(row)
            
            #Remove header row
            csvData.pop(0)
            
            logging(f'Number of Entries opened {fileName}: {len(csvData)}')
            
    except Exception as e:
        logging(f'Error in reading file: {e}')

    cancelActions('reset')
    return csvData


def actionBtnsState(state):
    global btnDeleteInactive
    global btnOpenDelete
    global btnSettingsStats
    global btnAcctAttribs
    
    if state == 'enabled':
        btnDeleteInactive["state"] = "normal"
        btnOpenDelete["state"] = "normal"
        btnSettingsStats["state"] = "normal"
        btnAcctAttribs["state"] = "normal"
    else:
        btnDeleteInactive["state"] = "disabled"
        btnOpenDelete["state"] = "disabled"
        btnSettingsStats["state"] = "disabled"
        btnAcctAttribs["state"] = "disabled"



def csvOpen():
    global userDB
    global userInactiveDB
    global cancelAction
    listboxTop()
    
    try:
        root.filename = filedialog.askopenfilename(initialdir = "./",title = "Select file",filetypes = (("csv files","*.csv"),("all files","*.*")))
        logging (f"Open File: {root.filename}")
        fileName = root.filename
    except Exception as e:
        PrintException(e)
        fileName = USER_DB_FILE
    
 
    cancelActions(False)
    
    try:
        with open(fileName) as csvfile:
            readCSV = csv.reader(csvfile, delimiter=',')
            
            userDB.clear()     
            for row in readCSV:
                if cancelAction is True:
                    cancelAction = False
                    break
                userDB.append(row)
                if row[0] != 'Active':
                    userInactiveDB.append(row)   
                logging(f'Read data: {row[2]}')
                #fieldnames = ['flag','userID','email','first_name', 'last_name','last_login','months_since','app_ver','group','license']
            
            logging(f'Number of Entries opened: {len(userDB)}')
            actionBtnsState('enabled')
   
    except Exception as e:
        logging(f'Error in reading file: {e}')
    
    cancelActions('reset')

def csvOpenDelete():
    global cancelAction
    
    cpUser = []
    rowCount = 0
    progress_var.set(0)
    listboxTop()
    
    cancelActions(False)
    
    try:
        root.filename = filedialog.askopenfilename(initialdir = "/",title = "Select file",filetypes = (("csv files","*.csv"),("all files","*.*")))
        logging (f"Open File: {root.filename}")
        fileName = root.filename
    except Exception as e:
        PrintException(e)
        fileName = EMAIL_FILE
        
    try:
        with open(fileName) as csvfile:
            readCSV = csv.reader(csvfile, delimiter=',')
            #csvLen = len(readCSV)
            
            cpUser.clear()
            #print(f"{readCSV}")
            for row in readCSV:
                if cancelAction == True:
                    cancelAction = False
                    break
                rowCount += 1
                try:
                    cpUser.append(row[0])
                except Exception as e:
                    log("Error appending email")
                
                logging(f'Read CSV data: {row}')
                #fieldnames = ['flag','userID','email','first_name', 'last_name','last_login','months_since','app_ver','group','license']
                #progress_var.set(int((rowCount/csvLen)*100))
            logging(f'Number of Entries opened: {len(cpUser)}')
        try:
            xref_UpdateUser(cpUser)
        except Exception as e:
            logging('Err xref user')
    except Exception as e:
        logging(f'Error in reading Email file: {e}')        
    
    cancelActions('reset')

def writeRawUserData(userData):
    with open('userData.json', 'w') as jsonFile:
        json.dump(userData, jsonFile)

def openRawUserData():
    data = None
    
    with open('userData.json') as json_file:
        data = json.loads(json_file)
        
    return data
    

def openAPIListDetailed():
    data = None
    from collections import OrderedDict
    try:
        with open('ZoomAPI-Detailed.json') as jsonFile:
            #data = json.load(jsonFile, object_pairs_hook=OrderedDict)
            data = json.load(jsonFile)
    
        
        for item in data:
            try:
                data[item] = OrderedDict(sorted(data[item].items()))
            except:
                pass
        
        data = OrderedDict(sorted(data.items()))    
        #for key, value in sorted(data.items(), key=lambda item: item[1])
    
    except Exception as e:
        logging(f"Zoom API File Issue: {e}")
        
        
    return data


def send_REST_request(apiType, data="", body= None, param = None, rType = "get", note = None, leaseTime = 2):
    '''
        Description:  Sends request to Zoom to pull more detailed info
                      not available in webhook event payload 
         Parameters: apiType - string - references type of API request
                     if select the correct URL from the apiURL dict
                     data - string - represents string that is appended
                     to URL to pull specified data, i.e. user ID
          
    '''
    global tokenError
    global statusZoom
    global images
    response = ""
    respData = ""
    
    tokenError = True
    
    if note is not None:
        logging(f'{note}')
    
    if rType == "image":
        logging (f"###Attempting Image DL: {apiType}")
        
        try:
            response = requests.get(url=apiType, stream=True)
            response.raw.decode_content = True
            images.append(response.raw)
            logging (f"###Response for Image DL: {response.status_code}")
        except Exception as e:
            PrintException(e)
            
        return images[-1]
    
    try:
        API_KEY = eAPIKey.get()
    except Exception as e:
        print (f"API Key Error:{e}")
        API_KEY = ""
        
    try:
        API_SECRET = eAPISecret.get()
    except Exception as e:
        print (f"API Secret error:{e}")
        API_SECRET = ""
     
    if API_KEY == "" or API_SECRET == "":
        return
    
    authHeader = JWT_Token2(API_KEY,API_SECRET,leaseTime)   

    #print(authHeader)    
    
    delimiter = ""
    if param is not None:
        delimiter = "?"
        ampersand = ""
        for key in param:
            if param[key] != '' and param[key] != None:
                delimiter = "{}{}{}={}".format(delimiter,ampersand,key,param[key])
                ampersand = "&"  
        
    if authHeader != '':
        
        if apiType in apiURL:
            url = f'{headerURL}{apiURL[apiType]}{delimiter}'
        else:
            url = f'{headerURL}{apiType}{delimiter}'
        
        try:
            if data is not None:
                if '@' in url and data != "":
                    url = url.replace("@", data)
        except Exception as e:
            PrintException(e,f'Error in url replace')

        api = f"{url}"

        start = time.time()
        
        print(f'Sending HTTP REST Request {api}, Body:{body}')   
        
        try:
            if rType == "get":
                if body is not None:
                    response = requests.get(url=api, json=body, headers=authHeader)
                else:
                    response = requests.get(url=api, headers=authHeader)
            elif rType == "put":
                response = requests.put(url=api, json=body, headers=authHeader)
            elif rType == "post":
                response = requests.post(url=api, json=body, headers=authHeader)
            elif rType == "patch":
                response = requests.patch(url=api, json=body, headers=authHeader)
                logging(f'Response: {response}')
                #print(f'Details:{respData["detail"]}')
            elif rType == "delete":
                logging(f"Sending delete REST request!!")
                response = requests.delete(url=api, headers=authHeader)
                status = response.status_code
                if response.status_code == 204:
                    msgRsp = "Succesfully deleted/removed"
                else:
                    msgRsp = "Did not delete/remove item"
                logging(f'{msgRsp} {note}: {response}')
        except Exception as e:
            logging(f'Send HTTP {rType} REST Request {api}, Response: {response}, Error:{e}')     
        try:
            status = response.status_code
            try:
                statusZoom.set(f"Zoom Resp: {status}")
            except:
                pass
            try:
                respData = response.json()
                print(f'Received HTTP REST Request {respData}')
            except Exception as e:
                print(f'No JSON data in response from request: {e}')
        
            
            if status == 404 or status == 400:
                try:
                    logging(f'{response.raw}')
                    return f'HTTP Code{status}: respData["code"],{respData["message"]}'
                except:
                    return "Error"
            elif 'code' in respData:
                logging('Send POST Request error: Code:{} Message:{}'.format(respData['code'],respData['message']))          
                return "{}\n".format(respData['message'])
            else:
                tokenError = False
            if logConfig['debug'].get() == 1:
                logging(f'Response: Code:{status} Message:{response.content}')
            
        except Exception as e:
            PrintException(e)
            statusZoom.set(f"No Response")
            logging('Processing HTTP REST Request {} error:{}'.format(api, e))
        
    return respData

def date_month_processing(direction, dateStr):

    if direction < 0:
        pass
        

def download_file(url, fileExtension, mtype = "", user = "", topic = "", topicId = "", datePath = "", desc = ""):
    #jwtToken lease time should be in minutes to accomodate download time or maybe just the initial request?.  Maybe 10 minutes?
    global cancelAction

    cancelActions(False)
    
    if cancelAction is True:
        cancelAction = False
        btnDownload["state"] = "normal"
        return    
    
    
    try:
        API_KEY = eAPIKey.get()
    except Exception as e:
        print (f"API Key Error:{e}")
        API_KEY = ""
        
    try:
        API_SECRET = eAPISecret.get()
    except Exception as e:
        print (f"API Secret error:{e}")
        API_SECRET = ""
     
    authHeader = JWT_Token2(API_KEY,API_SECRET,10, tokenOnly = True)  
    
    url = f"{url}?access_token={authHeader}"
        
    
             
    ## generate destination folder
    # define the name of the directory to be created
    path = f"/{mtype}/{user}/{topic}/{datePath}"
    fileName = f"{topic}-{datePath}-{desc}.{fileExtension}"
    
    path = path.replace(":","")
    fileName = fileName.replace(":","")
    
    logging(f"Checking download folder:  {path}") 
    
    
    
    if not is_admin(): 
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        
        except Exception as e:
            logging (f"Could not reset app to elevate permissions: {e}")
                    
    if is_admin():
        try:
            os.makedirs(path, exist_ok=True)
        except Exception as e:
            logging (f"Creation of the directory {path} failed: {e}")
        else:
            logging (f"Successfully created the directory {path}")

    
    



    if not os.path.isdir(path):
        path = ""
    
        
    logging(f"Attempting download of {url}")
    
    
    try:
        with requests.get(url, stream=True) as r:
            r.raise_for_status()

            with open(fileName, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)         
    except Exception as e:
        logging(f"Error in download")
        PrintException(e)
    
   # This didn't work 
   # try:
   #     remotefile = urlopen(url)
   #     print(f"urlopen data: {remotefile}")
   #     print(f"remotefile.info: {remotefile.info()}")
   #     blah = remotefile.info()['Content-Disposition']
   #     print(f"Blah: {blah}")
   #     value, params = cgi.parse_header(blah)
   #     filename = params["filename"]
   #     urlretrieve(url, filename)
   #     # Retrieve HTTP meta-data
   #     logging(f"Downloaded {url}:  {r.status_code}, {r.headers['content-type']}, {r.encoding}")    
   # except Exception as e:
   #     PrintException(e)
   #     logging(f"Error in download attempt method 2")
   
   # This works     
   # try:
   #     wget.download(url, fileName)
   # except Exception as e:
   #     PrintException(e)
   #     logging(f"Error in download attempt method 3")


def progress_bar_update(total = 100, increment = 1, reset = False):
    global progressCounter
    
    if reset != True:
        #cancelActions(True)
        progressCounter += increment
        bar = int((progressCounter/total)*100)
        progress_var.set(bar)
    else:
        progress_var.set(0)
        progressCounter = 0
        #cancelActions(False)
    
    root.update()
    
    
def popup_listbox_process(filesListBox, fileType = "recordings"):
    global acctRec

    fileList = [filesListBox.get(idx) for idx in filesListBox.curselection()]
    logging(f"Files to be opened:  {fileList}")
    
    totalRecords = 0  
    emails = []
    fileData = []
 
    destroy_all_subwindows()
    
    #1 Open all files first
    progress_bar_update(reset = True)
    for fileCSV in fileList:
        try:
            fileData.append(csvRead(fileCSV,RECDATA_FIELDS))
        except Exception as e:
            logging("Error reading file: {e}")
        
        progress_bar_update(len(fileList))
     
    if fileType == "recordings":
        acctRec.clear()
        acctRec = {}
        
        logging("Processing all file data....")
        
        
        
        for fileRows in fileData:
            progress_bar_update(reset = True)
            for row in fileRows:
               
                try:
                    mtgId = f"{row[0]}"
                except:
                    mtgId = 'null'
                    
                    
                if mtgId not in acctRec:
                    acctRec.update(
                        {
                            mtgId:
                            {
                                "topic":row[1],
                                "timeStart":row[2],
                                "share":row[3],
                                "recId":row[4].replace("'","").strip('][').split(', '),
                                "fileType":row[5].replace("'","").strip('][').split(', '),
                                "host":row[6],
                                "participants":row[7].replace("'","").strip('][').split(', '),
                                "names":row[8].replace("'","").strip('][').split(', '),
                                "mtgId":row[9].replace("'","").strip('][').split(', '),
                                "download":row[10].replace("'","").strip('][').split(', '),
                                "fileSize":row[11].replace("'","").strip('][').split(', ') 
                            }    
                        }
                    )
                    #print (f"Participants:{type(acctRec[mtgId]['participants'])}:  {acctRec[mtgId]['participants']}")
                    
                    try:
                        for email in acctRec[mtgId]['participants']:
                            if email not in emails and email is not None and email != "" and email != []:
                                emails.append(email)
                    except:
                        print (f"Email {email} already exists in list")
                        
                        
                    if row[6] != "" and row[6] not in emails:
                        emails.append(row[6])
                    
                    progress_bar_update(len(fileRows))
        print (f"****EMAIL LIST: {emails}")
        emails.sort()

        menuUserEmailValuesAddAll(emails)
        btnDownload["state"] = "normal"
    
    destroy_all_subwindows()
    
def popup_listbox(title = "", instruction = "", listData = []):
    global filesListBox
    
    popupListWindow = Toplevel(root)
    popupListWindow.title(title) 

    popupListWindow.configure(bg=colorScheme["3"])
    popupListWindow.resizable(height = False, width = False)

    lblPopup = stdLabelStyle(popupListWindow, text = f"{instruction}")
    lblPopup.grid(
        row = pos(0,rowPos),
        column = posC(0,colPos),
        )


    frameFileBox = stdFrameControlStyle(popupListWindow, pady = 10)
    
    frameFileBox.grid(
        row = pos(1,rowPos),
        column= posC(0,colPos)
    )


    
    sbFilesListBox= Scrollbar(
        frameFileBox,
        relief = "flat",
        troughcolor = colorScheme['4']        
        )     

    listBoxFiles = Listbox(
        frameFileBox,
        selectmode = "multiple",  
        yscrollcommand = sbFilesListBox.set,
        setgrid = 1,
        width = 60,
        activestyle= 'dotbox',
        bg= colorScheme['6'],
        fg= colorScheme['3'],
        selectbackground= colorScheme['2'],
        highlightthickness=0,
        relief = "flat",
        cursor = "hand2",
        font = stdFontStyle(size = 10, weight = "normal"),
        bd = 0      
    ) 
      
    listBoxFiles.grid(
        row = rowPos,
        column = posC(0,colPos),
        sticky = W,
        padx = 10,
        pady = 10
    )
    
    sbFilesListBox.grid(
        row = rowPos,
        column = posC(1,colPos),
        rowspan=10,
        sticky = N+S+E
    )
            
    for each_item in range(len(listData)):           
        listBoxFiles.insert(END, listData[each_item]) 
        listBoxFiles.itemconfig(each_item, bg = colorScheme['6']) 
      
    # Attach listbox to vertical scrollbar  
    sbFilesListBox.config(command = listBoxFiles.yview)
    
    btnFinished = stdButtonStyle(\
        popupListWindow,
        text = 'Open Selected Files',
        width = 30,
        image = None,
        command = lambda:popup_listbox_process(listBoxFiles)
    )
    
    btnFinished.grid(
        row = pos(1,rowPos),
        column = posC(0,colPos),
        sticky = N+S+E+W
    )
    
    popupListWindow.mainloop()     
    
def open_recordings_metadata():
    
    #Check current folder for matching files to open
    recFilesList = [fileItem for fileItem in os.listdir() if RECDATA_FILE in fileItem]
    print(recFilesList)
    popup_listbox(
        title = "Select Recording Metadata Files",
        instruction = "Select file(s) below to open",
        listData = recFilesList
    )
    #Generate Tkinter popup window with listbox and the ability to select
    #multiple items in listbox
    
    
    
def download_participant_recordings():
    global acctRec
    global userEmail
    global cancelAction    
    
    notFound = True
    userEmail = userEmailAddr.get()
    #print (f"{acctRec}")
    # TODO Eventually user can choose from multiple CSV files to open to scan through    
    logging(f"Checking if {userEmail} has any existing recordings they were a participant in")  
    
    
    
    for mtg in acctRec:
        #print(f"{mtg}")
        try:
            if not acctRec[mtg]["participants"]:
                acctRec[mtg]["participants"].append(acctRec[mtg]["host"])
        except:
            pass
        
          
        if userEmail in acctRec[mtg]["participants"]:
            topic = acctRec[mtg]["topic"]
            timeStart = acctRec[mtg]["timeStart"]
            notFound = False
            logging(f"{userEmail} has {len(acctRec[mtg]['download'])} files in meeting {topic}: {timeStart} they were recorded in.")    
            
            for fileURL in acctRec[mtg]["download"]:
                idx = acctRec[mtg]["download"].index(fileURL)
                fileExtenson = acctRec[mtg]["fileExtension"][idx]
                
                download_file(
                    fileURL,
                    fileType = fileType,
                    mtype = "recording",
                    user = userEmail,
                    topic = topic,
                    topicId = mtg,
                    datePath = timeStart,
                    desc = f"{idx}"
                )
        
    if notFound:
        logging(f"{userEmail} does not have any existing recordings they were a participant in")  


def get_recording_dates():
        try:
            calDate = datetime.datetime.strptime(eTxtRecDates.get(), '%Y-%m')
        except:
            calDate = datetime.datetime.now()
        
        return calDate
    

def get_account_recordings(months = None, dateStart = None, dateEnd = None, cnt = 0, next_page_token = None, total = None, recData = {}):
    '''
    Retrieve all recording IDs from account
 
    Args:
      userID (string): Zoom user ID value

    Returns:
      (dict) dict of recording IDs and details
    '''
    global acctRec
    global cancelAction
    
    accountId = acct_id()
    pageSize = 300
    
    
    if dateStart is None:
        try:
            months = int(eRecMonths.get())
        except:
            months = 1
            
       
        cnt = 0
        
        acctRec.clear()
        
        calDate = get_recording_dates()
        
        dateStart = calDate.strftime("%Y-%m-01")
        dateEnd = calDate.strftime("%Y-%m-15")
           
      
            
        cancelActions(False)
         
    MAX_PAGE_SIZE = 300
    
    query = {
        "page_size":MAX_PAGE_SIZE, #DEFAULT IS 30 IN ZOOM
        "next_page_token":next_page_token, 
        "from":dateStart,
        "to": dateEnd
    }
    
    
    if cancelAction is True:
        cancelAction = False
        btnDownload["state"] = "normal"
        return
      
    #1.  Get all records of recordins on account based on time period
        record = None
    try:
        record = send_REST_request('acctRecordings', data=accountId, param=query, rType = "get", leaseTime = 6)
        recordsTotal = record["total_records"]
        
        if recordsTotal == 0:
            send_REST_request('acctRecordings', data=accountId, param=query, rType = "get", leaseTime = 6)
            recordsTotal = record["total_records"]
            
    except:
        record = None
        recordsTotal = total



    if record is None:
        logging(f"No recording metadata available for pass #{cnt}") 
    else:
        try:
            steps = ((int(eRecMonths.get())) - months) + 1
        except:
            steps = 1
            
        logging(f"Starting recording metadata scan, step {steps}/{(int(eRecMonths.get()) * 3)}")        
        next_page_token = record["next_page_token"]
        
        calDate = datetime.datetime.strptime(dateStart, '%Y-%m-%d')
        logging(f"Reading Cloud Recording metadata for {calendar.month_name[calDate.month]}-{calDate.year}: ({cnt}/{recordsTotal})")
            
        #2.  Check each record returned and save meeting ID and separately store host names and recording IDs
        for item in record["meetings"]:
            mtgId = item["uuid"]
            if mtgId not in acctRec:
                acctRec.update(
                    {
                        mtgId:
                        {
                            "topic":item["topic"],
                            "timeStart":item["start_time"],
                            "recId":[],
                            "fileType":[],
                            "host":item["host_email"],
                            "participants":[],
                            "names":[],
                            "mtgId":[],
                            "share":"",
                            "download":[],
                            "fileSize":[],
                            
                        }
                    }
                )
            
            try:
                acctRec[mtgId]["share"] = item["share_url"]
            except:
                acctRec[mtgId]["share"] = ""
            
            for rec in item["recording_files"]: 
                acctRec[mtgId]["recId"].append(rec["id"])
                try:
                    acctRec[mtgId]["mtgId"].append(rec["meeting_id"])
                except:
                    acctRec[mtgId]["mtgId"].append(mtgId)  
                try:
                    acctRec[mtgId]["download"].append(rec["download_url"])
                except:
                    acctRec[mtgId]["download"].append("")
                try:
                    acctRec[mtgId]["fileType"].append(rec["file_type"])
                except:
                    acctRec[mtgId]["fileType"].append("")
                try:
                    acctRec[mtgId]["fileSize"].append(rec["file_size"])
                except:
                    acctRec[mtgId]["fileSize"].append(0)    
            
                
    try:
        cnt += len(record["meetings"])
    except:
        #cnt += MAX_PAGE_SIZE
        pass
        
    if cnt >= recordsTotal:
        calDate = get_recording_dates()
        
        if dateEnd == calDate.strftime("%Y-%m-15"):
            cnt = 0
            next_page_token = ""
            dateStart = calDate.strftime("%Y-%m-16")
            endDateRaw = datetime.date(calDate.year, calDate.month, calendar.monthrange(calDate.year, calDate.month)[-1])
            dateEnd = endDateRaw.strftime("%Y-%m-%d")
            
            try:
                steps = ((int(eRecMonths.get())) - months) + 2
            except:
                steps = 2 
                
            logging(f"Starting recording metadata scan, step {steps}/{(int(eRecMonths.get()) * 3)}")
        elif months < 1:
            logging(f"Recording metadata scan completed")
            btnDownload["state"] = "normal"
            return
        
        
    bar = int((cnt/recordsTotal)*100) 
    progress_var.set(bar)
    
    #Check performance of this
    root.update()
    
    if next_page_token != "" or cnt == 0:
        get_account_recordings(
            months = months,
            dateStart = dateStart,
            dateEnd = dateEnd,
            cnt = cnt,
            next_page_token=next_page_token,
            total = recordsTotal,
            recData = acctRec
            )
    else:
        calDate = datetime.datetime.strptime(dateStart, '%Y-%m-%d')
        dateStart = calDate.strftime("%Y-%m-01")
        
        try:
            steps = ((int(eRecMonths.get())) - months) + 3
        except:
            steps = 3
                
        logging(f" Starting Participant scan, step {steps}/{(int(eRecMonths.get()) * 3)}")
        logging(f"Reading Meeting participant emails for {len(acctRec)} meetings...")
        get_meeting_participants(acctRec)
        save_user_rec_metadata(acctRec,dateStart,dateEnd)
        months = months - 1
        if months > 0:
            calDate = calDate.replace(
                year = calDate.year if calDate.month > 1 else calDate.year - 1,
                month = calDate.month - 1 if calDate.month > 1 else 12,
                day = 1
            )
            
            dateStart = calDate.strftime("%Y-%m-01")
            dateEnd = calDate.strftime("%Y-%m-15")
            
            print (f"Months To Check: {months}, Next Batch:  From: {dateStart} To: {dateEnd}")
            get_account_recordings(
                months = months,
                dateStart = dateStart,
                dateEnd = dateEnd,
                cnt = 0,
                next_page_token = None,
                recData = acctRec
            )
        
        #if months > 0:
        #    pass
        #    #TODO decrement month with logic and update start and end dates and iterate again through function
        #else:
        #    return        

    
def get_meeting_unknown_participants(recData, meetingUUID, mtgType = "past", next_page_token = None, cnt = 0):
    '''
    Retrieve all unknown registrant IDs and host ID for each recording
 
    Args:
      userID (string): Zoom user ID value

    Returns:
      (dict) appends userIDs part of recording to recDict
    '''
    pageSize = 300        
       
    queryDB = {
        "type": mtgType,
        "page_size":300, #DEFAULT IS 30 IN ZOOM
        "next_page_token":next_page_token,
        "include_fields":"registrant_id",
    }
        
        
    try:
        #Needs meeting UUID vs meeting ID to get a specific meeting instance
        record_db = send_REST_request('db_mtgParticipants', data=meetingUUID, param=queryDB, rType = "get")
        
        recordsTotal = record["total_records"]
        next_page_token = record["next_page_token"]
        
        #logging(f"Reading Meeting participant emails for meeting #({cnt} out of {len(recData)})")                       
        bar = int((cnt/len(recData))*100) 
        progress_var.set(bar)
        #Check performance of this
        root.update()
    
        for participant in record["participants"]:
            if participant["user_name"] != "":
                recData[meetingUUID]["names"].append(participant["user_name"])
            if participant["microphone"] != "":
                recData[meetingUUID]["camera"].append(participant["microphone"])
            if participant["camera"] != "":
                recData[meetingUUID]["mic"].append(participant["camera"])
        
    except Exception as e:
        #PrintException(e)
        logging(f'Issue with:  {meetingUUID}, {e}')
    
 


def get_meeting_participants(recData, next_page_token = None, cnt = 0):
    '''
    Retrieve all registrant userIDs and host ID for each recording
 
    Args:
      userID (string): Zoom user ID value

    Returns:
      (dict) appends userIDs part of recording to recDict
    '''
    global cancelAction
    
    pageSize = 300
    
    
    if next_page_token is None:
        cnt = 0
        cancelActions(False)
         
    

      
    # Get all participants in meeting
    cnt = 0
    
    for meetingUUID in recData:
        if cancelAction is True:
            cancelAction = False
            return
        
        cnt += 1
        query = {
            "page_size":300, #DEFAULT IS 30 IN ZOOM
            "next_page_token":next_page_token, 
        }
        
        queryDB = {
            "type":"past",
            "page_size":300, #DEFAULT IS 30 IN ZOOM
            "next_page_token":next_page_token,
            "include_fields":"registrant_id",
        }
        
        
        try:
            #Needs meeting UUID vs meeting ID to get a specific meeting instance
            record = send_REST_request('mtgParticipants', data=meetingUUID, param=query, rType = "get")
            record_db = send_REST_request('db_mtgParticipants', data=meetingUUID, param=queryDB, rType = "get")
            
            recordsTotal = record["total_records"]
            next_page_token = record["next_page_token"]
            
            #logging(f"Reading Meeting participant emails for meeting #({cnt} out of {len(recData)})")                       
            bar = int((cnt/len(recData))*100) 
            progress_var.set(bar)
            #Check performance of this
            root.update()
            
            for participant in record["participants"]:
                if participant["user_email"] != "":
                    recData[meetingUUID]["participants"].append(participant["user_email"])
                    recData[meetingUUID]["names"].append(participant["name"])
            
        except Exception as e:
            #PrintException(e)
            logging(f'No participants for meeting #{cnt}/{len(recData)}:  {meetingUUID}')
        
        
        #print(f"{len(recData)} Entries to be saved")
        
        

def save_user_rec_metadata(recData,startDate,endDate):
    try:
        with open(f'{RECDATA_FILE}-{startDate} to {endDate}.csv', 'w', encoding="utf-8", newline='') as csvFile:
            writer = csv.DictWriter(csvFile, fieldnames = RECDATA_FIELDS)
            writer.writeheader()
            
            
            for meetingID in recData:
                csvRow = {\
                    "MeetingID": meetingID,
                    "Topic":recData[meetingID]["topic"],
                    "StartTime":recData[meetingID]["timeStart"],
                    "ShareLink":recData[meetingID]["share"],
                    "RecordingIDs": recData[meetingID]["recId"],
                    "FileType":recData[meetingID]["fileType"],
                    "Host":recData[meetingID]["host"],
                    "Participants":recData[meetingID]["participants"],
                    "Name": recData[meetingID]["names"],
                    "ExtraMeetingID":recData[meetingID]["mtgId"],
                    "DownloadURL":recData[meetingID]["download"],
                    "FileSize":recData[meetingID]["fileSize"]
                }
                writer.writerow(csvRow)
    except Exception as e:
        logging(f'Error saving Recording metadata IDs: {e}')
        
def get_user_recordings(userID):
    '''
    Searches all recordings where userID was a part of
 
    Args:
      userID (string): Zoom user ID value

    Returns:
      (dict) dict of recording IDs and details where
      userID was a registrant or host.
    '''
    
    
    
    
def get_user_meetings(userID):
    meetings = None
    try:
        meetingsAll = send_REST_request('meetings',data = userID, param = {'type':'scheduled','page_size':1})
        meetings = send_REST_request('meetings',data = userID, param = {'type':'upcoming','page_size':300})
        print (f"Meeting Data: {meetings}")
    except Exception as e:
        logging(f"Error getting meeting data {e}")
    
    meetingCnt = 0
    meetingScheduled = 0
    meetingAllCnt = 0
    if meetingsAll is not None:
        try:
            meetingsAllCnt = meetingsAll['total_records']
        except Exception as e:
            PrintException(e)
            logging(f'!Error getting all meeting count:{e}')
            
    if meetings is not None:
        try:
            meetingCnt = meetings['total_records']
            
        except Exception as e:
            PrintException(e)
            logging(f'!Error getting meeting count:{e}')        
        try:     
            for record in meetings["meetings"]:
                if record['type'] == 2 or record['type'] == 8:
                    meetingScheduled += 1
        except Exception as e:
            PrintException(e)
            logging(f'!Error getting meeting data: {e}')
    return (meetingsAllCnt, meetingCnt, meetingScheduled)


def logoutUser():
    """ Will trigger the revocation of SSO token for user, and in effect, log user out
        of all devices they are logged into for Zoom.  User email address is pulled from
        User Email Address tkinter text entry field.
       
    Args:  None
    
    Returns:  None
    """            
    global userDB
    
    userID = get_userID(userEmailAddr.get())
    
    send_REST_request('logout', data=userID, rType = "delete", note=f"Attempt to Logout {userEmailAddr.get()} from all devices")
    
    
def set_user_Email(userID, newEmail):
    
    update = {"email":newEmail}
    
    try:
        send_REST_request('emailUpdate', data=userID, body=update, rType = "put", note=f"Attempt to Update Zoom acct user {userEmailAddr.get()} to {newEmail}")
        update_userDB(userID, "Email", newEmail)
    except Exception as e:
        errMsg = f"user {userEmailAddr.get()} email update failed."
        PrintException(e, errMsg)
    
def get_userID(userEmail):
    licNo = 1
    emailIdx = 1
    userIdIdx = 2
    licenseIdx =  8
    userDBdef = ["Flags","Email","User ID","First Name", "Last Name", "Last Login", "Client Ver", "Group", "License","Months", "Picture URL"]
    
    userEmail = userEmailAddr.get()

    try:
        for user in userDB:
            if user[emailIdx] == userEmail:
                return user[userIdIdx]
    except:
        pass
        
    return None

def delete_user(userID, userEmail=""):
    logging (f'Attempting to delete {userEmail}')
    
    deleteStatus = send_REST_request('user', data = userID, param = {"action":"delete"}, rType = "delete", note=userEmail)
    
    if '204' in deleteStatus:
        update_userDB("Email",userID, None)


def update_userDB(userID, category, value):
    global userDB
      
    userDBdef = ["Flags","Email","User ID","First Name", "Last Name", "Last Login", "Client Ver", "Group", "License","Months", "Picture URL"]
    userIdIdx = 2

    itemIdx = userDBdef.index(category)
    
    
    
    for user in userDB:
        if userID in user[userIdIdx]:
            if category == userDBdef[userIdIdx] and value == None:
                userDB.remove(user)
                break
            else:
                idx = userDB.index(user)
                userDB[idx][itemIdx] = value
                break
    
def update_field(field, data):   
    if field is type(StringVar):
        if data is None:
            data = ''
        field.set(str(data))
        field.delete(0,"end")
        field.insert(0, data)
    else:
        if data is not None:
            field.set(data)    

def groupParse(groupName):
    if groupName == 'No Group':
        group = "AcctSetting"
    else:
        groups = groupName.split(":  ")
        group = groups[1]
    
    return group
        
def get_UserInfo(user):
    global menuUserGroupItems
    
    licNo = 1
    emailIdx = 1
    userIdIdx = 2
    licenseIdx =  8
    groupIdx = 7
    
    print("User Data:  {user}")
    
    #Blank all fields first
    for content in userTxtData:
        update_field(userTxtData[content],None)    
    
    
    userId = user[userIdIdx]
    userDBdef = ["Flags","Email","User ID","First Name", "Last Name", "Last Login", "Client Ver", "Group", "License","Months Inactive", "Picture URL"]
    
    userEmail = user[emailIdx]
    
    group = groupParse(user[groupIdx]) 
    
    for item in menuUserGroupItems:
        menuUserGroupItems[item]['type'].set(0)
        
    menuUserGroupItems[group]['type'].set(1)
    
    userInfo = send_REST_request('user', data=userId, rType = "get", note="Getting user info")
    
    #User Image link
    if len(user[-1])> 0:
        picLink.set(user[-1])
        lblUserPicLink['text'] = 'User Image'
    else:
        picLink.set(user[-1])
        lblUserPicLink['text'] = 'No Image available'
    root.update()
     
    
    for item in userInfo:
        try:
            if item in userTxtData:
                userRoleValue.set(userInfo['role_name'])
                print (f'###Item: {item}, obj:{userTxtData[item]}, Contents: {userInfo[item]}')    
                #userDataField[item].set(userInfo[item])
                update_field(userTxtData[item],userInfo[item])
                root.update()
        except Exception as e:
            PrintException(e,"Error update user fields")
            
    userSettings = {}             
    try:
        userSettings = get_user_settings(userId, type=2, count = 0)
       
        for setting in userSettings['feature']:
            text = setting
            if setting is type(str):
                try:
                    print(f"Object is string: {setting}")
                    text = setting.replace("_", " ")
                except:
                    text = setting
                logging(f'{text}: {userSettings["feature"][setting]}')
            else:
                logging(f'{text}: {userSettings["feature"][setting]}')
       
    except Exception as e:
        PrintException(e,f"User {userId} Setting can't be retrieved")
    
    try:
        k = ''  
        
        if userSettings != {}:
            diffCount = 0
            diffLen = 0
            for category in userSettings:
                try:
                    groupVal = groupDB[group][category]
                    userVal = userSettings[category]
                    
                    diffSettings = {k: userVal[k] for k in groupVal if k in userVal and groupVal[k] != userVal[k]}
                    diffLen = len(diffSettings.keys())         
                    logging(diffSettings)
                except:
                    pass
            logging(f'# of differences to {group} group settings: {diffLen}')
    except Exception as e:
        PrintException(e,f"User:{userId}")
    
    try:
        logging(f'Recordings: {check_user_recording_count(userId)}')
    except Exception as e:
        logging(f'Recordings in the last {eRecMonths.get()} months: {e}')
    
    try:
        (meetingsAll, meetingsUpcoming, meetingsSched) = get_user_meetings(userId)
        logging(f'All Time Meeting Total:{meetingsAll}')
        logging(f'Upcoming Meeting Total:{meetingsUpcoming}')
        logging(f'Upcoming Scheduled Meetings:{meetingsSched}')
    except Exception as e:
        logging(f'Upcoming Meetings {e}')
    
    
    #Last message in log so it shows at the top of the log, and all items below
    #it would be the contents that are retrieved
    logging(f'User Info: {userEmail}')
    
    

    #try:
    #    imageURL = user[-1]
    #    print(f"Image URL: {imageURL}")
    #    userImage = send_REST_request(
    #        imageURL,
    #        rType = "image",
    #        note="Getting user image"
    #    )
    #    print(f"##$$$##Extracting Image Data")
    #    im = Image.open(io.BytesIO(userImage))
    #    img = ImageTk.PhotoImage(im)
    #    print(f"##$$$##Build Picture Window")
    #    dialogBox = Toplevel(root)
    ##    dialogBox.title("Image")
    #    dialogBox.resizable(height = True, width = True)  
    #    dialogFrame = LabelFrame(dialogBox, padx = 100, pady = 10, bg = colorScheme['3'], fg = colorScheme['1'], image = img)
    #    dialogFrame.grid(row = 0 , column = 0, sticky = W)        
     #   imageUserFrame.configure(image=img)
    #except Exception as e:
    #    print(f"##$$$##Image Error: {e}")
    #    PrintException(e)
        
def UpdateUser_Delete():
    listboxTop()
    
    userEmail = userEmailAddr.get()
    userID =  get_userID(userEmail)
    
    delete_user(userID,userEmail)
    
    
def UpdateUser_Email():
    email = userEmailAddr.get()
    logging (f"Attempting to update user {email} email's address")
    userID = get_userID(email)
    newEmail = etxtUpdateEmail.get()
    set_user_Email(userID, newEmail)
    
def deleteUser_Role():
    '''
    Removes a Zoom all user's roles to ensure they can be deprovisoned
    if they are in a deletion-restricted role

    Args:
      None
    Returns:
      None
    '''
    userEmail = userEmailAddr.get()
    userID =  get_userID(userEmail)
    
    userInfo = get_user_data(userID)

    # 2.  Find role Id that was pulled on class init
    print(f'Roles: {roles}')
    if roles == {}:
        logging('No roles have been retrieved from settings page')
    else:
        if userInfo['role_name'] in roles:
            roleId = roles[userInfo['role_name']]
        else:
            roleId = None

        #3. Set user role to basic member
        response = \
            send_REST_request(\
              f'v2/roles/{roleId}/members/{userID}',
              data = None,
              body = None,
              rType = "delete"
        )
        
        logging(f'Response for attempting removal of role:  {response}')

def UpdateUser_Role():
    '''
    Updates a Zoom all user's role based on tkinter drop down list values

    Args:
        None
    Returns:
        None
    '''
    testRole()

def testRole():
    userEmail = userEmailAddr.get()
    userId =  get_userID(userEmail)
    
    userInfo = get_user_data(userId)
    userNewRole = userRoleValue.get()
    # 2.  Find role Id that was pulled on class init    
    print(f'Roles: {roles}, New Role Proposed: {userNewRole}')
    if roles == {}:
        logging('No roles have been retrieved from settings page')
    else:
        if userInfo['role_name'] in roles:
            currentRoleId = roles[userInfo['role_name']]
            newRoleId = roles[userNewRole]
        else:
            currentRoleId = None
            newRoleId = None


        roleId = newRoleId
        #3. Set user role based on entry field
        response = \
            send_REST_request(
              'role',
              data = roleId,
              body = {
                  'members':[{
                      "id":userId
                  }]
              },
              rType = "post"
        )
        
        logging(f'Response for attempting update of role:  {response}')
           
    
    
def UpdateUser_Info():
    global groupDB
    global userDB
    emailIdx = 1
    userIdIdx = 2
    userDBdef = ["Flags","Email","User ID","First Name", "Last Name", "Last Login", "Client Ver", "Group", "License","Months Inactive", "Picture URL"]
    
    userEmail = userEmailAddr.get()
  
   ##@@TODO Clear all fields first
    ## Populate raw dict with full user info      
    try:
        for user in userDB:
            if user[emailIdx] == userEmail:
                get_UserInfo(user)
                
                for item in user:
                    try:
                        key = userDBdef[user.index(item)]    
                    except Exception as e:
                        key = f"{e}"
                        ##@@@@TODO Chek
                    logging(f'{key}: {item}')
                break
        else:
            if len(userDB) < 1:
                logging(f'Please retrieve Zoom user\'s data first.')
       
    except Exception as e:
        PrintException(e)
        logging(f"Error getting user info: {e}")
        
    listboxTop()

def listboxTop():
    listbox.see(0)
    root.update()
   
def updateUser_Feature(feature):
    """Method to toggle user feature setting to opposite value
    
    Args:  feature (string), should be a string containing a zoom user setting feature
           i.e. Webinar, Large Meeting
    
    Returns:  None
    """
    listboxTop()
    userEmail = userEmailAddr.get()
    userID =  get_userID(userEmail)
    userSetting = get_user_settings(userID, type = 2,  count = 0)
    state = not userSetting['feature'][feature]
    update = \
           {
               'feature':\
                {
                   feature:state
                }
           }
    
    logging (f'Attempting to set {feature} to {state}')
    updateFeature = send_REST_request('settings', data = userID, body = update, rType = "patch")
     
    userSetting = get_user_settings(userID, type = 2,  count = 0)
      
    if userSetting['feature'][feature] != state:
        logging (f'Failed to set {feature} to {state}')

def UpdateUser_Webinar():
    """Method meant for tkinter button callback to trigger toggling webinar license for
       a specified user.
       
    Args:  None
    
    Returns:  None
    """    
    updateUser_Feature('webinar')
    
    

def UpdateUser_LargeMtg():
    """Method meant for tkinter button callback to trigger toggling large meeting license for
       a specified user.
       
    Args:  None
    
    Returns:  None
    """    
    updateUser_Feature('large_meeting')    
    

def UpdateUser_Basic():
    global userDB
    licType = 'Basic'
    licNo = 1
    emailIdx = 1
    userIdIdx = 2
    licenseIdx =  8
    
    listboxTop()
    userEmail = userEmailAddr.get()
    for user in userDB:
        if user[emailIdx] == userEmail:
            logging(f'Updating {userEmail} to {licType}')
            userID = user[userIdIdx]
            userCurrLicense = user[licenseIdx] 
            modify_user_license(userID,userEmail, userCurrLicense, userType=licNo)
            break
            
def UpdateUser_Licensed():
    global userDB
    licType = 'Licensed'
    licNo = 2
    emailIdx = 1
    userIdIdx = 2
    licenseIdx =  8
    listboxTop()
    userEmail = userEmailAddr.get()
    for user in userDB:
        if user[emailIdx] == userEmail:
            logging(f'Updating {userEmail} to {licType}')
            userID = user[userIdIdx]
            userCurrLicense = user[licenseIdx] 
            modify_user_license(userID,userEmail, userCurrLicense, userType=licNo)
            break            

def filterUser(user):
    userGroup = user[7]
    userLicense = user[8]
    months = user[9]
    
    
    chkParam = [False, False, False, False, False]

    userGroup = extract_group(userGroup)
    group = filterGroup.get()


    if group == 'All Users':
        group = None
    elif group == 'Users in no Groups':
        group = 'No Group'
        
    if group is not None and userGroup != group:
        chkParam[4] = True            

    if chkActivity.get() == 1 and chkParam[4] == False:
        try:
            monthsActive = int(eActiveUser.get())
        except:
            monthsActive = 0
       
        if months <= monthsActive :
            chkParam[0] = True
                
    if chkRec.get() == 1 and chkParam[4] == False:
        try:
            recMonths = int(eRecMonths.get())
        except:
            recMonths = 0
        
        recordings = check_user_recording_count(user[userIdIdx])
        
        if recordings > 0:
            chkParam[1] = True
       
        logging('{}: {} has {} recordings and last logged in {} months ago'.format(userGroup,email,recordings,months))
        
    if chkMeetings.get() == 1 and chkParam[4] == False:
        (meetingsAllCnt, meetingCnt, meetingScheduled) = get_user_meetings(user[userIdIdx])
        if meetingScheduled > 0:
            chkParam[2] = True

    if chkBasic.get() == 1:
        chkParam[3] = True


    testing = logConfig['test'].get()
    
    return (testing, chkParam)

def xref_UpdateUser(userList):
    emailIdx = 1
    userIdIdx = 2
    monthsIdx = 6
    groupIdx = 7
    licenseIdx =  8
    email = ""
    userCount = 0
    recordings = 0
    months = ""
    progress_var.set(0)
    logging("Removing Users based on imported list....")
    
    print(f"\nData:::\n{userList}\n{userDB}")
    userEmails = len(userList) - 1

    monthsActive = None
    recMonths = None
    meetings = None
    noDeletes = None
    
    
    chkParam = [False, False, False, False, False]
        
    for email in userList:
        userCount += 1
        for user in userDB:
            if user[emailIdx] == email:
                userLicense = user[8]
                
                (testing, chkParam) = filterUser(user)
                 
                try:
                    if True not in chkParam:
                        # No checkboxes, and group matches, just delete
                        if logConfig['test'].get() == 0:
                            delete_users_list(user[userIdIdx], email)
                        else:
                            logging(f"TESTING: {email} is being deleted.")
                            
                    elif chkParam[3] is True:
                        # If No Deletes is enabled then send user to basic
                        # no other parameters are true
                        chkParam[3] = False
                        if True not in chkParam:
                            if testing == 0:
                                modify_user_license(user[userIdIdx],email, userLicense)
                            else:
                                logging(f"TESTING:  {email} is being modified to {userLicense}.")
                        else:
                            logging(f"{email} is not being deleted or modified.")
                    
                    
                    else:
                        logging("{} is not being deleted or modified.".format(email))     
                except Exception as e:
                    logging(f'Error Updating User: {e}')
            
        progress_var.set(int((userCount/userEmails)*100))            
    else:
        logging("No users to remove")
    logging("Finished removing users....")                    
                
    
def start_modify_user(email):
    emailIdx = 1
    userIdIdx = 2
    monthsIdx = 6
    groupIdx = 7
    licenseIdx =  8
    userCount = 0
    recordings = 0
    months = ""
    progress_var.set(0)
    counter = 0
    monthsActive = None
    recMonths = None
    meetings = None
    noDeletes = None
    
    chkParam = [False, False, False, False, False]   
    
    for user in userDB:
        if user[emailIdx] == email:
            userGroup = user[7]
            userLicense = user[8]
            months = user[9]
            
            modifyLicense = "Basic"
            
            (testing, chkParam) = filterUser(user)
                            
            try:
                if True not in chkParam:
                    # No checkboxes, and group matches, just delete
                    if testing == 0:
                        delete_user(user[userIdIdx],userEmail)
                    else:
                        logging(f"TESTING: {user[groupIdx]},{email} is being deleted.")
                    return 1
                elif chkParam[3] is True:
                    # If No Deletes is enabled then send user to basic
                    # no other parameters are true
                    chkParam[3] = False
                    if True not in chkParam:
                        if testing == 0:
                            modify_user_license(user[userIdIdx],email, userLicense)
                        else:
                            logging(f"TEST: {user[groupIdx]}, {email} is being modified to {modifyLicense}.")
                        return 1
                    else:
                        pass
                        #logging(f"{email} is not being deleted or modified.")
                else:
                    pass
                    #logging(f"{email} is not being deleted or modified.")     
            except Exception as e:
                logging(f'Error Updating User: {e}')
    return 0

def extract_group(group):
    if group != 'No Group':
        userGroups = group.split(":  ")
        userGroup = userGroups[1]
    else:
        userGroup = group
        
    return userGroup

def get_group_data():
    groupData = {}
        
    try:
        groups = send_REST_request('groups', rType = "get")
    except Exception as e:
        groups = None
        print(f'Exception:{e}')    
   
    if groups != None:
        try:
            total_groups = groups['total_records']
            logging(f'Number of groups found: {total_groups}')
        except Exception as e:
            logging(f'Groups Count issue:{e}')
            total_groups = 0              
        
       
        # loop through all pages and return user data    
        for record in range(1, total_groups):
            try:
                gName = groups['groups'][record]['name']
            except Exception as e:
                logging('No Group Name')
                gName = ''
            try:
                gID = groups['groups'][record]['id']
            except Exception as e:
                logging(f'No Group ID:  {e}')
                gID = ''
            
            try:
                groupData.update({gID:gName})
            except Exception as e:
                logging(f'Error in storing group data: {e}')
                

    return groupData


def groupMenuInit(origin, groupData = None, menuObj = None):
    groupMenu = {} 
    
    # get # of groups
    # add groups into menu
    # return
    if menuObj is None:
        menuObj =  Menubutton (origin, text= "Group", relief=RAISED )
        menuObj.grid()
        menuObj.menu  =  Menu ( menuObj, tearoff = 0 )
        menuObj["menu"]  =  menuObj.menu
    else:
        menuObj.grid()
    
    try:
        if groupData is None:
            groupData = get_group_data()
            
        try:
            menuObj.menu.delete(0, len(groupData)) 
        except Exception as e:
            PrintException(e)
      
        for group in groupData:
            groupName = groupData[group]
            #1. Create group name in dictionary
            groupMenu[groupName] = {}
            #2 Add variable type to dict under group
            groupMenu[groupName].update({'type':IntVar(value = 0)})
            #3 Add tkinter menu object to dict under group
            groupMenu[groupName].update({
                'obj': menuObj.menu.add_checkbutton (
                    label=groupName,
                    variable=groupMenu[groupName]['type']
                )
        })
            
        root.update()
        print (f'### Menu: {groupMenu}')
    except Exception as e:
        PrintException(e)
        
    return (menuObj, groupMenu)

def validate_user_modification(userID):
    pass
    
    
def modify_user_license(userID,userEmail, userCurrLicense, userType=1):
      
    userDesc = f"{userEmail} will be updated from {userCurrLicense} to {userType}"
    
    data =\
        {
            "type": userType
        }   
    
    send_REST_request('user', data=userID, body=data, rType = "patch", note=userDesc)
   
    userLicense =\
       {
           "1":"Basic",
           "2":"Licensed",
           "3":"On-Prem"
       }
   
   
    update_userDB(userID, "License", userLicense[str(userType)])
      



def monthsDate(startDate, endDate):
    
    current = datetime.datetime.now()
    prev_month_lastday =  datetime.datetime.now()
    
    for i in range (0,monthsCheck,1):
        _first_day = prev_month_lastday.replace(day=1)
        if i>0:
            prev_month_lastday = _first_day - datetime.timedelta(days=1)
    
        lastDate = prev_month_lastday.replace(day=1)
    
        monthStart = prev_month_lastday.strftime("%Y-%m-01")
        lastDay = (lastDate + relativedelta(day=31)).day
        monthEnd = prev_month_lastday.strftime("%Y-%m-{}".format(lastDay))    
 
    return (monthStart,lastDay,monthEnd)

def check_user_recording_count(userID):
    userRec = {}
    response = ""
    print('Validating recordings for: {}'.format(userID))
    
    try:
        monthsCheck = int(eRecMonths.get())
    except:
        monthsCheck = 0
        
    current = datetime.datetime.now()
    prev_month_lastday =  datetime.datetime.now()

    for i in range (0,monthsCheck,1):
        _first_day = prev_month_lastday.replace(day=1)
        if i>0:
            prev_month_lastday = _first_day - datetime.timedelta(days=1)
    
        lastDate = prev_month_lastday.replace(day=1)
    
        monthStart = prev_month_lastday.strftime("%Y-%m-01")
        lastDay = (lastDate + relativedelta(day=31)).day
        monthEnd = prev_month_lastday.strftime("%Y-%m-{}".format(lastDay))
        try:
            apiParam =\
                     {
                         'to':monthEnd,
                         'from':monthStart,
                         'page_size':1
                     }
            
            userRec = send_REST_request('recording', data=userID, param = apiParam, rType = "get")       
            
            try:
                if userRec['total_records'] > 0:
                    return userRec["total_records"]
            except:
                return 0
            
        except Exception as e:
            logging ('Error in Request for Recording data {}: {}'.format(response, e))
            break
    return 0               
            
def modify_user_license_scim2(userID,userName, userCurrLicense, userType="Basic"):
    # userInactiveDB = [[userID,userLoginMonths, userFirstName, userLastName, License],...]
    global chkRec
     
    if userCurrLicense.lower() != userType.lower():
        userURL = f'{API_SCIM2_USER}/{userID}'
        #https://api.zoom.us/scim2/Users/{userId}
        userSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
        data =\
             {
                 "schemas":userSchema,
                 "userType":userType
             }                     
        try:      
            logging(f"{userName} has {recordings} cloud recordings.")
        except Exception as e:
            PrintException(e)
        
        send_REST_request('scim2', data=userID, param = "", rType = "put")

def modify_user_scim2(userType, scim2data):
    ## @To Do
    userName = scim2data['displayName']
    userID = scim2data['id']
    userURL = f'{API_SCIM2_USER}/{userID}'

    
    if userType.lower() == 'basic':
        userType = "Basic"
        #https://api.zoom.us/scim2/Users/{userId}
        data =\
             {
                 "schemas":scim2data["schemas"],
                 "userType":userType
             }                     
    send_REST_request('scim2', data=userID, param = "", rType = "put", note = f'Set {userName} to {userType}')
    
def delete_users_list(userID, userDesc):
    api = f"v2/users/{userID}"
    api = f"{api}?action=delete"
    
    send_REST_request(api, data="", param = "", rType = "delete", note = f'{userDesc}')
    
    
    
        
def get_user_scim2_data(userID):
    logging(f'Checking SCIM2 Data for {userID}')
    urn = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
    
    try:
        scim2_data = send_REST_request('scim2', data=userID, param = "", rType = "get")
        print(f'SCIM2 Response: {scim2_data}')
    except Exception as e:
        print(f'SCIM2 Exception:{e}')
        
    
    return scim2_data

def get_plan_data(token,accountID):    
    # https://api.zoom.us/v2/accounts/{accountId}/plans/usage
    pass

    userRec = {}
    print('Validating recordings for: {}'.format(userID))
    
    

    #Check 6 months of recordings
    current = datetime.datetime.now()
    prev_month_lastday =  datetime.datetime.now()

    for i in range (0,6,1):
        _first_day = prev_month_lastday.replace(day=1)
        if i>0:
            prev_month_lastday = _first_day - datetime.timedelta(days=1)
    
        lastDate = prev_month_lastday.replace(day=1)
    
        monthStart = prev_month_lastday.strftime("%Y-%m-01")
        lastDay = (lastDate + relativedelta(day=31)).day
        monthEnd = prev_month_lastday.strftime("%Y-%m-{}".format(lastDay))
        try:
            api = 'https://api.zoom.us/v2/users/{}/recordings'.format(userID)
            api = '{}?to={}&from={}&page_size=1'.format(api,monthEnd,monthStart)
            
            
            response = requests.get(url=api, headers=authHeader)        
            
            print("{}\n{}".format(api,response.text))
            if response.status_code == 200:
                try:
                    userRec = response.json()
                    if userRec['total_records'] > 0:
                        return userRec["total_records"]
                except Exception as e:
                    logging("Error in recording check {}: {}".format(userRec,e))
        except Exception as e:
            logging ('Error in Request for Recording data {}: {}'.format(response, e))   
    return 0


def create_user():
    '''

    '''
    newUser = {\
      "action": "ssoCreate",
      "user_info": {
        "email": userEmailAddr.get(),
        "type": 1,
        "first_name": "",
        "last_name": ""
      }
    }
    
    
    


def proc_user_settings(data, group, email):
    tally = {}
    csvRow = {\
        "Email": email,
        "Group": group,
        "Category":"",
        "Setting":"",
        "Value":""
        }
    
    
    if data != {}:
        try:
            for category in data:
                try:
                    for setting in data[category]:
                        try:
                            value = data[category][setting]
                            if value is list:
                                for item in value:
                                    value = f"{value}, {item}"
                                                            
                            csvRow = {\
                                "Email": email,
                                "Group": group,
                                "Category":category,
                                "Setting":setting,
                                "Value":value
                                }
                             
                        except Exception as e:
                            PrintException(e)
                except:
                    PrintException(e)
        except:
            PrintException(e)

    return csvRow



def openAPIList():
    data = {}
    datafile = {}
    
    try:
        with open(API_FILE, 'r') as JSONFile:
            datafile = JSONFile.read()
            logging(f"Opening JSON API List file: {API_FILE}")
        
        data = json.loads(datafile)
       #.decode("utf-8","ignore")  
    except DecodeError:
        pass

    return data

    
def get_acct_roles():
    global roles
    data = send_REST_request('roles', data = '', rType = "get")
    roles = {}
    
    try:
        for item in data['roles']:
            try:
                roles.update({item['name']:item['id']})
            except Exception as e:
                PrintException(e)
                
            logging(f'{item["name"]} role has {item["total_members"]} members')
            logging(f'{item["description"]}')
        listUserRolesAddAll(roles)
    except Exception as e:
        PrintException(e,'Could not retrieve role data')
    
    
    
def get_users_settings():
    global progress_var
    global userDB
    global cancelAction

    listboxTop()
    cancelActions(False)
    fileName = "User Setting Tracking.csv"

    startingUser = etxtProcEmail.get()
    if startingUser != '':
        flagFindUser = 1
        logging(f'Searching for user index {startingUser} to start processing users')
    else:
        flagFindUser = 0
        
    try:
        count = 0
        with open(fileName, 'w', newline='') as csvFile:
            writer = csv.DictWriter(csvFile, fieldnames = ["Email","Group", "Category", "Setting","Value"])
            writer.writeheader()
            
            for user in userDB:
                if cancelAction is True:
                    cancelAction = False
                    break
                
                count += 1
                bar = int((userDB.index(user)/len(userDB))*100) 
                progress_var.set(bar)
                #root.update_idletasks()
                
                userID = user[2]
                email = user[1]
                group = user[7]
                if flagFindUser == 1 and email == startingUser:
                    flagFindUser = 0
                
                if flagFindUser == 0:
                    logging(f'{count} Retrieving {group}, {email} settings')
                    userSettings = get_user_settings(userID, type = 3, count=count)
                    #csvRow = proc_user_settings(userSettings, group, email)
                    tally = {}
                    csvRow = {\
                        "Email": email,
                        "Group": group,
                        "Category":"",
                        "Setting":"",
                        "Value":""
                        }
                    
                    if userSettings != {}:
                        try:
                            for category in userSettings:
                                try:
                                    for setting in userSettings[category]:
                                        try:
                                            value = userSettings[category][setting]
                                            if value is list:
                                                for item in value:
                                                    value = f"{value}, {item}"
                                                                            
                                            csvRow = {\
                                                "Email": email,
                                                "Group": group,
                                                "Category":category,
                                                "Setting":setting,
                                                "Value":value
                                                }
                                            writer.writerow(csvRow)
                                        except Exception as e:
                                            PrintException(e)
                                except Exception as e:
                                    PrintException(e)
                        except Exception as e:
                            PrintException(e)         
    except Exception as e:
        logging (f'Error with creating file: {e}')
    
    cancelActions('reset')

def save_acct_settings(settingsDB, lockSetting):
    
    try:
        today = datetime.datetime.now()
        fileName = f"{SETTINGS_FILE}-{datetime.datetime.strftime(today, dateStr['file'])}.csv"
        with open(fileName, 'w', newline='') as csvFile:
            writer = csv.DictWriter(csvFile, fieldnames = ["Group", "Category", "Setting","Value", "Locked"])
            writer.writeheader()                
        
            for group in settingsDB:
                groupSettings = settingsDB[group]
    
                tally = {}
                csvRow = {\
                    "Group": group,
                    "Category":"",
                    "Setting":"",
                    "Value":"",
                    "Locked":""
                }
                
                if groupSettings != {}:
                    try:
                        for category in groupSettings:
                            try:
                                for setting in groupSettings[category]:
                                    try:
                                        value = groupSettings[category][setting]
                                        if value is list:
                                            for item in value:
                                                value = f"{value}, {item}"
                                                                        
                                        csvRow = {\
                                            "Group": group,
                                            "Category":category,
                                            "Setting":setting,
                                            "Value":value,
                                            "Locked":""
                                            }
                                        
                                        try:
                                            csvRow.update({"Locked":lockSetting[category][setting]})    
                                        except:
                                            pass
                                        
                                        writer.writerow(csvRow)
                                    except Exception as e:
                                        PrintException(e)
                            except Exception as e:
                                PrintException(e)
                    except Exception as e:
                        PrintException(e)             
    except Exception as e:
        logging (f'Error with creating file: {e}')    
    
def get_groups_settings(groupData):
    global cancelAction
    global groupDB
    
    listboxTop()
    cancelActions(False)
    groupDB = {}      
    count = 0
    
    logging(f'{count} Retrieving Account settings')
    groupDB['AcctSetting'] = get_acct_settings()
    lockSettings = get_lock_settings()    
        
    for groupID in groupData:
        if cancelAction is True:
            cancelAction = False
            break
        
        count += 1
        group = groupData[groupID]
        logging(f'{count} Retrieving {group} settings')
        groupSettings = get_group_settings(groupID, count)
        try:
            groupDB[group] = groupSettings
        except Exception as e:
            PrintException(e)
        
    save_acct_settings(groupDB, lockSettings)   


def get_group_settings(groupID, count = 0):   
    groupSettings = None
    
    try:
        
        timeStart = time.time()
        groupSettings = send_REST_request('groupSettings', data = groupID, rType = "get")
        groupSettings2 = send_REST_request('groupSettings', data = groupID, param = {"option":"meeting_authentication"}, rType = "get")
        groupSettings3 = send_REST_request('groupSettings', data = groupID, param = {"option":"recording_authentication"}, rType = "get")
        groupSettings['auth'] = {}
        groupSettings['auth'].update(groupSettings2)
        groupSettings['rec_auth'] = {}
        groupSettings['rec_auth'].update(groupSettings3)
        timeEnd = time.time()            
        timeTotal = timeEnd - timeStart
        
    except Exception as e:
        PrintException(e)
    
    return groupSettings

def get_lock_settings():
    try:
        acctID = acct_id()
        timeStart = time.time()
        acctSettings = send_REST_request('lockSettings', data = acctID, rType = "get")  
        timeEnd = time.time()            
        timeTotal = timeEnd - timeStart
         
    except Exception as e:
        PrintException(e)
       
    return acctSettings

def acct_id():
    try:
        acctId = eAcctID.get()
        
        if acctId == "":
            raise KeyError
    except Exception as e:
        acctId = "me"
    
    logging(f"Using AccountID: {acctId}")
    return acctId
    
def get_acct_settings():
    acctSettings = {}
    
    try:
        acctID = acct_id()
        timeStart = time.time()
        acctSettings = send_REST_request('acctSettings', data = acctID, rType = "get")
        acctSettings2 = send_REST_request('acctSettings', data = acctID, param = {"option":"meeting_authentication"}, rType = "get")
        acctSettings3 = send_REST_request('acctSettings', data = acctID, param = {"option":"recording_authentication"}, rType = "get")
        acctSettings4 = send_REST_request('acctSettings', data = acctID, param = {"option":"security"}, rType = "get")
        acctSettings['auth'] = {}
        acctSettings['auth'].update(acctSettings2)
        acctSettings['rec_auth'] = {}
        acctSettings['rec_auth'].update(acctSettings3)
        acctSettings['securityAcct'] = {}
        acctSettings['securityAcct'].update(acctSettings4)        
        timeEnd = time.time()            
        timeTotal = timeEnd - timeStart
         
    except Exception as e:
        PrintException(e)
       
    return acctSettings



def get_user_settings(userId, type = 2, count = 0):   
    userSettings = None
    
    try:
        
        timeStart = time.time()
        if type >= 0:
            userSettings = send_REST_request('settings', data = userId, rType = "get")
            
        if type >= 1 and userSettings is not None:
            userSettings2 = send_REST_request('settings', data = userId, param = {"option":"meeting_authentication"}, rType = "get")
            try:
                userSettings['auth'] = {}
                userSettings['auth'].update(userSettings2)
            except Exception as e:
                PrintException(e)
        if type >= 2 and userSettings is not None:
            userSettings3 = send_REST_request('settings', data = userId, param = {"option":"recording_authentication"}, rType = "get")   
            try:
                userSettings['rec_auth'] = {}
                userSettings['rec_auth'].update(userSettings3)
            except Exception as e:
                PrintException(e)
        
        timeEnd = time.time()            
        timeTotal = timeEnd - timeStart
        btnSettingsText.set(f"Backup User Settings {timeTotal:.2f}s per user/{((timeTotal*(len(userDB)-count))/60):.3f}mins")
        root.update()
    except Exception as e:
        PrintException(e, "Error in user settings retrieval")
    
    
    print (f"####User Settings####\n{userSettings}")
    return userSettings

def populateCustomAttributes():
    """Retrieves a single users data to see what custom attributes are applied to the Zoom account
       and updates the tkinter combobox with the values.
       
    Args:  None
           
    Returns:  List of the custom attribute names
    """
    global customAttribList
    global customAttrib
    global emenuAttrib
    
    userInfo = list_user_data()
    customAttribList.clear()
    
    try:
        for user in userInfo['users']:
            for attrib in user['custom_attributes']:
                value = f"{attrib['name']}, {attrib['key']}"
                customAttribList.append(value)     
        
        logging(f"Custom Attributes Found: {customAttribList}")        
        customAttrib.set(customAttribList[0])
        emenuAttrib['values'] = customAttribList
        root.update()
    
        return customAttribList
    except Exception as e:
        logging(f"Error pulling custom attributes: {e}")
        return ""
    
def list_user_data(records = 1, pageNumber = 0):
    """Retrieve page of user records (list users zoom api command)
       
    Args:  records (integer), number of records per page, max 300
           pageNumber (integer), page number of recordset to retrieve (may change to nextpagetoken in future)
           
    Returns:  Dictionary of the page of user data
    """
    
    pageData = None
    
    JSONData = {
        'status': "",
        'page_size': records,
        'role_id': "",
        'include_fields': "custom_attributes",
        'page_number': str(pageNumber)
        }           

    try:
        pageData = send_REST_request('users', param = JSONData, rType = "get")
    except Exception as e:
        pageData = None
        print('Exception:{}'.format(e))       
    
    return pageData
    
def get_user_data(userId):

    user_data = None
    try:         
        user_data = send_REST_request('user', data = userId, rType = "get")

        #user_data = requests.get(url=url, headers=authHeader).json()
        #userInactive = [userID,userLoginMonths, userFirstName, userLastName]
        
    except Exception as e:
        logging('User Data pull error: {}'.format(e))
        
    
    return user_data    
 
    
def get_users_data(groupsDict):
    global progress_var
    global progress
    global root
    global userDB
    global userRawDB
    global userInactiveDB
    global cancelAction
    global dateInactiveThreshold
    # get total page count, convert to integer, increment by 1
    total_pages = None
    record_count = 0
    userLoginMonths = 0
    pageCount = 0
    page_data = None
    data = None
    print ('Groups:  {}'.format(groupsDict))
       

    page_data = list_user_data(records = 1, pageNumber = 0)
    
    if page_data != None:
        try:
            pageSize = 300
            total_pages = int(page_data['page_count']) + 1
            #pageNumber = str(int(page_data['page_number']) + 1)
            recordsTotal = int(page_data['total_records']) + 1
            pageCount = int(recordsTotal / pageSize) + 1
        except Exception as e:
            print(f'{page_data}\nError: {e}')
            #logging(page_data['message'])
            total_pages = 0
            pageCount = 0
            recordsTotal = 0
            
        logging('Retrieving {} user records'.format(recordsTotal))
        logging('Pages of data: {}'.format(pageCount))
        actionBtnsState('enabled')
        # results will be appended to this list
        all_entries = []
        # loop through all pages and return user data
        runAvg = 0
        flagUserCount = 0
        cntTime = 0
        startTime = [0,0,0,0,0,0,0,0,0,0]
        endTime = [0,0,0,0,0,0,0,0,0,0]
        user_ids = []
        licenseCnt = {'total':{'Basic':0,'Licensed':0,'On-Prem':0,'None':0},'flagged':{'Basic':0,'Licensed':0,'On-Prem':0,'None':0}}
        todaysDate = datetime.datetime.now(pytz.timezone(localTimeZone))
        cancelActions(False)
        try:
            with open(USER_DB_FILE, 'w', newline='') as csvfile:
                fieldnames = ['flag','user_id','email','first_name', 'last_name','last_login','months_since','app_ver','group','license']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                                    
                for page in range(0, int(pageCount)):
                    
                    if cancelAction is True:
                        cancelAction = False
                        break
                    
                    
                    flagUser = ['None','None']
                    startTime[cntTime] = time.time()
                    
                    #logging("Pulling: {}".format(JSONData))
                    
                    user_data = list_user_data(pageSize, page)
                        
                    
                    try:
                        for user in user_data['users']:
                            record_count += 1
                            progress_var.set(int((record_count/recordsTotal)*100))
                            root.update()
                            
                            try:
                                userEmail = user['email']
                                
                                
                                for record in user:
                                    if userEmail not in userRawDB:
                                        userRawDB[userEmail] = {record:user[record]}
                                    else:
                                        userRawDB[userEmail].update({record:user[record]})
                                
                            
                            except:
                                userEmail = None
                            
                            
                            
                            try:
                                userID = user['id']
                            except Exception as e:
                                userID = None
                            try:    
                                userFirstName = user['first_name']
                            except:
                                userFirstName = None
                            
                            try:
                                userLastName = user['last_name']
                            except:
                                userLastName = None
                                
                            try:
                                userLastLogin = user['last_login_time']
                            except:
                                #No valid Login, so creation date should be used.
                                try:
                                    userLastLogin = user['created_at']
                                except:
                                    userLastLogin = '2015-01-01T00:00:00Z'
                                
                            try:
                                try:
                                    userLastLogin = timeLocal(userLastLogin,"object")
                                    #dateInactiveThreshold =  timeLocal(dateInactiveThreshold,"object")
                                except Exception as e:
                                    logging(f'Error TZ: {e}')
                                    PrintException(e)
                                #UTCdate = datetime.datetime.strptime(userLastLogin,'%Y-%m-%dT%H:%M:%SZ')
                                #loginDate =  UTCdate.date()
                                # Debugging TZ
                                #logging(f"##Inactivity Check {userEmail}:  {userLastLogin}, ({type(userLastLogin)}) & Inactivity Date:  {dateInactiveThreshold} ({type(userLastLogin)})")
                                #try:
                                #    elapsedDays = (userLastLogin - dateInactiveThreshold).days
                                #    print(f"Days since last online:  {elapsedDays}")
                                #except Exception as e:
                                #    print(f'Threshold calc Error {e}')
                                #    PrintException(e)
                                
                                delta = None
                                if dateInactiveThreshold is not None:
                                    try:
                                        
                                        delta =  (dateInactiveThreshold - userLastLogin).days
                                        
                                        # Debugging Date
                                        #logging("Delta date: {}".format(delta))
                                    except Exception as e:
                                        PrintException(e)
                                        print('Date Error: {}'.format(e))
                                        
                                        
                                    
                                elapsedTime = relativedelta(todaysDate,userLastLogin)
                                
                                userLoginYears = elapsedTime.years 
                                userLoginMonths = (elapsedTime.years * 12) + elapsedTime.months
                                
                            except Exception as e:
                                print ("Error in date-time conversion: {}".format(e))
                            
                            try:
                                if dateInactiveThreshold is not None:
                                    if delta >= 0:
                                        try:
                                            flagUser = ['Inactive','Login']
                                        except Exception as e:
                                            logging("Error in flagging: {}".format(e))
                                        
                                        if logConfig['inactive'].get() == 1:
                                            logging("{} has been inactive for {} months".format(userEmail, userLoginMonths))
                                    else:
                                        try:
                                            flagUser = ['Active','Login']     
                                        except Exception as e:
                                            logging("Error in flagging: {}".format(e))
                            except Exception as e:
                                print ('No Valid Last Login Data for {}: {}'.format(userEmail,e))
                                flagUser = ['No','Login']
                                userLastLogin = None
                                
                            try:
                                userPicURL = user['pic_url']
                            except:
                                userPicURL = ''
                                
                            try:                
                                userLastClientVer = user['last_client_version']
                                
                            except:
                                userLastClientVer = 'No Version Data'
                            
                            try:                
                                userLicense = user['type']
                                if userLicense == 1:
                                    userLicense = 'Basic'
                                elif userLicense == 2:
                                    userLicense = 'Licensed'
                                elif userLicense == 3:
                                    userLicense = 'On-Prem'
                                else:
                                    userLicense = f'Undefined: {user["type"]}'
                                
                                try:
                                    if userLicense in licenseCnt['total']:
                                        licenseCnt['total'][userLicense] += 1
                                    else:
                                        licenseCnt['total'][userLicense] = 1
                                except Exception as e:
                                    print (f"Error in license counting: {e}")
                                    
                            except:
                                userLicense = 'None'    
                            
                            try:
                                groupCnt = 0
                                groupName = ''
                                groupNames = ''
                                groupList = []
                                for group in user['group_ids']:
                                    groupCnt += 1
                                   
                                    try:
                                        if group in groupsDict:
                                            groupName = groupsDict[group]
                                        else:
                                            groupName = 'No Group'
                                            flagUser = ['No','GroupID']
                                        groupList.append(groupName)
                                    except Exception as e:
                                        print('**Group Error: {}'.format(e))
                                        
                                    #print ('Found GroupID:{}'.format(groupName))    
                                    
                                    # User can be in multiple groups, so it shows number
                                    # of group memberships and group names
                                    groupNames = '{} {}'.format(groupNames,groupName)
                                    userGroup = '{}: {}'.format(groupCnt,groupNames)
                                    
                            except Exception as e:
                                print ('Invalid user group data for: {}, {}'.format(userEmail,e))
                                print("{}".format(user_data))
                                flagUser = ['No','Group']
                                userGroup = 'No Group'    
                            
                            try:
                                if userLoginMonths >= maxMonths:
                                    userInactive = [userID,userLoginMonths, userFirstName, userLastName, userLicense, userEmail]
                                    userInactiveDB.append(userInactive)
                            except Exception as e:
                                logging ("Error with inactive user check process: {}".format(e))
                                    
                                    
                            if flagUser[0] == 'No' or flagUser[0] == 'Inactive':
                                
                                if (logConfig['inactive'].get() == 1 and flagUser[0] == 'Inactive') or\
                                   (logConfig['noGroup'].get() == 1 and flagUser[0] == 'No'):
                                    logging("{} {}:#{}, {}".format(flagUser[0],flagUser[1],record_count,userEmail))
                                
                                
                                
                                flagUserCount += 1
                                try:
                                    licenseCnt['flagged'][userLicense] += 1
                                except:
                                    licenseCnt['flagged'][userLicense] = 1
                            userCSVData = {
                                    'flag': flagUser[0],
                                    'user_id':userID,
                                    'email': userEmail,
                                    'first_name':userFirstName,
                                    'last_name':userLastName,
                                    'last_login':userLastLogin,
                                    'months_since':userLoginMonths,
                                    'app_ver':userLastClientVer,
                                    'group':userGroup,
                                    'license':userLicense
                                }
                            
                            
                            writer.writerow(userCSVData)
                            #print ('Last Recorded Zoom version for {}: {}'.format(userEmail,userLastClientVer))
                            flagUser = ['None','None']
                        
                                # userDeleteList.append(userInactive)
                                #
                                
                            try:
                                user_ids = [
                                    flagUser[0],
                                    userEmail,
                                    userID,
                                    userFirstName,
                                    userLastName,
                                    userLastLogin,
                                    userLastClientVer,
                                    userGroup,
                                    userLicense,
                                    userLoginMonths,
                                    userPicURL,
                                    groupList
                                ]
                                userDB.append(user_ids)
                                actionBtnsState('enabled')
                            except:
                                user_ids = []
                            
                    except:
                        pass
                        
                    all_entries.extend(user_ids)
                    data = all_entries
                    page += 1
                    endTime[cntTime] = time.time()
                    cntTime += 1
                    if cntTime == 10:
                        timeDiffSum = 0
                        cntTime = 0
                        for idx in range (0, 10):
                            timeDiffSum += (endTime[idx]-startTime[idx])
                        timeAvg =  timeDiffSum / 11
                        runAvg = timeAvg * (total_pages - page)        
                    if runAvg == 0:
                        runAvg = (endTime[0]-startTime[0]) * (total_pages - page)        
                    
                    progress.step(int((page/total_pages)*100))
                    root.update()
                    #root.update_idletasks()
                    
                    #print("Time Remaining: {:.2f}s, {}/{} : {}".format(runAvg,page,total_pages,user_ids))
                # print the contents using zip format.

                
                
                
                for userLicense in licenseCnt['total']:
                    logging(f'Total {userLicense} Users Counted: {licenseCnt["total"][userLicense]}')
                
                logging('Total Flagged Users: {}'.format(flagUserCount))
                
                logging('User Data Pulled:  {}'.format(len(userDB)))
                logging('Users Inactive: {}'.format(len(userInactiveDB)))
                 
                 
                 
                #writeRawUserData(userRawDB) 
                menuUserEmailValuesAddAll(userRawDB)
                
        except Exception as e:
            msg =  f'File Write Error, please close file it may be open in Excel:  {e}'
            PrintException(e,msg)
            data = None
    
    
    cancelActions('reset')
    return data

def get_subaccount_data():
    try:
        subAccount = \
            send_REST_request(\
                apiType ='subaccount',
                rType = "get",
            )        
    except Exception as e:
        log("Error getting sub account data: {}".format(e))
        subAccount = None
    
    try:
        seats = 0
        for data in subAccount['accounts']:
            if 'seats' in data:
                seats += data['seats']
    except:
        seats = 0
        
    
    return (subAccount,seats)


def displayAccountInfo():
    (cloudUsage,cloudStorage) = getAccountInfo(desc = "Retrieving Account Status...")
    statusLicense.set(cloudUsage)
    statusCloud.set(cloudStorage)
    populateCustomAttributes()
    logging("...Finished retrieving account status, data shown in status bar below")

def getAccountInfo(desc):
    planInfo = \
        send_REST_request(\
            apiType ='plan',
            data = acct_id(),
            rType = "get",
            note=desc,
        )
    
    #(subAccount, seats) = get_subaccount_data()
    
    

    
    try:
        planLicenses = planInfo["plan_base"]["hosts"]
        planUsers = planInfo["plan_base"]["usage"]
        remainingNow = planLicenses - planUsers
        remainingPct = round(((remainingNow / planLicenses) * 100),2)
        
        licenseInfo =  f"Licenses: {remainingPct}% ({remainingNow:,}/{planLicenses:,})"
        cloudStorage = planInfo["plan_recording"]["free_storage"]
        cloudUsage = planInfo["plan_recording"]["free_storage_usage"]
        
        try:
            cloudExceed = f"(+{planInfo['plan_recording']['plan_storage_exceed']})"
        except:
            cloudExceed = ""
            
        cloudInfo = f"{cloudUsage}{cloudExceed}/{cloudStorage}"
    
        return (licenseInfo,cloudInfo)
    except Exception as e:
        print ("Exception in License info: {}".format(e))
        return (None,None)
    
    return ("No Cloud Data","No License Data")
    
def total_licenses():

    try:
        logging('Retrieved Data:')
        for each_row in zip(*([i] + (j) for i, j in licenseCnt['total'].items())): 
            logging(*each_row, " ")
        logging ('Remaining Licences: {}'.format(TOTAL_LICENSES - licenseCnt['total']['Licensed']))             
        
        logging('Flagged Licenses:')
        for each_row in zip(*([i] + (j) for i, j in licenseCnt['flagged'].items())): 
            logging(*each_row, " ")                                    
    except Exception as e:
        logging("Error in generating table of Licenses:{}".format(e))

def Relicense_Inactive():
    #userInactive = [userID,userLoginMonths, userFirstName, userLastName, userLicense,userEmail]
    global cancelAction
    counter = 0
    progress_var.set(0)
    usersCnt = len(userInactiveDB)
    userCounter = 0
    logging(f'Examining {usersCnt} users for modification')
    cancelActions(False)
    
    for userData in userInactiveDB:
        if cancelAction is True:
            cancelAction = False
            break
        
        #userID = userData[0]
        userEmail = userData[5]
        userLicense = userData[4]
        #logging(f'{counter} Examining: {userEmail}, {userLicense} License')
        userCounter += start_modify_user(userEmail)
        #modify_user_license(userID,userName, userLicense)
        counter += 1
        progress_var.set(int((counter/usersCnt)*100))
    logging (f'{userCounter} users modified.')

    cancelActions('reset')

            
def onListSelect(event):
    global eDomain
    global userEmailAddr
    # Note here that Tkinter passes an event object to onselect()
    objWidget = event.widget
    try:
        idx = int(objWidget.curselection()[0])
    except:
        idx = 0
    value = objWidget.get(idx)
    print('You selected item {}: {}, checking for domain: {}'.format(idx, value, eDomain.get()))
    
    if logConfig['clipboard'].get() == 1:
        root.clipboard_clear()
        selected = listbox.get(ANCHOR)
        root.clipboard_append(selected)
        
    data = value.split()
    try:
        domain = eDomain.get()
    except:
        domain = ''
        
    for item in data:
        if f'@{domain}' in item:
            if domain != '':
                head, sep, tail = item.partition(domain)
                item = f'{head}{sep}'
            
            userEmailAddr.set(item)
            break

def menuAPICommand(eventObject):
    #logging('Triggered API Command')
    command = emenuAPICmd.get()
    

    etxtAPI.delete(0, END)
    etxtAPI.insert(0, command)
    emenuAPICmd.configure(width=20)

def menuUserEmailValuesAddAll(data):
    global userEmailAddr
    global eComboUserEmail
    
    
    logging('Updating User email drop down list...')
    userEmailList.clear()
    try:
        for userEmail in data:
            userEmailList.append(userEmail)
    
        eComboUserEmail['values'] = userEmailList
        
        if len(userEmailList) > 0:
            userEmailAddr.set(userEmailList[-1])       
    except Exception as e:
        PrintException(e, 'Error updating user Email list')
        
    logging(f'....Finished updating user email drop down list with {len(userEmailList)} entries')
        

    
def menuUserEmailValuesAdd(email):
    userEmailList.append(email)
    eComboUserEmail['values'] = userEmailList
    userEmailAddr.set(userEmailList[-1])
    
def menuUserEmailValuesInit():
    userEmailList.clear()
    ###@@TODO - user
    for email in userRawDB[category]:
        userEmailList.append(cmd)
        
    eComboUserEmail['values'] = userEmailList
    userEmailAddr.set(userEmailList[0])
    
def menuAPICmdValues(category):
    global apiCommandList
    global emenuAPICmd
    global apiCommand
    
    apiCommandList.clear()
    
    try:
        for cmd in apiDict[category]:
            apiCommandList.append(cmd)
            
        emenuAPICmd['values'] = apiCommandList
        apiCommand.set(apiCommandList[0])
        emenuAPICmd.configure(width=20)
    except Exception as e:
        PrintException(e)
    
def menuAPICategory(eventObject):
    global apiCommandList
    #logging('Triggered API Category')
    root.update()
    category = emenuAPICat.get()
    
    menuAPICmdValues(category)
    
    etxtAPI.delete(0, END)
    etxtAPI.insert(0, apiCommandList[0])
    emenuAPICmd.configure(width=20)
    
    root.update()



def listUserRolesAddAll(data):
    global userRoleList
    global comboUserRoles
    
    logging('Updating User roles drop down list...')
    userRoleList.clear()
    try:
        for userRole in data:
            userRoleList.append(userRole)
    
        comboUserRoles['values'] = userRoleList
        
        if len(userRoleList) > 0:
            userRoleValue.set(userRoleList[-1])       
    except Exception as e:
        PrintException(e, 'Error updating user role list')
        
    logging('....Finished updating user role drop down list')
        


def testdata():
    #Used to validate if recordings is returning appropriate data
    userID = ""
    get_user_scim2_data(userID)
    rec = check_user_recording_count(userID)
    input("Press Enter to continue...")
    print ("Cloud Recording Count Test: {}".format(rec))
    
def getOpsLog():
    listboxTop()
    
    userDailyOpLog(
        userEmailAddr.get(),
        eTxtUserLogStart.get(),
        eTxtUserLogEnd.get()
    )
    
def getSigningLog():
    listboxTop()
    userDailySignInLog(
        userEmailAddr.get(),
        eTxtUserLogStart.get(),
        eTxtUserLogEnd.get()
    )
def userDailyOpLog(userEmail, dateStart = None, dateEnd = None, nextPage = None):
    pageCounter = 1
    today = datetime.datetime.now()
    todayStr = f'{datetime.datetime.strftime(today, dateStr["calendar"])}'
    
    params = {\
        'to':dateEnd,
        'from':dateStart,
        'page_size':300,
        'next_page_token':nextPage
        }
    
    logging(f'Checking Daily Operation log for: {userEmail}')
    try:
        opsLogs = send_REST_request('logs', param=params, rType = "get", note = "")
            
        for userLog in opsLogs["operation_logs"]:
            for item in userLog:
                if userEmail in userLog[item]:
                    for item in userLog:
                        text = item.replace("_", " ")
                        if text == 'time':
                            userLog[item] = timeLocal(userLog[item], "string")
                        logging(f"{text}: {userLog[item]}")
    except Exception as e:
        PrintException(e)
        
    try:
        if opsLogs['next_page_token']:
            logging('Checking next page of operation activity logs...')
            pageCounter += 1
            userDailySignInLog(userEmail, dateStart, dateEnd, nextPage = opsLogs['next_page_token'])
    except Exception as e:
        PrintException(e)
    
    if pageCounter > 0:
        pageCounter = 0
        logging(f'Done checking Operations log for: {userEmail}')        
        
    
def userDailySignInLog(userEmail, dateStart = None, dateEnd = None, nextPage = None):
    pageCounter = 1
    today = datetime.datetime.now()
    todayStr = f'{datetime.datetime.strftime(today, dateStr["calendar"])}'
    
    params = {\
        'to':dateEnd,
        'from':dateStart,
        'page_size':300,
        'next_page_token':nextPage
        }
    logging(f'Checking Daily Sign In/Out log for: {userEmail}')
    try:
        signinLogs = send_REST_request('signin', param=params, rType = "get", note = "")

        if "activity_logs" in signinLogs:        
            for userLog in signinLogs["activity_logs"]:
                for item in userLog:
                    if userEmail in userLog[item]:
                        for item in userLog:
                            text = item.replace("_", " ")
                            if text == 'time':
                                userLog[item] = timeLocal(userLog[item], "string")
                            logging(f"{text}: {userLog[item]}")
    
            try:
                if signinLogs['next_page_token']:
                    logging('Checking next page of sign in/out activity logs...')
                    pageCounter += 1
                    userDailySignInLog(userEmail, dateStart, dateEnd, nextPage = signinLogs['next_page_token'])
            except Exception as e:
                PrintException(e)
    except Exception as e:
        PrintException(e)

    
    if pageCounter > 0:
        pageCounter = 0
        logging(f'Done checking Daily SignIn/Out log for: {userEmail}')
        

def resizeFuncAPICat(): 
    maxWidth = 2
    
    for var in apiCategoryList:
        if len(var) > maxWidth:
            maxWidth = len(var) + 2
            
    emenuAPICat.configure(width=maxWidth)
    
def resizeFuncAPICmd():
    maxWidth = 2
    print (f'{apiCommandList}')
    for var in apiCommandList:
        if len(var) > maxWidth:
            maxWidth = len(var) + 2
    
    print (f'Resized width:{maxWidth}')
    emenuAPICmd.configure(width=maxWidth)
    root.update()

def destroy_all_subwindows():
    for widget in root.winfo_children():
        if isinstance(widget, Toplevel):
            logConfig['open'] = False
            widget.destroy()
            
def clearLog():
    logging(f'Clearing Log...')
    listbox.delete(0,END)    


def retrieveZoomUsers():
    global listbox
    global userDB
    global cancelAction
    global groupFilterList
    global menuUserGroups
    global menuUserGroupItems
    
    #Time the completion of the function
    startTime = time.time()
    
    #Reset the cancelActions button
    cancelActions(False)
    
    #Clear zoom user list dictionary
    userDB.clear()
    
    #Set log scrollbox to top (latest log item)
    listboxTop()
    #listbox.delete(0,END)
    
    zoom_token_auth()
    #get basic account info
    displayAccountInfo()
    
    #get account group information
    groupsData = get_group_data()
    menuUserGroups, menuUserGroupItems = groupMenuInit(txtUserFrame, groupsData, menuUserGroups)
    if menuUserGroupItems:
        menuUserGroups.grid()
    
    groupFilterList = []
    ## Update ComboBox
    groupFilterList.clear()
    groupFilterList = ['All Users','No Group']
    for group in groupsData:
        groupFilterList.append(groupsData[group])
        
    emenuGroupFilter['values'] = groupFilterList
    
    get_groups_settings(groupsData)
    
    
    #Retrieve all zoom user data
    data = get_users_data(groupsData)
    
    #Calculate overall time 
    endTime = time.time()
    timeTotal = endTime - startTime
    #btn.set(f"Retrieve all users: {((timeTotal*(len(userDB)))/60):.3f}mins")    
    
    cancelActions('reset')

def get_InactiveDate():
    global dateInactiveThreshold
    
    print('Retrieving inactivity date from form')
    try:
        if eDate.get() != '':
            try:
                inactiveDate = f'{eDate.get()}T00:00:00'
                dateInactiveThreshold = datetime.datetime.strptime(inactiveDate, dateStr['user'])
                dateInactiveThreshold = pytz.utc.localize(dateInactiveThreshold)
                #dateInactiveThreshold.replace(tzinfo=datetime.timezone.utc)
                print (f"Date Inactive Threshold:  {dateInactiveThreshold}")
            except Exception as e:
                print(f'##Error in Inactive Threshold: {e}')
                PrintException(e)
        else:
            dateInactiveThreshold = None
    except Exception as e:
        PrintException(e,"Invalid inactive date")
        dateCheck = "No Date"
        
        
def zoom_token_auth():
    global maxMonths
    global maxNum
    global dateInactiveThreshold
    
    try:
        maxMonths = int(eMonths.get())
    except:
        maxMonths = 10
    
    try:
        maxNum = int(eNumber.get())
    except:
        maxNum = 0
    
    get_InactiveDate()
        
def customAPI():
    """Executes custom API "send" button command and sends
       out the REST API command based on the data defined
       in the text fields of the custom API GUI frame
       
    Args:  None
    
    Returns:  None
    """        
    txtBody = etxtAPIBody.get()
    listboxTop()
    if txtBody == "":
        txtBody = None
    else:
        try:
            txtBody = json.loads(txtBody)
        except:
            txtBody = ""
    
    txtParam = etxtAPIParam.get()
    if txtParam == "":
        txtParam = None
    else:
        try:
            txtParam = json.loads(txtParam) 
        except:
            txtParam = None
    
    api =  f'{apiVer}{etxtAPI.get()}'
 
    response = \
        send_REST_request(\
            apiType = api,
            body= txtBody,
            param = txtParam,
            rType = RESTmethod.get(),
            note="Custom API Command Sent",
        )
    logging(f'Custom api Command: {api} {txtBody}')
    logging(f'Response:{response}')
    
def urlOpen(url):
    """Opens URL in new browser window
       
    Args:  url (str) - url to navigate to
    
    Returns:  None
    """
    try:
        webbrowser.open_new(url)
    except Exception as e:
        PrintException(e)
    
def cancelActions(state):
    """Executes cancel action by changing state of Cancel Action button
       and flagging the state of the cancel action that loops should
       be monitoring for as the break trigger
       
    Args:  None
    
    Returns:  None
    """      
    global cancelAction
    
    #if state == cancelAction:
    #    cancelAction = not cancelAction
    
    try:
        if state.lower() == 'reset':
            cancelAction = True
            btnCancel["state"] = "disabled"
    except:
        pass

    try:
        if state is True: 
            listboxTop()
            logging("Cancelling last request...")
            cancelAction = True
            btnCancel["state"] = "disabled"
        elif state is False:
            cancelAction = False
            btnCancel["state"] = "normal"
    except:
        pass

def posC(inc, val = None):
    """Increments or resets column position for Tkinter
       objects using grid settings
       
    Args:  inc (int) - value to increment columns by
           val (int) - value to reset base column position
    
    Returns:  rowPos (int) - new row position value
    """      
    global colPos
    
    if val is not None:
        colPos = val
    
    if inc == 0:
        colPos = 0
    colPos += inc
    return colPos
    
def pos(inc, val = None):
    """Increments or resets row position for Tkinter
       objects using grid settings
       
    Args:  inc (int) - value to increment rows by
           val (int) - value to reset base row position
    
    Returns:  rowPos (int) - new row position value
    """   
    global rowPos
    
    if val is not None:
        rowPos = val
    
    if inc == 0:
        rowPos = 0
    rowPos += inc
    return rowPos
def menuButtonFeedback(idx):
    global btnMenu
    
    #Mutually Exclusive button feedback
    for button in btnMenu:
        if btnMenu.index(button) is idx:
            button['bg']= colorScheme['1']
            button['fg']= colorScheme['3']
            button['activebackground'] = colorScheme['2']
            button['activeforeground'] = colorScheme['4']
            button['relief']='sunken'
        else:
            button['bg']= colorScheme['2']
            button['fg']= colorScheme['4']
            button['activebackground'] = colorScheme['1']
            button['activeforeground'] = colorScheme['3']
            button['relief']='flat'
    root.update()


def update_users_attrib():
    global cancelAction
    
    def updateAttributeNow(userId, email, name, key, value):
        if logConfig['test'].get() == 0:
            update_user_attrib(userId, name, key, value)
        else:
            logging(f"TESTING: {email}'s {name} is being updated to {value}.")   
    
    emailIdx = 1
    userIdIdx = 2
    email = ""
    userCount = 0
    value = etxtAttrib.get()
    key = emenuAttrib.get().split(', ')
    chkParam = [False, False, False, False, False]
    
    progress_var.set(0)
    
    logging(f"Updating custom attribute {key[0]} based on filters")
    cancelActions(False)
    
    for user in userDB:
        if cancelAction is True:
            cancelAction = False
            break
        
        userCount += 1
        email = user[emailIdx]
            
        userId = user[userIdIdx]
        (testing, chkParam) = filterUser(user)
         
        try:
            if True not in chkParam:
                # No checkboxes, and group matches, just update
                updateAttributeNow(userId, email, key[0], key[1], value)
            elif chkParam[3] is True:
                # If only No Deletes is enabled then just update
                chkParam[3] = False
                if True not in chkParam:
                    updateAttributeNow(userId, email, key[0], key[1], value)     
        except Exception as e:
            logging(f'Error Updating User: {e}')      
        
        progress_var.set(int((userCount/len(userDB))*100))
        root.update()
    
    logging(f"Finished updating {userCount} users....")
    
    
    

    

def update_user_attrib(userId, name, key, value):
    
    apiBody = {
        'custom_attributes':
            [{
                'name':name,
                'key':key,
                'value':value
            }]
    }
    
    send_REST_request('user', data=userId, body = apiBody, rType = "patch")  

    
def presetCommand(presetName, presetIdx, command):
    
    logging(f"Triggering {command} for {presetName}")
    presetData = presets[presetName]
    
    if command == "execute":
        for item in presetData:
            try:
                tempDebug = logConfig['debug'].get()
                logConfig['debug'].set(1)
                response = \
                    send_REST_request(\
                        apiType = item["url"],
                        body =  item.get('jsonBody', None),
                        param = item.get('jsonParam', None),
                        rType = item.get('method', None),
                        note= f"Custom API preset step for {presetName}",
                    )
                
                logConfig['debug'].set(tempDebug)
                
            except Exception as e:
                logging(f"Error: {e}")
                response = None            
                #"index":len(presets[txtName]) + 1,
                #"method":RESTmethod.get(),
                #"url":url,
                #"parameters":jsonParam,
                #"body":jsonBody,
                #"ids":txtIDs,
                #"chain":{},
                #"delay":0,
                #"response":{}
       
    

def buildPresetButton(presetName, menu_origin, origin, JSONtxt = ""):
    global btnMenu
    global frameSubMenuCtnrl
    global frameControls
    global menuButtonList
    global btnPresetActions
    
        
    if presetName not in menuButtonList and presetName != "":
        menuButtonList.append(presetName)
        
        #any appending to lists must match same index value as idx
        idx = menuButtonList.index(presetName)
        btn = stdButtonMenuStyle(\
            menu_origin,
            text=f'*{presetName}',
            command = lambda idx_d = idx:  menuButtons(idx_d, presetName)
        )
    
        btn.grid()
    
        btnMenu.append(btn)
    else:
        idx = menuButtonList.index(presetName)
        
        
    logging(f'{menuButtonList}\n{len(frameSubMenuCntrl)}/{len(frameControls)}, Preset Button Index {idx}')
    
    #1. Create Submenu section (Actions Menu) frame
    frameSubMenuCntrl.append(stdFrameSubMenuStyle(origin))
    frameSubMenuCntrl[idx].propagate(0) 
    frameSubMenuCntrl[idx].grid_remove()

    #2. Create Controls section frame
    frameControls.append(stdFrameControlStyle(origin))
    frameControls[idx].grid(row = 0, column = 3, sticky = N+W)
    frameControls[idx].propagate(0)
    frameControls[idx].grid_remove()
    
    logging(f'Updated:  {len(frameSubMenuCntrl)}/{len(frameControls)}, Preset Button Index {idx}')
    #3. Populate submenu with standard actions
    btnAction = [0,0,0]
    btnAction[0] = stdButtonStyle(\
        frameSubMenuCntrl[idx],
        text = 'Execute',
        width = 20,
        image = None,
        command = lambda:presetCommand(presetName, idx, "execute")
    )
    
    btnAction[1] = stdButtonStyle(\
        frameSubMenuCntrl[idx],
        text = 'Update',
        width = 20,
        image = None,
        command = lambda:presetCommand(presetName, idx, "update")
    )
    
    btnAction[2] = stdButtonStyle(\
        frameSubMenuCntrl[idx],
        text = 'Delete',
        width = 20,
        image = None,
        command = lambda:presetCommand(presetName,idx, "delete")
    )
    
    
    stdButtonActionGrid(btnAction[0])
    stdButtonActionGrid(btnAction[1])
    stdButtonActionGrid(btnAction[2])
    
    #temporary button data created, need to create permanenet button data in list or dict
    
    
    #4. Populate controls section with standard content (textbox)    
    eLblTemp = stdLabelStyle(frameControls[idx], text= f"PRESET SCRIPT {presetName.upper()}", theme = "title")
    eTxtTemp = stdTextStyle(frameControls[idx], text = JSONtxt)
    eLblTemp.grid(row = 0, sticky = N + W)
    eTxtTemp.grid(row = 1)
    
def menuButtons(idx, btnName = None):
    global maxAppHeight
    global menuButtonList
    global frameSubMenuCntrl
    
    menuButtonFeedback(idx)
    
    if btnName != None:
        if btnName not in menuButtonList:
            menuButtonList.append(btnName)
    
    #Hide all controls and action menu items for all 
    for fControl in frameControls:
        try:
            fControl.grid_remove()
        except Exception as e:
            PrintException(e)
  
    for fControl in frameSubMenuCntrl:
        try:
            fControl.grid_remove()
        except Exception as e:
            PrintException(e)
  

    try:
        frameSubMenuCntrl[idx].grid()
        frameControls[idx].grid()
    except Exception as e:
        PrintException(e)
        
    #frameControls[idx].configure(height=frameControls[0]["height"],width=frameControls[0]["width"])
    #frameControls[idx].grid_propagate(0)
    
    if idx == 0:
        pass
       #frameControls[idx]['text'] = 'S E T T I N G S'
        #Original grid settings are at bottom of code
    elif idx == 1:
        pass
        #frameControls[idx]['text'] = 'ACCOUNT-LEVEL MANAGEMENT'
    elif idx == 2:
        #frameControls[idx]['text'] = 'USER-LEVEL MANAGEMENT'
        frameUser.grid(\
            row = pos(0,rowPos),
            column = posC(0,colPos),
            columnspan = 3,
            sticky = NSEW
        )
    elif idx == 3:
        pass
        #frameControls[idx]['text'] = 'ZOOM API COMMANDS'
     
     
    (col,row) = frameAccount[0].grid_size()
    root.update()
    frameAccount[0].grid(\
        row = 0,
        rowspan = row+1,
        column= col + 15,
        columnspan = 2,
        sticky = NSEW
    )
    frameAccount[0].grid_columnconfigure(0, weight=1)
    frameAccount[0].grid_rowconfigure(0, weight=1)
    root.update()
    appHeight = 0

    totalHeight = root.winfo_height()
        
    totalWidth = root.winfo_width()
    #logHeight = frameLog.winfo_height() 
    appFrameHeight = frameApp.winfo_height()
    statusHeight = frameStatus.winfo_height()
    
    try:
        actionMenuHeight = frameSubMenuCntrl[idx].winfo_height()
    except Exception as e:
        actionMenuHeight = 0
        PrintException(e)
        
    #framesHeight =  - (logHeight + statusHeight)
    
    # Distance between action frame and log frame
    gapHeight = abs(appFrameHeight - actionMenuHeight)
    
    try:
        sizeDiff = (maxAppHeight - (totalHeight + gapHeight))
        
        
        
        if totalHeight < maxAppHeight:
            diff = maxAppHeight - totalHeight
        else:
            diff = 0
    except Exception as e:
        PrintException(e)
           
    #print (f'total: ({totalHeight}x{totalWidth}), update: {updateHeight}, size Diff {sizeDiff}, frame Height: {appFrameHeight}, action menu: {actionMenuHeight}, Gap: {gapHeight}')
    if diff > 4:
        #(col,row) = frameControls[0].grid_size
        #print(f'G0: {col}, {row}')
        try:
            btnSpacer = Button(\
                frameSubMenuCntrl[idx],
                text = "", 
                bg= colorScheme['6'],
                fg= colorScheme['6'],
                pady = diff / 2,
                highlightcolor = colorScheme['6'],
                activebackground = colorScheme['6'],
                activeforeground = colorScheme['6'],
                relief='flat'            
            )
            #lbSpacer.resizable(width=False, height=False)
            btnSpacer.grid()
        except Exception as e:
            PrintException(e)
            
        root.update()
        appHeight = root.winfo_height()
        print(f'Resized Height: {appHeight}')
        updateHeight = sizeDiff + gapHeight
        
        if appHeight < maxAppHeight:
            diff = maxAppHeight - appHeight
        
    
def btnTxtUpdates():
    """Method meant to update button text under the action frame,
       especially based on the checkboxes in the 'Options that prevent
       user updates' frame.
       
    Args:  None
    
    Returns:  None
    """   
    global btnOpenDeleteText
    global btnDeleteInactiveText
    
    btnSettingsText.set(f"Backup User Settings")    
    
    exclusions = []
    if chkRec.get() == 1:
        exclusions.append('Rec')
    if chkMeetings.get() == 1:
        exclusions.append('Meeting')
    if chkActivity.get() == 1:
        exclusions.append('Active')
    exclusions = "/".join(exclusions)
    
    if len(exclusions) > 0:
        scope = ''
    else:
        scope = ' all'
    
    if chkBasic.get() == 1:
        btnUpdateDelete["state"] = DISABLED
        inactiveTxt = f'Modify{scope} inactive users to Basic.  '
        emailTxt = 'Modify users via CSV email list to Basic.  '
        subAction = 'No Action'
    else:
        btnUpdateDelete["state"] = "normal"
        inactiveTxt = f'Delete{scope} inactive users. '
        emailTxt = 'Delete users via CSV email list.'       
        subAction = 'To Basic'
        
    

    
    if len(exclusions) > 0:
        btnDeleteInactiveText.set(f'{inactiveTxt}{subAction}: {exclusions}')
        btnOpenDeleteText.set(f'{emailTxt}{subAction}: {exclusions}')         
    else:
        btnDeleteInactiveText.set(f'{inactiveTxt}')
        btnOpenDeleteText.set(f'{emailTxt}')                 
    
    #mainloop()
    #root.update_idletasks()
        
def logConfigFrame():
    global frameSettings
    rows = 0
    try:
        root.update()
        for frm in frameSettings:
            (frColumns, frRows) = frameSettings[frm].grid_size()
            rows += frRows
        print(f'Grid Size: {frColumns}, {frRows}')
    except:
        frColumns = 3
        rows = 3
       
    frameSettings.append(\
        stdLabelFrameStyle(\
            frameControls[0],
            text = "Logging Options",
            )
    )  
    
    #(f'{frameSettings}')
    frIdx = len(frameSettings) - 1
    
        
    frameSettings[frIdx].grid(row = 0, rowspan = rows, column = frColumns, sticky = W)   
    
    
    
    chkbxLogTimeStamp = stdChkBxStyle(frameSettings[frIdx],text='Timestamp', variable = logConfig['timestamp'])
    chkbxLogTimeStamp.grid(row = pos(0,rowPos) , column = 0, sticky = W)
    chkbxLogTimeStamp.config(bd=2)
    
    chkbxLogWrap = stdChkBxStyle(frameSettings[frIdx],text='Wrap Lines', variable = logConfig['wrap'])
    chkbxLogWrap.grid(row = pos(1,rowPos) , column = 0, sticky = W)
    chkbxLogWrap.config(bd=2)
    
    chkbxLogInactive = stdChkBxStyle(frameSettings[frIdx],text='Display Inactive Users', variable = logConfig['inactive'])
    chkbxLogInactive.grid(row = pos(1,rowPos), column = 0, sticky = W)
    chkbxLogInactive.config(bd=2)
    
    chkbxLogNoGroup = stdChkBxStyle(frameSettings[frIdx],text='Display Users In No Group', variable = logConfig['noGroup'])
    chkbxLogNoGroup.grid(row = pos(1,rowPos), column = 0, sticky = W)
    chkbxLogNoGroup.config(bd=2)
    
    chkbxLogSave = stdChkBxStyle(frameSettings[frIdx],text=f'Save Logs', variable = logConfig['save'])
    chkbxLogSave.grid(row = pos(1,rowPos), column = 0, sticky = W)
    chkbxLogSave.config(bd=2)

    chkbxClip = stdChkBxStyle(frameSettings[frIdx],text='Click Line to Copy', variable = logConfig['clipboard'])
    chkbxClip.grid(row = pos(1,rowPos), column = 0, sticky = W)
    chkbxClip.config(bd=2)
    
    chkbxDebug = stdChkBxStyle(frameSettings[frIdx],text='Debug Mode', variable = logConfig['debug'])
    chkbxDebug.grid(row = pos(1,rowPos), column = 0, sticky = W)
    chkbxDebug.config(bd=2)

    chkbxTest = stdChkBxStyle(frameSettings[frIdx],text='Testing Mode', variable = logConfig['test'])
    chkbxTest.grid(row = pos(1,rowPos), column = 0, sticky = W)
    chkbxTest.config(bd=2)
    
def confirmationDialog(title, description, *btns):
    """Method meant to display secondary popup window that contains
       options to be pressed
       
    Args:  description (string) - Displays text in dialog box
           btns - multiple strings that contain buttons that should be displayed
    
    Returns:  dictionary of string variable to identify what button was pressed
    """     
    dialogBox = Toplevel(root)
    dialogBox.title(title)
    dialogBox.resizable(height = False, width = False)
        
    dialogFrame = LabelFrame(dialogBox, padx = 100, pady = 10, bg = colorScheme['3'], fg = colorScheme['1'])
    dialogFrame.grid(row = 0 , column = 0, sticky = W)   
    
    dictStruct = {}
    
    for btn in btns:
        dictStruct[btn] = BooleanVar()
        button = stdButtonStyle(textvariable = dictStruct[btn], text = btn)
        button.grid(row = 1, column = col(1,colPos))
    
    return dictStruct

def logConfigWindow():
    """Method meant to display secondary popup window that contains
       configuration settings for the log window
       
    Args:  None
    
    Returns:  None
    """   
    
    global logConfig
    try:
        logConfig['open'] = not logConfig['open']
    except:
        logConfig['open'] = True
        
        
    #if not logConfigWindow.top.winfo_exists():
    #logConfigWindow.top.lift(root)
    if logConfig['open'] is False:
        destroy_all_subwindows()
    if logConfig['open'] == True:
        logConfigWindow = Toplevel(root)
        logConfigWindow.title('Log Settings')
        logConfigWindow.resizable(height = False, width = False)
        
        frameConfig = LabelFrame(logConfigWindow, padx = 100, pady = 10, text = "Logging Options", bg = colorScheme['3'], fg = colorScheme['1'])
        frameConfig.grid(row = 0 , column = 0, sticky = W)   
        
        chkbxLogTimeStamp = stdChkBxStyle(frameConfig,text='Timestamp', variable = logConfig['timestamp'])
        chkbxLogTimeStamp.grid(row = pos(0,rowPos) , column = 0, sticky = W)
        chkbxLogTimeStamp.config(bd=2)
        
        chkbxLogWrap = stdChkBxStyle(frameConfig,text='Wrap Lines', variable = logConfig['wrap'])
        chkbxLogWrap.grid(row = pos(1,rowPos) , column = 0, sticky = W)
        chkbxLogWrap.config(bd=2)
        
        chkbxLogInactive = stdChkBxStyle(frameConfig,text='Display Inactive Users', variable = logConfig['inactive'])
        chkbxLogInactive.grid(row = pos(1,rowPos), column = 0, sticky = W)
        chkbxLogInactive.config(bd=2)
        
        chkbxLogNoGroup = stdChkBxStyle(frameConfig,text='Display Users In No Group', variable = logConfig['noGroup'])
        chkbxLogNoGroup.grid(row = pos(1,rowPos), column = 0, sticky = W)
        chkbxLogNoGroup.config(bd=2)
        
        chkbxLogSave = stdChkBxStyle(frameConfig,text=f'Save Logs', variable = logConfig['save'])
        chkbxLogSave.grid(row = pos(1,rowPos), column = 0, sticky = W)
        chkbxLogSave.config(bd=2)
        
        chkbxDebug = stdChkBxStyle(frameConfig,text='Debug Mode', variable = logConfig['debug'])
        chkbxDebug.grid(row = pos(1,rowPos), column = 0, sticky = W)
        chkbxDebug.config(bd=2)

        chkbxTest = stdChkBxStyle(frameConfig,text='Testing Mode', variable = logConfig['test'])
        chkbxTest.grid(row = pos(1,rowPos), column = 0, sticky = W)
        chkbxTest.config(bd=2)

def keyPress(event):
    print ("pressed", repr(event.char))
    
    ignoreKeys = ['\x01','\x08','\r']
    
    listbox['background'] = colorScheme['1']
    listbox['foreground'] = colorScheme['0']
    
    if event.char == '\x08':
        text = txtLogSearch.get()[0:-2]
        searchString = f"{text}"
    if event.char not in ignoreKeys:
        searchString = f"{txtLogSearch.get()}{event.char}"
    else:
        #@@To Do to fix backspace
        searchString = f"{txtLogSearch.get()}"
    print (f'{searchString}')
    (index,count) = logSearchIndex(listbox,searchString)
    print(f'Index: {index}, Matches:{count}')
        
    if count != 0:
        listbox.see(index[0])
    
    

def logSearchNext(lbObj):
    global indexList
    currIndex = int(lbObj.index(ACTIVE))
    
    if len(indexList) > 0:
        lbObj.itemconfig(currIndex, background = colorScheme['0'], foreground = colorScheme['1'])
        indexList.sort()
        print(f'#Current Index Search: {currIndex}, {indexList},{indexList[:-1][0]}')
        if currIndex >= indexList[-1]:
            currIndex = -1
        

        for item in indexList:
            if item > currIndex:
                print (f'#Found next item: {item}')
                lbObj.see(item)
                lbObj.activate(item)
                lbObj.itemconfig(item, background = colorScheme['6'], foreground = colorScheme['0'])
                break
        
        
    
    
def logSearchIndex(lbObj,text):
    global indexList
    
    indexList = []
    count = 0
    print(f'Searching for: {text}')
    listData = lbObj.get(0, "end")
    print(f'{listData}')
    for element in listData:
        itemIdx = listData.index(element)
        lbObj.itemconfig(itemIdx, background = colorScheme['1'], foreground = colorScheme['0'])
        if text.lower() in element.lower() and len(text) > 0:
            count += 1
            indexList.append(itemIdx)
            print (f'Index:{itemIdx}')
            lbObj.activate(itemIdx)
            lbObj.itemconfig(itemIdx, background = colorScheme['0'], foreground = colorScheme['1'])
            lbObj.itemconfig(indexList[0], background = colorScheme['6'], foreground = colorScheme['0'])
    
    if len(indexList) <= 1:
        btnLogSearch['state'] = "disabled"
    else:
        btnLogSearch['state'] = "normal"
    return (indexList,count)
    
       

def stdChkBxStyle(origin, text = None, image = None, width = 25, command = None, state = "normal", variable = None):
    
    chkbxObj = Checkbutton(\
        origin,
        text = text,
        bd = 0,
        image = image,
        compound = LEFT,
        padx = 2,
        pady = 2,
        width = width,
        #disabledforeground = colorScheme['5'],
        bg= colorScheme['3'],
        fg= colorScheme['1'],
        selectcolor=colorScheme['3'],
        highlightcolor = colorScheme['1'],
        activebackground = colorScheme['3'],
        activeforeground = colorScheme['1'],        
        relief='flat',
        anchor = W,
        font = ('verdana', 8, 'bold'),
        state = state,
        variable = variable,
        command = command
        )
    
    return chkbxObj        
        
def stdFontStyle(theme = "", font = 'verdana',size = 8, weight = 'normal'):
    
    
    if theme == "":
        return (font, size, weight)
    if theme == "title":
        return ("verdana", 9, 'bold')

def stdLabelLinkStyle(origin, text, theme = "", textvariable = None):
    
    objLabel = Label(\
        origin,
        text = text,
        bg = colorScheme['3'],
        fg = "blue",
        cursor = "hand2",
        textvariable = None,
        font = stdFontStyle(theme = theme)
    )
    
    return objLabel

def stdFrameSubMenuGrid(origin):
    origin.grid(
        row = pos(0,rowPos),
        rowspan = 15,
        column = 0,
        sticky = N+S
    )
    
    origin.grid_columnconfigure(0, weight=1)

def stdFrameControlStyle(origin, text = None, pady = 0, width = 200, height = 200):
    objLabelFrame = LabelFrame(
            origin,
            bg= colorScheme['3'],
            fg= colorScheme['1'],
            highlightcolor = colorScheme['3'],
            relief='flat',
            labelanchor = N+W,
            width= width,
            height= height,
            padx = 0,
            pady = 0,
            bd = 0,
            font= ('verdana', 10, 'bold'),
            text = text
    )
   
    objLabelFrame.configure(height=324)
    return objLabelFrame        

def stdFrameSubMenuStyle(origin, text = None):
    objLabelFrame = LabelFrame(
        origin,
        padx = 0,
        pady = 0,
        bg= colorScheme['6'],
        fg= colorScheme['3'],
        height = 100,
        width = 30,
        bd = 0,
        relief='flat',
        #anchor = W,
        text = text
        )
    
    objLabelFrame.configure(height=324)
    
    objLabel = Label(
        objLabelFrame,
        text="              ACTIONS             ",
        bg = colorScheme['6'],
        fg = colorScheme['3'],
        pady = 5,
        font= ('verdana', 10, 'bold'),
        justify = 'center'
    )

    objLabel.grid(row = pos(0,rowPos), column= 0, sticky = N)
    
    objLabelFrame.grid(row = pos(0,rowPos), column = 0, sticky = N+W)
    
    return objLabelFrame

def stdButtonActionGrid(btnObj):
      
    btnObj.grid(\
        row = pos(2,rowPos),
        column = posC(0,colPos),
        padx = (0,10),
        sticky = NSEW        
    )

    
def stdComboboxStyle(origin, textvariable = None, values = None, postcommand = None):
    
    objCombobox = ttk.Combobox(
        origin,
        state = "readonly",
        height = 10,
        background = colorScheme['4'],
        foreground = colorScheme['3'],
        font = stdFontStyle(),
        image = None,
        postcommand = postcommand,
        textvariable = textvariable,
        values = values        
    )
    
    
    return objCombobox
def stdComboboxMenuStyle(origin, textvariable = None, values = None, postcommand = None):
    
    objCombobox = ttk.Combobox(
        origin,
        #state = "readonly",
        height = 10,
        background = colorScheme['4'],
        foreground = colorScheme['2'],
        font = stdFontStyle(),
        image = None,
        postcommand = postcommand,
        textvariable = textvariable,
        values = values        
    )
    
    
    return objCombobox
    
def stdButtonMenuStyle(origin, text = None, image = None, width = 'std', command = None, state = "normal", textvariable = None):
    try:
        if width == 'std':
            width = 18
    except:
        pass
        
    btnObj = Button(\
        origin,
        text = text,
        bd = 2,
        image= image,
        compound = LEFT,
        padx = 5,
        pady = 8,
        width= width,
        bg= colorScheme['2'],
        fg= colorScheme['4'],        
        highlightcolor = colorScheme['3'],
        activebackground = colorScheme['1'],
        activeforeground = colorScheme['3'],       
        relief='flat',
        anchor = 'center',
        cursor = 'hand2',
        font= ('verdana', 9, 'bold'),
        state = state,
        textvariable = textvariable,
        command = command
        )
    
    return btnObj
    
def stdEntryStyle(origin, width = 15, textvariable = None, show = None ):

    entryObj = Entry(\
        origin,
        show = show,
        bd = 2,
        bg= colorScheme['4'],
        fg= colorScheme['3'],
        font= stdFontStyle(),
        textvariable = textvariable,
        state = 'normal',
        relief = 'groove',
        width = width,
        justify = 'left'
    )
    
    return entryObj

def stdTextStyle(origin, height = 20, width = 50, text = None, textvariable = None, show = None ):

    textObj = Text(\
        origin,
        bd = 2,
        bg= colorScheme['4'],
        fg= colorScheme['3'],
        font= stdFontStyle(),
        textvariable = textvariable,
        state = 'normal',
        relief = 'groove',
        height = height,
        width = width
    )
    
    textObj.insert('1.0', json.dumps(text, sort_keys=True, indent=4))
    
    return textObj



def stdLabelStatusStyle(origin, text, textvariable, width = 26, theme = ""):
    
    objLabel = Label(\
        origin,
        text = text,
        bg = colorScheme['3'],
        fg = colorScheme['1'],
        width = width,
        textvariable = textvariable,
        font = stdFontStyle(theme = theme)
    )
    
    return objLabel
    
    
def stdLabelStyle(origin, text, theme = ""):
    
    objLabel = Label(\
        origin,
        text = text,
        bg = colorScheme['3'],
        fg = colorScheme['1'],
        font = stdFontStyle(theme = theme)
    )
    
    return objLabel
    
def stdLabelFrameStyle(origin, text = None, image = None, width = 100):
    
    frameObj = LabelFrame(\
        origin,
        padx = 5,
        pady = 5,
        bg= colorScheme['3'],
        fg= colorScheme['1'],
        bd = 0,
        #relief='raised',
        width = width,
        labelanchor = N+W,
        text = text
    )
    
    return frameObj

def stdProgressBarStyle(origin, length = 100, variable = None):
    s = ttk.Style()
    s.theme_use('clam')
    s.configure("red.Horizontal.TProgressbar", foreground='red', background='red')
    progressBar = ttk.Progressbar(origin, style="red.Horizontal.TProgressbar", variable = variable, orient="horizontal", length=length,mode="determinate")
    #s.configure("Horizontal.TProgressbar", troughcolor ='gray', background='green')
    return progressBar


def stdButtonStyle(origin, text = None, image = None, width = 30, command = None, state = "normal", textvariable = None):
    btnObj = Button(\
        origin,
        text = text,
        bd = 1,
        image = image,
        compound = LEFT,
        padx = 5,
        pady = 5,
        width = width,
        #disabledforeground = colorScheme['5'],
        bg = colorScheme['2'],
        fg = colorScheme['1'],
        wraplength = 140,
        highlightcolor = colorScheme['1'],
        activebackground = colorScheme['1'],
        activeforeground = colorScheme['3'],        
        relief = 'raised',
        anchor = 'center',
        font = stdFontStyle(),
        state = state,
        cursor = 'hand2',
        textvariable = textvariable,
        command = command
        )
    
    return btnObj
    
def stdButtonActionStyle(origin, text = None, image = None, width = 30, command = None, state = "normal", textvariable = None):
    btnObj = Button(\
        origin,
        text = text,
        bd = 0,
        image = image,
        compound = LEFT,
        padx = 1,
        pady = 4,
        width = width,
        #disabledforeground = colorScheme['5'],
        bg = colorScheme['6'],
        fg = colorScheme['3'],
        wraplength = 140,
        highlightcolor = colorScheme['1'],
        activebackground = colorScheme['1'],
        activeforeground = colorScheme['3'],        
        relief = 'raised',
        anchor = 'center',
        font = stdFontStyle(),
        state = state,
        cursor = 'hand2',
        textvariable = textvariable,
        command = command
        )
    
    btnObj.config(highlightbackground=colorScheme['3'])
    
    return btnObj
        
def preset_step():
    global presets
    
    
    '''
    Planning:
    JSON Structure
    
        "Preset Name":
            [
                {
                    "method":string,
                    "url":string,
                    "parameters":dict,
                    "body":dict,
                    "ids":dict,
                    "response":dict,
                    "chain":dict,
                    "delay":int (optional, if 0 waits for response)
                }
             ]   
        A step can include data from previous step
        (I'm calling it attribute chaining)
        in the form of JSON dict data, like account id
        which is populated based on square-plus brackets  [+ +]
        i.e. id [+account_name+], account name is pulled from
        previous data
        
        adding a step will execute the previous step to
        get the data generated to generate a list
        of fields for the user to select one attribute to include in the
        next step (drop down selection?)
    '''
    try:
        txtName = etxtAPIPresetName.get()
    except:
        txtName = '__temp'
        
    try:
        txtBody = json.loads(etxtAPIBody.get())
        jsonBody = json.dumps(txtBody, sort_keys=True, indent=4)
    except:
        txtBody = None
        jsonBody = None
    
    try:
        txtParam = json.loads(etxtAPIParam.get())
        jsonParam = json.dumps(txtParam, sort_keys=True, indent=0)
        jsonParam = jsonParam.replace("\n   ","")
        jsonParam = jsonParam.replace("\n","")
        jsonParam = jsonParam.replace('\\"','"')
    except:
        txtParam = None
        jsonParam  = None
    
    
    try:
        txtIDs = eTxtApiId.get()
    except:
        txtIDs = None
    
    try:
        # headerURL
        url =  f'{apiVer}{etxtAPI.get()}'
    except:
        url = None
    
    if txtName not in presets:
        logging(f"Creating new preset {txtName}")
        presets.update({txtName:[]})


        
    try:
        response = \
            send_REST_request(\
                apiType = url,
                body= txtBody,
                param = txtParam,
                rType = RESTmethod.get(),
                note= f"Custom API temp preset step {txtName}",
            )
    except:
        response = None
    
    logging(f'Response:{response}')
    
    
    
    try:
        presetDict = {
            "index":len(presets[txtName]) + 1,
            "method":RESTmethod.get(),
            "url":url,
            "parameters":jsonParam,
            "body":jsonBody,
            "ids":txtIDs,
            "chain":{},
            "delay":0,
            "response":{}
        }
        presets[txtName].append(presetDict)
        
    except Exception as e:
        PrintException(e)
    ## Break down response to a list popup with selection list of  item:value        
    buildPresetButton(txtName, frameMenu, frameApp, JSONtxt =   presets[txtName])
    

def preset_store():
    '''
    Planning
    
    Storing a preset:
        1.  Save JSON struct dict to a presets file in local folder
        2.  A button is generated in the primary Options Menu
        3.  Selecting the option will have a button that says "start preset" and "save preset" in actions menu
        4.  Control Frame will list in a large, scrollable text box the
            JSON dict that can be editted (dict to JSON string)
    '''
    pass
    
    
def onListAPIMenuSelect(event):
    """Method meant to update onscreen listbox for API commands in  Actions sub-menu frame
       
    Args:  event (obj) data passed from tkinter bind event on selecting an item in
    the sub-menu list
    
    Returns:  None
    """
    
    objWidget = event.widget
    
    #Find the item selected in the list and see
    # what action is needed
    try:
        idx = int(objWidget.curselection()[0])
    except:
        idx = 0
    objWidget.update()
    value = objWidget.get(idx)
    
    print('You selected item {}: {}, Menu:  {}'.format(idx, value, apiMenu))
    
    if value == "<< Back to API Categories":
        apiListMenuCategory()   
    elif apiMenu == 'category':
        apiListMenuCommands(value)
    else:
        apiCommandPopulate(apiMenu, value)

def apiCommandPopulate(category, command):

    menuAPICmdValues(category)
    etxtAPI.delete(0,END)
    etxtAPIParam.delete(0,END)
    etxtAPIBody.delete(0,END)
    emenuAPICmd.delete(0,END)
    
    print (f"Category: {category}, Command: {command}, {apiData}")
    
    # Set radio button to match command's REST method
    try:
        RESTmethod.set(apiData[category][command]['method']) # initialize
    except Exception as e:
        PrintException(e)
    
    # Update query parameter sample to display in appropriate entry field
    if "query_param" in apiData[category][command]:
        text = json.dumps(apiData[category][command]["query_param"])
        text = apiData[category][command]["query_param"]
        etxtAPIParam.insert(0,text)
    
    #update body contents sample to display in appropriate entry field
    if "body" in apiData[category][command]:
        #text = json.dumps(apiData[category][command]["body"])
        text = apiData[category][command]["body"]
        etxtAPIBody.insert(0,text)
      
    #update combo list for command urls
    if "url" in apiData[category][command]:
        #text = json.dumps(apiData[category][command]["url"])
        text = apiData[category][command]["url"]
        # find if text exists in current combo list else just populate it
        if text in apiData[category]:
            indexTxt= apiData[category].index(text)
            content = apiData[category][text]
            apiCommand.set(indexTxt)   
        else:
            logging(f'Equivalent {category} command not listed in drop down menu', debugOnly = True)
            content = text
            etxtAPI.insert(0,content)
            emenuAPICmd.insert(0, content)
            apiCommand.set(content)
        #emenuAPICmd.current(emenuAPICmd['values'].index(text))
        if "{" not in text:
            eLblApiId.grid_remove()
            eTxtApiId.grid_remove()
        else:
            eLblApiId.grid()
            eTxtApiId.grid()
    
        
def apiListMenuCategory():
    global apiMenu
    
    apiMenu = "category"
    apiCommandsList.delete(0,END)
    for category in reversed(apiData):
        apiCommandsList.insert(0, category)
        
    if len(apiData) > 35:
        sbAPIList.grid()
    else:
        try:
            sbAPIList.grid_remove()
        except Exception as e:
            PrintException(e)
    
    ##@@TODO Resize and remove spacer buttons
    menuButtons(3)
    
def apiListMenuCommands(category):
    global apiMenu
    
    apiMenu = category
    emenuAPICat.set(category)
    apiCommandsList.delete(0,END) 
    for command in reversed(apiData[category]):
        apiCommandsList.insert(0, command)
    apiCommandsList.insert(0, "<< Back to API Categories")
    
    if len(apiData[category]) > 15:
        sbAPIList.grid()
    else:
        try:
            sbAPIList.grid_remove()
        except:
            pass
        
    ##@@TODO Resize and remove spacer buttons
    menuButtons(3)     

def apiListMenu(origin, variable = None):
    global apiListVar
    
    apiListVar = StringVar(origin)

    lbAPI = Listbox(\
        origin,
        setgrid = 1,
        width = 26,
        activestyle= 'dotbox',
        bg= colorScheme['6'],
        fg= colorScheme['3'],
        selectbackground= colorScheme['2'],
        highlightthickness=0,
        relief = "flat",
        cursor = "hand2",
        font = stdFontStyle(size = 10, weight = "normal"),
        bd = 0,
        name='apiListVar'
        )

    lbAPI.bind('<<ListboxSelect>>',onListAPIMenuSelect )
    lbAPI.grid(\
        row = pos(3,rowPos),
        column = posC(0,colPos),
        padx = 10,
        #columnspan = colPosMax,
        sticky = NSEW
        )
              
    sbAPI = Scrollbar(
        origin,
        relief = "flat",
        troughcolor = colorScheme['4']        
        ) 
    
    sbAPI.grid(
        row = rowPos,
        column = colPos,
        rowspan=40,
        sticky = N+S+E
    )
    
    
    lbAPI.config(yscrollcommand = sbAPI.set)  
    sbAPI.config(command = lbAPI.yview)
    
    apiData = openAPIListDetailed()
    
    try:
        for category in reversed(apiData):
            lbAPI.insert(0, category)

        if len(apiData) > 15:
            sbAPI.grid()
        else:
            sbAPI.grid_remove()
    
    except Exception as e:
        print (f'API List Menu Error: {e}')
        sbAPI.grid_remove()
        category = ""
        

        
    apiMenuType = 'category'
    
    return (apiData,lbAPI,sbAPI, category,apiMenuType)

    
rowPos = 0
colPos = 0
colPosMax = 12

# Build Primary Window
root = Tk()
root.option_add('*font', ('verdana', 8, 'bold'))
root.configure(bg=colorScheme["3"])
root.title('Zeus Tool:  Zoom Enterprise User Support Tool v0.8.19')
root.geometry("600x1050")
root.resizable(height = 600, width = 1050)

#try:
#    gui = Canvas(root, bg="blue", height=650, width=1015)
#    filename = PhotoImage(file = ".\ZeusT-BG.png")
#    background_label = Label(gui, image=filename)
#    background_label.place(x=0, y=0, relwidth=1, relheight=1)
#except Exception as e:
#    PrintException(e)
#    print(f'Error {e}')
#try:
#    background_image=PhotoImage('.\ZeusT-BG.png')
#    background_label = Label(root, image=background_image)
#    background_label.photo=background_image
#    background_label.place(x=0, y=0, relwidth=1015, relheight=650)
#except Exception as e:
#    print(f'Image Error: {e}')

#Display Title within application

iconFolder = PhotoImage(master=root, file='folder.png')
 


style = ttk.Style() 
style.configure(\
                'W.TButton',
                font = ('verdana', 10, 'bold',), 
                foreground = colors['light-brown'],
                background = colors['blue'],
                space = colors['brown']
                )

#style.map('W.TButton', foreground = [('active', 'disabled', 'green')], background = [('active', 'black')]) 

paneApp = PanedWindow(\
    root,
    bg= colorScheme['3'],
    orient= VERTICAL,
    showhandle = True,
    opaqueresize = True,
    handlesize = 4,
    handlepad = 4,
    sashpad = 4,
    #cursor = "hand2",
    #sashcursor = sb_v_double_arrow,
    sashrelief = 'flat',
    relief='flat'   
    )

frameApp = LabelFrame(\
    paneApp,
    bg= colorScheme['3'],
    text = '',
    padx = 0,
    pady = 0,
    relief='flat' 
    )

paneApp.add(frameApp)




frameMenu = LabelFrame(\
    root,
    bg= colorScheme['2'],
    fg= colorScheme['1'],
    highlightcolor = colorScheme['3'],
    relief='flat',
    padx = 0,
    pady = 5,
    labelanchor = N,
    font= ('verdana', 10, 'bold'),
    text="OPTIONS"  
    )


#frameSubMenu = stdFrameSubMenuStyle(paneApp)

frameSubMenuCntrl =  []

for i in range(0,5):
    frameSubMenuCntrl.append(
            stdFrameSubMenuStyle(frameApp)
        )
    frameSubMenuCntrl[i].propagate(0) 
    frameSubMenuCntrl[i].grid_remove()
    

frameControls = []

for i in range(0,5):
    frameControls.append(stdFrameControlStyle(frameApp))
    frameControls[i].propagate(0)
    

    
    
    

print(f'Length of frameControls: {len(frameControls)}')
frameLog = LabelFrame(\
    paneApp,
    bg= colorScheme['3'],
    fg= colorScheme['1'],
    highlightcolor = colorScheme['6'],
    relief='groove',
    bd = 1,
    labelanchor = N+W,
    font= ('verdana', 10, 'bold'),    
    text = ""
    )

paneApp.add(frameLog)

colPosMax = 16

frameStatus = LabelFrame(\
    root,
    bd = 4,
    bg= colorScheme['3'],
    fg= colorScheme['1'],
    highlightcolor = colorScheme['3'],
    relief='flat',
    labelanchor = W,
    font= ('verdana', 10, 'bold'), 
    text = ""
    )


#rows = 0
#while rows < 20:
#    paneApp.rowconfigure(rows, weight=1)
#    paneApp.columnconfigure(rows,weight=1)
#    rows += 1
frameApp.grid(
        row = pos(0,rowPos),
        column = posC(0,colPos),
        columnspan = colPosMax,
        sticky = NSEW
    )

paneApp.grid(column = 3, sticky = NSEW)   




frameLog.grid(\
        row = pos(1,rowPos),
        column = posC(0,colPos),
        columnspan = colPosMax,
        sticky = NSEW    
    )

frameStatus.grid(\
        row = 1,
        column = posC(0,colPos),
        columnspan = colPosMax + 3,
        sticky = E
        )



frameMenu.grid(\
        row = pos(0,rowPos),
        rowspan = 11,
        column = posC(0,colPos),
        columnspan = 2,
        sticky = N+S+W
    )

for fControl in frameControls:
    colPos = 3
    fControl.grid(\
            row = rowPos,
            rowspan = 10,
            column = posC(2,colPos),
            columnspan = 12,
            sticky = N+E
        )


frameAccount = []
frameSettings = []
frameSettings1 = []

# Three no-title frames inside settings(actions, Credentials, Logging)
#frameSettings.append(
#    stdFrameSubMenuStyle(
#        frameSubMenuCntrl[0]
#        )
#    )



frameSettings.append(stdLabelFrameStyle(\
    frameControls[0],
    text = ""
    ))


frameSettings[-1].grid(\
        row = pos(0,rowPos), rowspan = 10, column = posC(0,colPos), sticky = N+W)


eLblAPI = stdLabelStyle(frameSettings[-1], text="Zoom Communication", theme = "title")


elblJWTHelp = stdLabelLinkStyle(frameSettings[-1], text="Where do I get this?")
elblJWTHelp.bind("<Button-1>", lambda e: urlOpen("https://marketplace.zoom.us/docs/guides/build/jwt-app#:~:text=To%20register%20your%20app%2C%20visit,type%20and%20click%20on%20Create."))

eLblAPIKey = stdLabelStyle(frameSettings[-1], text="API Key*")
eAPIKey = stdEntryStyle(frameSettings[-1])
eLblAPISecret = stdLabelStyle(frameSettings[-1], text="API Secret*")
eAPISecret = stdEntryStyle(frameSettings[-1], show='*')
eLblAcctID = stdLabelStyle(frameSettings[-1], text="Alternate Account")
eAcctID = stdEntryStyle(frameSettings[-1])
eLblDomainInfo = stdLabelStyle(frameSettings[-1], text="Auto-Fill Settings", theme = "title")
eLblDomain =  stdLabelStyle(frameSettings[-1], text="Email Domain")
eDomain = stdEntryStyle(frameSettings[-1])

eLblLDAP = stdLabelStyle(frameSettings[-1], text="LDAP Settings", theme = "title")
eLblLDAPHost = stdLabelStyle(frameSettings[-1], text="LDAP Host")
eLDAPHost = stdEntryStyle(frameSettings[-1])
eLblLDAPUser = stdLabelStyle(frameSettings[-1], text="LDAP Login")
eLDAPUser = stdEntryStyle(frameSettings[-1])
eLblLDAPPass = stdLabelStyle(frameSettings[-1], text="LDAP Password")
eLDAPPass = stdEntryStyle(frameSettings[-1], show='*')

eLblFileMgmt = stdLabelStyle(frameSettings[-1], text="File Management", theme = "title")
eLblFolderPath = stdLabelStyle(frameSettings[-1], text="Default Save Folder")
eTxtFolderPath = stdEntryStyle(frameSettings[-1])
eBtnFolderPath = stdButtonStyle(frameSettings[-1], text = "Default Folder", width = 12, command = FolderPath)


eLblRecData = stdLabelStyle(frameSettings[-1], text="Recordings Metadata")
eBtnRecData = stdButtonStyle(frameSettings[-1], text = "Select Files", width = 12, command = open_recordings_metadata)




eLblAPI.grid(row = pos(0,rowPos), column = posC(0,colPos), sticky = NSEW)
elblJWTHelp.grid(row = pos(1,rowPos), column= posC(0,colPos), columnspan=2, sticky = E)

eLblAPIKey.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = E)
eAPIKey.grid(row = rowPos, column = posC(1,colPos), sticky = W)

eLblAPISecret.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = E)
eAPISecret.grid(row = rowPos, column = posC(1,colPos), sticky = W)

eLblAcctID.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = E)
eAcctID.grid(row = rowPos, column = posC(1,colPos), sticky = W)


eLblDomainInfo.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = NSEW)
eLblDomain.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = E)
eDomain.grid(row = rowPos, column = posC(1,colPos), sticky = W)

eLblLDAP.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = NSEW)
eLblLDAPHost.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = E)
eLDAPHost.grid(row = rowPos, column = posC(1,colPos), sticky = W)

eLblLDAPUser.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = E)
eLDAPUser.grid(row = rowPos, column = posC(1,colPos), sticky = W)

eLblLDAPPass.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = E)
eLDAPPass.grid(row = rowPos, column = posC(1,colPos), sticky = W)

eLblFileMgmt.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = NSEW)
eLblFolderPath.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = E)
eTxtFolderPath.grid(row = rowPos, column = posC(1,colPos), sticky = W)
eBtnFolderPath.grid(row = pos(1,rowPos), column = posC(1,0), sticky = W)

eTxtFolderPath.insert(END,os.getcwd())

eLblRecData.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = E)
eBtnRecData.grid(row = pos(1,rowPos), column = posC(1,0), sticky = W)

logConfig = {}
logConfig['timestamp'] = IntVar(value = 1)
logConfig['wrap'] = IntVar(value = 1)
logConfig['inactive'] = IntVar(value = 1)
logConfig['noGroup'] = IntVar(value = 1)
logConfig['save'] = IntVar(value = 1)
logConfig['debug'] = IntVar(value = 0)
logConfig['test'] = IntVar()
logConfig['clipboard'] = IntVar(value = 1)

logConfigFrame()


#frameSettings1[0].grid(\
#        row = pos(0,rowPos), column = posC(0,colPos), sticky = NSEW)

#root.update()
#(frRows, frColumns) = frameSettings1[0].grid_size()




btnOpenDeleteText = StringVar()
btnDeleteInactiveText = StringVar()
btnSettingsText = StringVar()

btnRetrieve = stdButtonStyle(frameSubMenuCntrl[1], text = "Retrieve All User Data", width = 25, command = retrieveZoomUsers)
btnOpen = stdButtonStyle(frameSubMenuCntrl[1], text = "Open All User Data", image = iconFolder, width = 25, command = csvOpen, state = DISABLED)
btnOpenDelete = stdButtonStyle(\
    frameSubMenuCntrl[1],
    textvariable = btnOpenDeleteText,
    image = iconFolder,
    width = 25,
    command = csvOpenDelete,
    state = DISABLED
    )

btnDeleteInactive = stdButtonStyle(\
    frameSubMenuCntrl[1],
    textvariable = btnDeleteInactiveText,
    width = 25,
    command = Relicense_Inactive,
    state = DISABLED
    )

btnSettingsStats = stdButtonStyle(
    frameSubMenuCntrl[1],
    textvariable = btnSettingsText,
    width = 25,
    command = get_users_settings,
    state = DISABLED
    )


btnAcctAttribs = stdButtonStyle(
    frameSubMenuCntrl[1],
    text = "Update Custom Attribute for all filtered users",
    width = 25,
    command = update_users_attrib,
    state = DISABLED
    )

btnAcctRec = stdButtonStyle(\
    frameSubMenuCntrl[1],
    text = "Get all acct Recording Metadata",
    width = 25,
    command = get_account_recordings
    )

stdButtonActionGrid(btnRetrieve)
stdButtonActionGrid(btnOpen)
stdButtonActionGrid(btnOpenDelete)
stdButtonActionGrid(btnDeleteInactive)
stdButtonActionGrid(btnSettingsStats)
stdButtonActionGrid(btnAcctAttribs)
stdButtonActionGrid(btnAcctRec)

frameAccount.append(stdLabelFrameStyle(\
    frameControls[1],
    text="Options that prevent user updates"
    ))

frameProcess = LabelFrame(\
    frameAccount[-1],
    padx = 0,
    pady = 0,
    bg = colorScheme['3'],
    fg = colorScheme['1'],    
    text = "Restart Processing"
    )


frameAttribs = LabelFrame(\
    frameAccount[-1],
    padx = 0,
    pady = 0,
    bg = colorScheme['3'],
    fg = colorScheme['1'],    
    text = "Custom Attributes"
    )


filterGroup = StringVar()
chkBasic = IntVar(value=1)
chkMeetings = IntVar()
chkRec = IntVar()
chkActivity = IntVar()

groupFilterList = ['All Users','Users in no Groups']
filterGroup.set(groupFilterList[0])


elblFilter = stdLabelStyle(frameAccount[-1], text= "Limit to   ")
emenuGroupFilter = ttk.Combobox(frameAccount[-1], textvariable=filterGroup, values=groupFilterList)
chkbxBasic = stdChkBxStyle(frameAccount[-1],text='Change user to Basic (No Deletes)', variable = chkBasic, command = btnTxtUpdates)
chkbxMeetings = stdChkBxStyle(frameAccount[-1],text='Check for Upcoming Meetings', variable = chkMeetings, command = btnTxtUpdates)
chkbxRecordings = stdChkBxStyle(frameAccount[-1],text='Check for Cloud Recordings', variable = chkRec, command = btnTxtUpdates)
chkbxActivity = stdChkBxStyle(frameAccount[-1],text='Check for user Activity', variable = chkActivity, command = btnTxtUpdates)
eLbl8 = stdLabelStyle(frameAccount[-1], text="No. of months to check for recordings")
eRecMonths = stdEntryStyle(frameAccount[-1])
eLblRecDates = stdLabelStyle(frameAccount[-1], text="Date to start checking recordings (YYYY-MM)")
eTxtRecDates = stdEntryStyle(frameAccount[-1])
eLblInactive = stdLabelStyle(frameAccount[-1], text="Date of last login for an inactive user (mm/dd/yyyy)")
eDate = stdEntryStyle(frameAccount[-1])
eLblMonthsActive = stdLabelStyle(frameAccount[-1], text="Months to be considered still active")
eActiveUser = stdEntryStyle(frameAccount[-1])


eRecMonths.delete(0, END)
eRecMonths.insert(0, "6")

eActiveUser.delete(0, END)
eActiveUser.insert(0, "0")

eDate.delete(0, END)
eDate.insert(0, "01/01/2019")

frameAccount[-1].grid(\
            row = pos(0,rowPos),
            column= posC(1,colPos),
            sticky = NSEW
        )



elblFilter.grid(row=rowPos, column = posC(0,colPos), sticky = W)
emenuGroupFilter.grid(row=rowPos, column = posC(0,colPos), sticky = E)
chkbxBasic.grid(row = pos(1,rowPos) , column = posC(0,colPos), sticky = W)
chkbxMeetings.grid(row = pos(1,rowPos) ,column = posC(0,colPos), sticky = W)
chkbxRecordings.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = W)
chkbxActivity.grid(row = pos(1,rowPos) , column = posC(0,colPos), sticky = W)
eLbl8.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = W)
eRecMonths.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = W)
eLblRecDates.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = W)
eTxtRecDates.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = W)
eLblMonthsActive.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = W)
eActiveUser.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = W)
eLblInactive.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = W)
eDate.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = W)
#eLbl = Label(frameAccount[-1], text="Months since last signin to be Inactive")
#eLbl.grid(row = pos(1,rowPos), column = colPos, columnspan = int(colPosMax / 3))
#eMonths = Entry(root)
#eMonths.pack()

frameProcess.grid(\
            row = pos(1,rowPos),
            column = colPos,
            #columnspan = frColumns+1,
            sticky = NSEW
        )

frameAttribs.grid(\
            row = pos(1,rowPos),
            column = colPos,
            #columnspan = frColumns+1,
            sticky = NSEW
        )

elblProcEmail = stdLabelStyle(frameProcess, text="Email")
etxtProcEmail = stdEntryStyle(frameProcess)
elblProcEmail.grid(row = pos(0,rowPos), column = posC(0,colPos), sticky = NSEW)
etxtProcEmail.grid(row = rowPos, column = posC(1,colPos), sticky = E)




customAttrib = StringVar()
customAttribList = ["None"]
customAttrib.set(customAttribList[0])

elblAttribSet = stdLabelStyle(frameAttribs, text="Set ")
emenuAttrib = ttk.Combobox(frameAttribs, textvariable=customAttrib, values=customAttribList)
elblAttribTo = stdLabelStyle(frameAttribs, text=" to ")
etxtAttrib = stdEntryStyle(frameAttribs)

elblAttribSet.grid(row = pos(0,rowPos), column = posC(0,colPos), sticky = NSEW)
emenuAttrib.grid(row = rowPos, column = posC(1,colPos), sticky = E)
elblAttribTo.grid(row = rowPos, column = posC(1,colPos), sticky = E)
etxtAttrib.grid(row = rowPos, column = posC(1,colPos), sticky = E)











frameUser = LabelFrame(\
    frameControls[2],
    padx=5,
    pady = 5,
    bg= colorScheme['3'],
    fg= colorScheme['1'],
    bd = 0,
    text = ""
    )


   

#frameControls[0].grid_columnconfigure(0, weight=1)
#frameControls[1].grid_columnconfigure(0, weight=1)
#frameControls[2].grid_columnconfigure(0, weight=1)
#frameControls[3].grid_columnconfigure(0, weight=1)



lblStatusAPI = Label(\
    frameStatus,
    bg = colorScheme['4'],
    fg = colorScheme['2'],
    text = "Zoom Web API Controls"
    #text="Not communicating with Zoom API"
    )

lblStatusAPI.grid(\
    row = pos(0,rowPos),
    column = posC(0,colPos),
    columnspan = 20
)


btnMenu = []
btnAction = []
menuButtonList = ['Settings', 'Account Level', 'User Level', 'Custom API', 'LDAP']

for btnItem in menuButtonList:
    menuIdx = menuButtonList.index(btnItem)
    
    btnMenu.append(stdButtonMenuStyle(\
        frameMenu,
        text = menuButtonList[menuIdx],
        command = lambda menuIdx_d = menuIdx: menuButtons(menuIdx_d)
        ))
    
    btnMenu[-1].grid(\
        row = pos(2,rowPos),
        rowspan = 2,
        column = posC(0,colPos),
        columnspan = 2,
        sticky = NSEW
    )
    

logData = StringVar(frameLog)
logData.set("Program Started")

listbox = Listbox(\
    frameLog,
    setgrid = 1,
    width = 90,
    name='log'
    )

listbox.bind('<<ListboxSelect>>',onListSelect )
listbox.grid(\
    row = pos(0,rowPos),
    column = posC(0,colPos),
    columnspan = colPosMax,
    sticky = NSEW
    ) 
scrollbar = Scrollbar(frameLog) 
scrollbar.grid(row = rowPos , column = colPosMax+4, rowspan=1,  sticky=N+S+W) 
listbox.config(yscrollcommand = scrollbar.set)  
scrollbar.config(command = listbox.yview)

btnCancel = stdButtonStyle(frameLog, text="Cancel Action", width=15, command= lambda: cancelActions(True), state=DISABLED)

btnCancel.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = W)

btnClearLog = stdButtonStyle(frameLog, text="Clear log", width=15, command=clearLog)
btnClearLog.grid(row = rowPos, column = posC(1,colPos), sticky = W)



btnLogConfig = stdButtonStyle(frameLog,text='Log Config', width = 10, command=logConfigWindow)
btnLogConfig.grid(row = rowPos, column = posC(1,colPos), sticky = W)

btnLogSearch= stdButtonStyle(frameLog,text='Find Next', width = 15, command=lambda: logSearchNext(listbox))
btnLogSearch.grid(row = rowPos, column = posC(1,colPos), sticky = W)

searchStr = StringVar()

txtLogSearch = stdEntryStyle(frameLog, textvariable = searchStr)
txtLogSearch.grid(row = rowPos, column = posC(1,colPos), sticky = NSEW)


txtLogSearch.bind("<Key>", keyPress)



btnOpenCreds = stdButtonStyle(\
    frameSubMenuCntrl[0],
    text = 'Open Credentials File',
    width = 20,
    image = iconFolder,
    command = openCredentials
    )


btnTestConnection = stdButtonStyle(\
    frameSubMenuCntrl[0],
    text = 'Account Info',
    image = None,
    width = 20,
    command = displayAccountInfo
    )

btnRoles = stdButtonStyle(\
    frameSubMenuCntrl[0],
    text = "List Zoom user roles",
    width = 25,
    command = get_acct_roles
)

stdButtonActionGrid(btnOpenCreds)
stdButtonActionGrid(btnTestConnection)

stdButtonActionGrid(btnRoles)
##@@@@@@@

#eLbl3 = Label(root, text="Number to Relicense (debug)")
#eLbl3.pack()
#eNumber = Entry(root)
#eNumber.pack()


eAPIKey.focus_set()





#btnDeleteInvalid = Button(root, text="Delete All Invalid Users", width=30, command=callback, state=DISABLED)
#btnDeleteInvalid.pack()
#btnSAMLReorg = Button(root, text="Relicense users based on SAML", width=30, command=callback, state=DISABLED)
#btnSAMLReorg.pack()
#btnOpen = Button(root, text="Save Log", width=30, command=logSave)
#btnOpen.pack()





frameUserFields = []

#User Email Frame
frameUserFields.append(stdLabelFrameStyle(frameControls[2]))
frameUserFields[-1].grid(column = posC(0,colPos), row = pos(0,rowPos), sticky = N+W)


userLogStart = StringVar()
userLogEnd = StringVar()

userTxtData = {
    "email":StringVar(),
    "first_name":StringVar(),
    "last_name":StringVar(),
    "pmi":IntVar(),
    "use_pmi":BooleanVar(),
    "timezone":StringVar(),
    "language":StringVar(),
    "dept":StringVar(),
    "host_key":StringVar(),
    "cms_user_id":StringVar(),
    "job_title":StringVar(),
    "company":StringVar(),
    "location":StringVar(),
    "custom": StringVar()
    #{
    #    "key":StringVar(),
    #    "name":StringVar(),
    #    "value":StringVar()
    #}
}


txtUserLogFrame = stdLabelFrameStyle(frameUserFields[-1], text="User Log options (defaults to today and yesterday if blank)")
txtUserLogFrame.grid(column = 0, row = pos(1,rowPos), sticky = N+W)

eLblUserLogStart = stdLabelStyle(txtUserLogFrame, text="Log Start (yyyy-mm-dd)")
eTxtUserLogStart = stdEntryStyle(txtUserLogFrame, width=20)


eLblUserLogEnd = stdLabelStyle(txtUserLogFrame, text="Log End (yyyy-mm-dd)")
eTxtUserLogEnd = stdEntryStyle(txtUserLogFrame, width=20)




eLblUserLogStart.grid(row = pos(1,rowPos), column = 0, sticky = E)
eTxtUserLogStart.grid(row = rowPos, column = 1, columnspan=2, sticky = W)
eLblUserLogEnd.grid(row = pos(1,rowPos), column = 0, sticky = E)
eTxtUserLogEnd.grid(row = rowPos, column = 1, columnspan=2, sticky = W)


txtUserFrame = stdLabelFrameStyle(frameUserFields[-1], text = "User Configuration - select <Update User> to accept changes")
txtUserFrame.grid(column = 0, row = pos(1,rowPos), sticky = N+W)


rowPos = 0

picLink = StringVar()

lblUserPicURL = stdLabelStyle(txtUserFrame, text="User Profile Picture")
lblUserPicLink = stdLabelLinkStyle(txtUserFrame, text = 'None', textvariable = picLink)
lblUserPicLink.bind("<Button-1>", lambda e: urlOpen(picLink.get()))

lblUserPicURL.grid(row = pos(1,rowPos), column = 0, sticky = E)
lblUserPicLink.grid(row = rowPos, column = 1, columnspan=2, sticky = W)


(menuUserGroups, menuUserGroupItems) = groupMenuInit(txtUserFrame)
menuUserGroups.grid(row = pos(1,rowPos), column = 1, sticky = W)
menuUserGroups.grid_remove()
    
userRoleValue = StringVar()
lblUserRole = stdLabelStyle(txtUserFrame, text = "User Role")
userRoleList = []
comboUserRoles = stdComboboxMenuStyle(txtUserFrame, textvariable=userRoleValue, values=userRoleList)


lblUserRole.grid(row = pos(1,rowPos), column = 0, sticky = E)
comboUserRoles.grid(row = rowPos, column = 1, columnspan=2, sticky = W)




userDataField = {}
userLabelField = {}
for userField in userTxtData:
    fieldName = userField.replace("_"," ")
    fieldName = fieldName.capitalize()
    
    if isinstance(userTxtData[userField],BooleanVar):
        userDataField[userField] = stdChkBxStyle(txtUserFrame,text= fieldName, variable = userTxtData[userField])
        userDataField[userField].grid(row = pos(1,rowPos), column = 1, columnspan=2, sticky = W)
    else:
        userLabelField[userField] = stdLabelStyle(txtUserFrame, text=fieldName)
        userLabelField[userField].grid(row = pos(1,rowPos), column = 0, sticky = E)
        userDataField[userField] = stdEntryStyle(txtUserFrame, textvariable = userTxtData[userField], width=20)
        userDataField[userField].grid(row = rowPos, column = 1, columnspan=2, sticky = W)
        
 
imageUserFrame = stdLabelFrameStyle(txtUserFrame, text = "Image")
#imageUserFrame.grid(column = 3, row = 3, rowspan = 10, sticky = N+W)       
lbluserImage = stdLabelStyle(txtUserFrame, text="Profile Picture")
#lbluserImage.grid(column = 3, row = 2, sticky = N+W)

tempRow = pos(1,rowPos)

btnInfo = stdButtonStyle(frameSubMenuCntrl[2], text="User Info", command=UpdateUser_Info)
btnUpdateEmail = stdButtonStyle(frameSubMenuCntrl[2], text="Update User", command=UpdateUser_Email)
btnRoleUpdate = stdButtonStyle(frameSubMenuCntrl[2], text = "Update Role", command = UpdateUser_Role)
btnLogOps = stdButtonStyle(frameSubMenuCntrl[2], text="Operations Log", command=getOpsLog)
btnLogSignin = stdButtonStyle(frameSubMenuCntrl[2], text="Sign In/Out Log", command=getSigningLog)
btnLogout = stdButtonStyle(frameSubMenuCntrl[2], text="Log Out User", command=logoutUser)
btnUpdateLicensed = stdButtonStyle(frameSubMenuCntrl[2], text="Set Licensed", command=UpdateUser_Licensed)
btnUpdateBasic = stdButtonStyle(frameSubMenuCntrl[2], text="Set Basic", command=UpdateUser_Basic)
btnUpdateWebinar = stdButtonStyle(frameSubMenuCntrl[2], text="Toggle Webinar", command=UpdateUser_Webinar)
btnUpdateLargeMtg = stdButtonStyle(frameSubMenuCntrl[2], text="Toggle Large Mtg", command=UpdateUser_LargeMtg)
btnDownload = stdButtonStyle(frameSubMenuCntrl[2], text="Participant Recordings DL", command=download_participant_recordings, state=DISABLED)
btnUpdateDelete = stdButtonStyle(frameSubMenuCntrl[2], text="Delete User", command=UpdateUser_Delete, state=DISABLED)
btnXferDelete = stdButtonStyle(frameSubMenuCntrl[2], text="Transfer & Delete", command=UpdateUser_Delete, state=DISABLED)
btnDeactivate = stdButtonStyle(frameSubMenuCntrl[2], text="Deactivate", command=UpdateUser_Delete, state=DISABLED)

userEmailAddr = StringVar()
userEmailList = []
eLblUserEmail = stdLabelStyle(frameSubMenuCntrl[2], text="User Email")
#eEmail = stdEntryStyle(frameSubMenuCntrl[2],width=30)
eComboUserEmail = stdComboboxMenuStyle(frameSubMenuCntrl[2], textvariable=userEmailAddr, values=userEmailList)
#eLblUserEmail.grid(row = pos(0,rowPos), column = 0, sticky=N+E)
#eEmail.grid(row = rowPos, column = 1, columnspan=2, sticky = N+W)


stdButtonActionGrid(eLblUserEmail)
stdButtonActionGrid(eComboUserEmail)
#stdButtonActionGrid(eEmail)
stdButtonActionGrid(btnInfo)
stdButtonActionGrid(btnUpdateEmail)
stdButtonActionGrid(btnRoleUpdate)
stdButtonActionGrid(btnLogOps)
stdButtonActionGrid(btnLogSignin)
stdButtonActionGrid(btnLogout)
stdButtonActionGrid(btnUpdateLicensed)
stdButtonActionGrid(btnUpdateBasic)
stdButtonActionGrid(btnUpdateWebinar)
stdButtonActionGrid(btnUpdateLargeMtg)
stdButtonActionGrid(btnDownload)
stdButtonActionGrid(btnUpdateDelete)
stdButtonActionGrid(btnXferDelete)
stdButtonActionGrid(btnDeactivate)



# Custom API Control Page Layout
frameAPI = LabelFrame(\
    frameControls[3],
    padx=5,
    pady = 5,
    bg= colorScheme['3'],
    fg= colorScheme['1'],
    bd = 0,
    text = "Custom API Commands"
    )

#frameAPIAction = stdFrameSubMenuStyle(
#    frameControls[3],
#)

#stdFrameSubMenuGrid(frameAPIAction)

frameAPI.grid(\
            row = pos(1,rowPos),
            column = posC(1,colPos),
            columnspan = 3,
            sticky = NSEW
        )



elblAPIURL = stdLabelLinkStyle(frameAPI, text="https://marketplace.zoom.us/docs/api-reference/zoom-api")
elblAPIURL.bind("<Button-1>", lambda e: urlOpen("https://marketplace.zoom.us/docs/api-reference/zoom-api"))
elblAPIURL.grid(row = pos(0,rowPos), column= 0, columnspan=6, sticky = NSEW)

(apiData, apiCommandsList, sbAPIList, apiCategory, apiMenu) = apiListMenu(frameSubMenuCntrl[3])




RADIOMODES = [\
        ("POST", "post"),
        ("GET", "get"),
        ("PUT", "put"),
        ("PATCH", "patch"),
        ("DELETE", "delete"),
    ]

RESTmethod = StringVar()
RESTmethod.set("get") # initialize

rowPos = 1
colPos = 0
for text, mode in RADIOMODES:
    apiRadioBtn = Radiobutton(frameAPI, text=text,
                    variable=RESTmethod, value=mode, bg = colorScheme['3'], fg = colorScheme['1'], selectcolor = colorScheme['3'])
    apiRadioBtn.grid(row = rowPos, column = colPos)
    colPos += 1

try:
    apiDict = openAPIList()
    apiCategoryList = []
    apiCmdCount = 0
    apiCommandList = []
    cat = ''
    for cat in apiDict:
        apiCategoryList.append(cat)
        apiCmdCount += len(apiDict[cat])

    for cmd in apiDict[cat]:
        apiCommandList.append(cmd)
    logging(f"Retrieved {len(apiCategoryList)} API categories and {apiCmdCount} commands")
    
except:
    apiCategoryList = None
    apiCommandList = None

    
if apiCategoryList != None:
    apiCategories = StringVar(root)
    apiCategories.set(cat) # set the default option


    
    apiCommand = StringVar(root)
    apiCommand.set(apiCommandList[0]) # set the default option

    eLblAPICat = stdLabelStyle(frameAPI, text="API Category")
    emenuAPICat = stdComboboxStyle(frameAPI, textvariable=apiCategories, values=apiCategoryList)
    resizeFuncAPICat()
    
    eLblAPICmd = stdLabelStyle(frameAPI, text="API Command")
    emenuAPICmd = stdComboboxStyle(frameAPI, textvariable=apiCommand,postcommand=resizeFuncAPICmd, values=apiCommandList)
    #etxtAPI.delete(0, END)
    #etxtAPI.insert(0, "/report/operationlogs")

    emenuAPICat.bind("<<ComboboxSelected>>", menuAPICategory)
    emenuAPICmd.bind("<<ComboboxSelected>>", menuAPICommand)
    
    
    eLblAPICat.grid(row = pos(1,rowPos), column= 0, columnspan=2, sticky = E)
    emenuAPICat.grid(row = rowPos, column = 2, columnspan=4, sticky = W)    
    eLblAPICmd.grid(row = pos(1,rowPos), column= 0, columnspan=2, sticky = E)
    emenuAPICmd.grid(row = rowPos, column = 2, columnspan=4, sticky = W)   

eLblApiId = stdLabelStyle(frameAPI, text="IDs")
eTxtApiId = stdEntryStyle(frameAPI)
eTxtApiId.delete(0, END)

elblAPIParam = stdLabelStyle(frameAPI, text="Parameters (JSON)")
etxtAPIParam = stdEntryStyle(frameAPI)
etxtAPIParam.delete(0, END)
#etxtAPIParam.insert(0, '{"page_size":300}')

elblAPIBody = stdLabelStyle(frameAPI, text="Body (JSON)")
etxtAPIBody = stdEntryStyle(frameAPI)


elblAPI = stdLabelStyle(frameAPI, text="Commmand (URL End)")
etxtAPI = stdEntryStyle(frameAPI)
    
elblAPI.grid(row = pos(1,rowPos), column= 0, columnspan=2, sticky = E)
etxtAPI.grid(row = rowPos, column = 2, columnspan=4, sticky = W)

eLblApiId.grid(row = pos(1,rowPos), column= 0, columnspan=2, sticky = E)
eTxtApiId.grid(row = rowPos, column = 2, columnspan=4, sticky = W)

elblAPIParam.grid(row = pos(1,rowPos), column= 0, columnspan=2, sticky = E)
etxtAPIParam.grid(row = rowPos, column = 2, columnspan=4, sticky = W)

elblAPIBody.grid(row = pos(1,rowPos), column= 0, columnspan=2, sticky = E)
etxtAPIBody.grid(row = rowPos, column = 2, columnspan=4, sticky = W)

btnAPIUpdate = stdButtonStyle(frameAPI, text="SEND", width=10, command=customAPI)
btnAPIUpdate.grid(row = 3, rowspan=4, column = 5, sticky = E)


frameApiPresets = stdFrameControlStyle(frameAPI, pady = 10)
frameApiPresets.grid(row = pos(1,rowPos), columnspan = 6, column= 0, sticky = W)

elblAPIPresetName = stdLabelStyle(frameApiPresets, text="Preset Name")
etxtAPIPresetName = stdEntryStyle(frameApiPresets)
    
elblAPIPresetName.grid(row = pos(0,rowPos), column= 0, columnspan = 2, sticky = W)
etxtAPIPresetName.grid(row = rowPos, column = 0, columnspan = 2, sticky = E)

btnApiPresetAdd = stdButtonStyle(frameApiPresets, text="Add Step to Preset", command=preset_step)
btnApiPresetAdd.grid(row = pos(1,rowPos), column = 0, sticky = E)
btnApiPresetSave = stdButtonStyle(frameApiPresets, text="Clear Preset Data", command=customAPI)
btnApiPresetSave.grid(row = pos(1,rowPos), column = 0, sticky = E)




btnLDAPList = stdButtonStyle(\
    frameSubMenuCntrl[4],
    text = 'List Attributes',
    width = 20,
    image = None,
    command = openCredentials
    )
stdButtonActionGrid(btnLDAPList)


#screenHeight = root.winfo_screenheight() 
#screenWidth = root.winfo_screenwidth() 
#windowHeight = root.winfo_height()
#windowWidth = root.winfo_width()

#if screenHeight > windowHeight:
#    scrollbarApp = Scrollbar(paneApp) 
#    scrollbarApp.grid(row = 0 , column = 7, rowspan=5,  sticky=N+S+W) 
#    paneApp.config(yscrollcommand = scrollbarApp.set)  
#    scrollbar.config(command = paneApp.yview)

statusLicense = StringVar(value = "License:  No Data")
statusCloud = StringVar(value = "Cloud Storage:  No Data")
statusZoom = StringVar(value = "No Communication")

lblStatus = {
    'connection':stdLabelStatusStyle(frameStatus, width = 15, textvariable = statusZoom, text="No Communication"),
    'license':stdLabelStatusStyle(frameStatus, width = 30, textvariable = statusLicense, text="Licenses:  No Data"),
    'cloud':stdLabelStatusStyle(frameStatus, textvariable = statusCloud, text="Cloud Storage:  No Data") 
    }

colPos = -1

for lbl in lblStatus:
    lblStatus[lbl].grid(row = 0, column = posC(1,colPos), sticky = W)

progress_var = DoubleVar() #here you have ints but when calc. %'s usually floats
progress = stdProgressBarStyle(frameStatus, length = 100, variable = progress_var)
progress.grid(row = 0, column = posC(1,colPos), sticky = W)


maxAppHeight = 694

btnTxtUpdates()

menuButtons(0)




images = []


#if __name__ == '__main__':
#    t = threading.Timer(10.0, guiUpdate)
#    t.start()

#Testing
#get_InactiveDate()
#print(f"Local Time Coversion Check: {timeLocal('2020-06-08T21:59:43Z')}")

 

mainloop()




