'''
To Do to finish app and make a true Zoom Enterprise support app:

Code Cleanup
-Method comments
-Add classes


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
import datetime
import pytz
import tzlocal
from PIL import Image, ImageTk
import csv
import pytz
import json
import jwt
import linecache
#import os
import requests
import time
import webbrowser
from dateutil.relativedelta import relativedelta
from dateutil import tz
from tkinter import *
from tkinter import ttk
from tkinter import filedialog


## GLOBAL CONSTANTS ##
FROM_ZONE = tz.tzutc()
TO_ZONE = tz.tzlocal()

API_SCIM2_USER = 'https://api.zoom.us/scim2/Users'
USER_DB_FILE = "ZoomRetrievedUserList.csv"
EMAIL_FILE = 'email-list.csv'
API_FILE = 'ZoomAPI.json'
SETTINGS_FILE = "Zoom Group Setting Tracking.csv"
## GLOBAL VARIABLES ##
maxMonths = 0
maxNum = 0
indexList = []
cancelAction = False
fileLog = ""
localTimeZone = tzlocal.get_localzone().zone
dateInactiveThreshold = datetime.datetime.now()

colors =\
       {
           'blue':'#51608C',
           'gray':'#8697A6',
           'blue-gray':'#BFCDD9',
           'light-brown':'#BF8756',
           'brown':'#8C4F2B'
        }


colorScheme =\
       {
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


dateStr=\
    {
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
apiURL =\
    {
        'users': 'v2/users',
        'user':'v2/users/@',
        'groups': 'v2/groups',
        'scim2': 'scim2/Users/@',
        'plan': 'v2/accounts/@/plans/usage',
        'account':'v2/accounts/@',
        'roles':'v2/roles',
        'rolesList':'v2/roles/@/members',
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
        'groupSettings':'v2/groups/@/settings'       
    }

userDB = []
userRawDB = {}
groupDB = {}
userInactiveDB = []
logConfig = {}


####################################

def logging(text ,save=True):
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

    
    try:
        if listbox.size() == 0:
            fileLog = f"ZoomAppLog-{datetime.datetime.strftime(today, dateStr['file'])}.txt"    
    except:
        fileLog = f"ZoomAppLog.txt"
            
    if len(text) > 0:
        todayStr = ""
        if logConfig['timestamp'].get() == 1:
            todayStr = f'[{datetime.datetime.strftime(today, dateStr["log"])[:-3]}] ' 
        text = f'{todayStr}{text}'
     
        if len(text) >= lineLenMax and logConfig['wrap'].get() == 1:
            if text is not list():
                if '{' in text:
                    try:
                        text = text.split("Response:")
                        text = text[1]
                    except Exception as e:
                        print(f'!!!!!!Error in Logging: {e}, \nMessage:{text}')
                    try:
                        text = text.replace('{', '')
                        text = text.replace('}','')
                        text = text.replace('[','')
                        text = text.replace(']','')
                        text = text.replace("'",'')
                        text = text.replace("_",' ')
                        
                        texthalf = text.split(",")
                        for i in range(len(texthalf) -1, -1, -1):
                            listbox.insert(0,texthalf[i])
                    except Exception as e:
                        print(f'!!!!!!Error in Logging: {e}, \nMessage:{text}')
                else:                
                    #text.replace('{', '{\n')  
                    #if '}' in text:
                    #    text.replace('}', '}\n')
                    
                    textChunk = [text[i:i+lineLenMax] for i in range(0, len(text), lineLenMax)]
                    #print(f' Dated Text {len(textChunk)}:{textChunk}')
                    for i in range(len(textChunk) - 1, -1, -1):
                        #logData.set(textChunk[i])
                        listbox.insert(0, textChunk[i])
        else:
            #logData.set(text)
            listbox.insert(0, text)
        
        print(f"Log:  {text}")
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
    msg = f"++Error: {errMsg}: {error},  Exception in ({filename}, LINE {lineno}, {line.strip()}: {exc_obj}"
    if logConfig['debug'].get() == 1:
        logging(msg)
    else:
        print(msg)

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
            print(f'saving file {fileLog} with: {text}')
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
        PrintException(e)
    
    return localTZ

def ldapAttributes():
    from ldap3 import Server, Connection

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
 
 
def JWT_Token2(key,secret, leaseTime = 2): 
    authHeader = ""
    
    try:
        today = datetime.datetime.now()
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
        
        jwtToken = encoded_jwt.decode("utf-8")
        
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
    csvData = []
    
    try:
        root.filename = filedialog.askopenfilename(initialdir = "./",title = "Select file",filetypes = ((f"{fileDesc}",f"*.{fileType}"),("all files","*.*")))
        fileName = root.filename
    except Exception as e:
        logging (f"Error opening file: {e}")
        fileName = fileDefault

    cancelActions(False)
    try:
        with open(fileName) as file:
            logging (f"Open File: {root.filename}")
            readFile = csv.reader(file, delimiter=',')
            
            for row in readFile:
                if cancelAction is True:
                    cancelAction = False
                    break
                csvData.append(row)
            
            
            logging(f'Number of Entries opened {fileName}: {len(csvData)}')
            
    except Exception as e:
        logging(f'Error in reading file: {e}')

    cancelActions('reset')
    return csvData


def actionBtnsState(state):
    if state == 'enabled':
        btnDeleteInactive["state"] = "normal"
        btnOpenDelete["state"] = "normal"
        btnSettingsStats["state"] = "normal"
    else:
        btnDeleteInactive["state"] = "disabled"
        btnOpenDelete["state"] = "disabled"
        btnSettingsStats["state"] = "disabled"        



def csvOpen():
    global userDB
    global userInactiveDB
    global cancelAction
    listboxTop()
    
    try:
        root.filename = filedialog.askopenfilename(initialdir = "./",title = "Select file",filetypes = (("csv files","*.csv"),("all files","*.*")))
        logging (f"Open File: {root.filename}")
        fileName = root.filename
    except:
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
    cpUser = []
    rowCount = 0
    progress_var.set(0)
    listboxTop()
    
    cancelActions(False)
    
    try:
        root.filename = filedialog.askopenfilename(initialdir = "/",title = "Select file",filetypes = (("csv files","*.csv"),("all files","*.*")))
        logging (f"Open File: {root.filename}")
        fileName = root.filename
    except:
        PrintException(e)
        fileName = EMAIL_FILE
        
    try:
        with open(EMAIL_FILE) as csvfile:
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
    
    with open('ZoomAPI-Detailed.json') as jsonFile:
        data = json.load(jsonFile)
    return data


def send_REST_request(apiType, data="", body= None, param = None, rType = "get", note=""):
    '''
        Description:  Sends request to Zoom to pull more detailed info
                      not available in webhook event payload 
         Parameters: apiType - string - references type of API request
                     if select the correct URL from the apiURL dict
                     data - string - represents string that is appended
                     to URL to pull specified data, i.e. user ID
          
    '''
    global tokenError
    response = ""
    respData = ""
    
    tokenError = True
    
    if note != "":
        logging(f'{note}')
    
    
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
     
     
    authHeader = JWT_Token2(API_KEY,API_SECRET,1.5)   

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
            if '@' in url and data != "":
                url = url.replace("@", data)
        except Exception as e:
            logging(f'Error in url replace: {e}')

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
            elif rType == "patch":
                response = requests.patch(url=api, json=body, headers=authHeader)
                logging(f'Response: {response}')
                #print(f'Details:{respData["detail"]}')
            elif rType == "delete":
                logging(f"Sending delete REST request!!")
                response = requests.delete(url=api, headers=authHeader)
                status = response.status_code
                if response.status_code == 204:
                    msgRsp = "Succesfully deleted"
                else:
                    msgRsp = "Did not delete"
                logging(f'{msgRsp} {note}: {response}')
        except Exception as e:
            logging(f'Send HTTP {rType} REST Request {api}, Response: {response}, Error:{e}')     
        try:
            status = response.status_code
            statusZoom.set(f"Zoom Resp: {status}")
            try:
                respData = response.json()
                print(f'Received HTTP REST Request {respData}')
            except Exception as e:
                print(f'No JSON data in response from request: {e}')
        
            
            if status == 404:
                try:
                    return respData['detail']
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

def get_subaccount_data():
    try:
        subAccount = send_REST_request('subaccount', data='')
    except Exception as e:
        logging("Error getting sub account data: {}".format(e))
        subAccount = None
    
    try:
        seats = 0
        for data in subAccount['accounts']:
            if 'seats' in data:
                seats += data['seats']
    except:
        seats = 0
        
    logging(f"There are {seats} licenses assigned to subaccounts") 
    return (subAccount,seats)

def logoutUser():
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
    userDBdef = ["Flags","Email","User ID","First Name", "Last Name", "Last Login", "Client Ver", "Group", "License","Months"]
    
    userEmail = userEmailAddr.get()

    try:
        for user in userDB:
            if user[emailIdx] == userEmail:
                return user[userIdIdx]
    except:
        None
        
    return None

def delete_user(userID, userEmail=""):
    logging (f'Attempting to delete {userEmail}')
    
    deleteStatus = send_REST_request('user', data = userID, param = {"action":"delete"}, rType = "delete", note=userEmail)
    
    if '204' in deleteStatus:
        update_userDB("Email",userID, None)


def update_userDB(userID, category, value):
    global userDB
      
    userDBdef = ["Flags","Email","User ID","First Name", "Last Name", "Last Login", "Client Ver", "Group", "License","Months"]
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
    


def get_UserInfo(user):
    
    licNo = 1
    emailIdx = 1
    userIdIdx = 2
    licenseIdx =  8
    groupIdx = 7
    
    print("User Data:  {user}")
    
    userId = user[userIdIdx]
    userDBdef = ["Flags","Email","User ID","First Name", "Last Name", "Last Login", "Client Ver", "Group", "License","Months Inactive"]
    
    userEmail = user[emailIdx]
    
    userInfo = send_REST_request('user', data=userId, rType = "get", note="Getting user info")
                
    for item in userInfo:
        try:
            if item in userTxtData:
                
                print (f'###Item: {item}, obj:{userTxtData[item]}, Contents: {userInfo[item]}')    
                #userDataField[item].set(userInfo[item])
                if userTxtData[item] is type(StringVar):
                    userTxtData[item].set(str(userInfo[item]))
                    userDataField[item].delete(0,"end")
                    userDataField[item].insert(0, userInfo[item])
                else:
                    userTxtData[item].set(userInfo[item])
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
        if user[groupIdx] == 'No Group':
            group = "AcctSetting"
        else:
            groups = user[groupIdx].split(":  ")
            group = groups[1]
        
        if userSettings is not {}:
            diffCount = 0
            for category in userSettings:
                try:
                    groupVal = groupDB[group][category]
                    userVal = userSettings[category]
                    
                    diffSettings = {k: userVal[k] for k in groupVal if k in userVal and groupVal[k] != userVal[k]}
                    diffLen = len(diffSettings.keys())         
                    logging(diffSettings)
                except:
                    None
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
    
def UpdateUser_Info():
    global groupDB
    global userDB
    licType = 'Basic'
    licNo = 1
    emailIdx = 1
    userIdIdx = 2
    licenseIdx =  8
    groupIdx = 7
    userDBdef = ["Flags","Email","User ID","First Name", "Last Name", "Last Login", "Client Ver", "Group", "License","Months Inactive"]
    
    userEmail = userEmailAddr.get()
    
    
    
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
                userGroup = user[7]
                userLicense = user[8]
                months = user[9]
                
                if chkActivity.get() == 1:
                    try:
                        monthsActive = int(eActiveUser.get())
                    except:
                        monthsActive = 0
                   
                    if months <= monthsActive:
                        chkParam[0] = True
                            
                if chkRec.get() == 1:
                    try:
                        recMonths = int(eRecMonths.get())
                    except:
                        recMonths = 0
                    
                    if months < recMonths:
                        recordings = check_user_recording_count(user[userIdIdx])
                    
                    if recordings > 0:
                        chkParam[1] = True
                   
                    logging('{}: {} has {} recordings and last logged in {} months ago'.format(userGroup,email,recordings,months))
                    
                if chkMeetings.get() == 1:
                    (meetingsAllCnt, meetingCnt, meetingScheduled) = get_user_meetings(user[userIdIdx])
                    if meetingScheduled > 0:
                        chkParam[2] = True
                
                if chkBasic.get() == 1:
                    chkParam[3] = True
            
                 
                group = filterGroup.get()
                
                if group == 'All Users':
                    group == None
                elif group == 'Users in no Groups':
                    group = 'No Group'
                    
                if group != None:
                    if user[groupIdx] == group or group == None:
                        chkParam[4] = False
                    else:
                        chkParam[4] = True
                 
                 
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
                            if logConfig['test'].get() == 0:
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
            
            userGroup = extract_group(user[groupIdx])
            
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
        
                            
            try:
                if True not in chkParam:
                    # No checkboxes, and group matches, just delete
                    if logConfig['test'].get() == 0:
                        delete_user(user[userIdIdx],userEmail)
                    else:
                        logging(f"TESTING: {user[groupIdx]},{email} is being deleted.")
                    return 1
                elif chkParam[3] is True:
                    # If No Deletes is enabled then send user to basic
                    # no other parameters are true
                    chkParam[3] = False
                    if True not in chkParam:
                        if logConfig['test'].get() == 0:
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

def validate_user_modification(userID):
    None
    
    
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
            None
        
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
    None




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
                            None
                except:
                    PrintException(e)
                    #None
        except:
            PrintException(e)
            #None

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
    data = send_REST_request('roles', data = '', rType = "get")
    try:
        for item in data['roles']:
            logging(f'{item["name"]} role has {item["total_members"]} members')
            logging(f'{item["description"]}')
    except Exception as e:
        logging('Could not retrieve data')
    
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
                                            None
                                except Exception as e:
                                    PrintException(e)
                                    #None
                        except Exception as e:
                            PrintException(e)
                            #None

                
    except Exception as e:
        logging (f'Error with creating file: {e}')
    
    cancelActions('reset')

def save_acct_settings(settingsDB):
    
    try:
        with open(SETTINGS_FILE, 'w', newline='') as csvFile:
            writer = csv.DictWriter(csvFile, fieldnames = ["Group", "Category", "Setting","Value"])
            writer.writeheader()                
        
            for group in settingsDB:
                groupSettings = settingsDB[group]
    
                tally = {}
                csvRow = {\
                    "Group": group,
                    "Category":"",
                    "Setting":"",
                    "Value":""
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
                                            "Value":value
                                            }
                                        writer.writerow(csvRow)
                                    except Exception as e:
                                        PrintException(e)
                                        None
                            except Exception as e:
                                PrintException(e)
                                #None
                    except Exception as e:
                        PrintException(e)
                        #None               
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
        
    save_acct_settings(groupDB)   


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

def get_acct_settings():
    acctSettings = {}
    
    try:
        acctID = "me"
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
                
def get_user_data(groupsDict):
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
       
    pageSize = 1
    JSONData = {\
        'status':"",
        'page_size':pageSize,
        'role_id':"",
        'page_number':'0'
        }
    
            

    try:
        page_data = send_REST_request('users', param = JSONData, rType = "get")
    except Exception as e:
        page_data = None
        print('Exception:{}'.format(e))    
  
  
  
  
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
                    
                    
                    
                    JSONData = {\
                        'status':"",
                        'page_size':pageSize,
                        'role_id':"",
                        'page_number':str(page)
                    }
                    
                    #logging("Pulling: {}".format(JSONData))
                    
                    try:         
                        user_data = send_REST_request('users', param = JSONData, rType = "get")
                    
                        #user_data = requests.get(url=url, headers=authHeader).json()
                        #userInactive = [userID,userLoginMonths, userFirstName, userLastName]
                        
                    except Exception as e:
                        logging('User Data pull error: {}'.format(e))
                        
                    
                    try:
                        for user in user_data['users']:
                            record_count += 1
                            progress_var.set(int((record_count/recordsTotal)*100))
                            
                            
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
                                for group in user['group_ids']:
                                    groupCnt += 1
                                   
                                    try:
                                        if group in groupsDict:
                                            groupName = groupsDict[group]
                                        else:
                                            groupName = 'No Group'
                                            flagUser = ['No','GroupID']
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
                                    
                            writer.writerow({'flag': flagUser[0],'user_id':userID, 'email': userEmail, 'first_name':userFirstName, 'last_name':userLastName, 'last_login':userLastLogin,'months_since':userLoginMonths,'app_ver':userLastClientVer,'group':userGroup,'license':userLicense})
                            #print ('Last Recorded Zoom version for {}: {}'.format(userEmail,userLastClientVer))
                            flagUser = ['None','None']
                        
                                # userDeleteList.append(userInactive)
                                #
                                
                            try:
                                user_ids = [flagUser[0],userEmail, userID, userFirstName, userLastName,userLastLogin,userLastClientVer,userGroup,userLicense, userLoginMonths]
                                userDB.append(user_ids)
                                actionBtnsState('enabled')
                            except:
                                user_ids = []
                                
                            
                        

                    except:
                        None
                        
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
                    
                    #progress.step(int((page/total_pages)*100))
                    
                    root.update()
                    root.update_idletasks()
                    
                    #print("Time Remaining: {:.2f}s, {}/{} : {}".format(runAvg,page,total_pages,user_ids))
                # print the contents using zip format.

                
                
                
                for userLicense in licenseCnt['total']:
                    logging(f'Total {userLicense} Users Counted: {licenseCnt["total"][userLicense]}')
                
                logging('Total Flagged Users: {}'.format(flagUserCount))
                
                logging('User Data Pulled:  {}'.format(len(userDB)))
                logging('Users Inactive: {}'.format(len(userInactiveDB)))
                 
                 
                 
                #writeRawUserData(userRawDB) 
                logging('Updating User drop down list...')
                for userEmail in userRawDB:
                    menuUserEmailValuesAdd(userEmail)
                logging('....Finished updating user drop down list')
        
        except Exception as e:
            logging ('File Write Error, please close file it may be open in Excel\n{}'.format(e))
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

def getAccountInfo(desc):
    planInfo = \
        send_REST_request(\
            apiType ='plan',
            data = "me",
            rType = "get",
            note=desc,
        )
    
    #(subAccount, seats) = get_subaccount_data()
    
    

    
    try:
        planLicenses = planInfo["plan_base"]["hosts"]
        planUsers = planInfo["plan_base"]["usage"]
        remainingNow = planLicenses - planUsers
        remainingPct = round(((remainingNow / planLicenses) * 100),2)
        
        licenseInfo =  f"Licenses: {remainingPct}%, ({remainingNow:,}/{planLicenses:,})"
        cloudStorage = planInfo["plan_recording"]["free_storage"]
        cloudUsage = planInfo["plan_recording"]["free_storage_usage"]
        cloudInfo = f"Storage: {cloudUsage} / {cloudStorage}"
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
    
    for cmd in apiDict[category]:
        apiCommandList.append(cmd)
        
    emenuAPICmd['values'] = apiCommandList
    apiCommand.set(apiCommandList[0])
    emenuAPICmd.configure(width=20)
    
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

def testdata():
    #Used to validate if recordings is returning appropriate data
    userID = ""
    get_user_scim2_data(userID)
    rec = check_user_recording_count(userID)
    input("Press Enter to continue...")
    print ("Cloud Recording Count Test: {}".format(rec))
    
def getOpsLog():
    listboxTop()
    userDailyOpLog(userEmailAddr.get())
def getSigningLog():
    listboxTop()
    userDailySignInLog(userEmailAddr.get())

def userDailyOpLog(userEmail):
    today = datetime.datetime.now()
    todayStr = f'{datetime.datetime.strftime(today, dateStr["calendar"])}'
    
    params = {\
        'to':'',
        'from':'',
        'page_size':300,
        'next_page_token':''
        }
    
    logging(f'Checking Daily Operation log for: {userEmail}')
    try:
        opsLogs = send_REST_request('logs', param=params, rType = "get", note = "")
        if 'next_page_token' in opsLogs:
            params['next_page_token'] = opsLogs['next_page_token']
            ##@@ToDo Loop through X pages of ops log, repeat for sign in / out activity log
            
        for userLog in opsLogs["operation_logs"]:
            for item in userLog:
                if userEmail in userLog[item]:
                    for item in userLog:
                        text = item.replace("_", " ")
                        if text == 'time':
                            userLog[item] = timeLocal(userLog[item], "string")
                        logging(f"{text}: {userLog[item]}")
        logging(f'Done checking Daily Operation log for: {userEmail}')
    except:
        PrintException(e)
    
def userDailySignInLog(userEmail):

    today = datetime.datetime.now()
    todayStr = f'{datetime.datetime.strftime(today, dateStr["calendar"])}'
    
    params = {\
        'to':'',
        'from':'',
        'page_size':300,
        'next_page_token':''
        }
    logging(f'Checking Daily Sign In/Out log for: {userEmail}')
    try:
        signinLogs = send_REST_request('signin', param=params, rType = "get", note = "")

        
        for userLog in signinLogs["activity_logs"]:
            for item in userLog:
                if userEmail in userLog[item]:
                    for item in userLog:
                        text = item.replace("_", " ")
                        if text == 'time':
                            userLog[item] = timeLocal(userLog[item], "string")
                        logging(f"{text}: {userLog[item]}")

        logging(f'Done checking Daily SignIn/Out log for: {userEmail}')
    except:
        PrintException(e)

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


def callback():
    global listbox
    global userDB
    global cancelAction
    global groupFilterList
    
    startTime = time.time()
    cancelActions(False)
    userDB.clear()
    listboxTop()
    #listbox.delete(0,END)
    zoom_token_auth()
    displayAccountInfo()
    groupsData = get_group_data()
     
    ## Update ComboBox
    groupFilterList.clear()
    groupFilterList = ['All Users','No Group']
    for group in groupsData:
        groupFilterList.append(groupsData[group])
        
    emenuGroupFilter['values'] = groupFilterList
     
    get_groups_settings(groupsData)
            
    #testdata
    data = get_user_data(groupsData)
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
 
    global dateCheck
    
    try:
        maxMonths = int(eMonths.get())
    except:
        maxMonths = 10
    
    try:
        maxNum = int(eNumber.get())
    except:
        maxNum = 0
    
    get_InactiveDate()
        
   
    
    logging("Inactive Date:  {}".format(dateInactiveThreshold))
    
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
    
    logging(f'Response:{response}')
    
def urlOpen(url):
    """Opens URL in new browser window
       
    Args:  url (str) - url to navigate to
    
    Returns:  None
    """  
    webbrowser.open_new(url) 
    
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
        None

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
        None

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


def menuButtons(idx):
    global maxAppHeight
    menuButtonFeedback(idx)
    
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
  

  
    frameSubMenuCntrl[idx].grid()
    frameControls[idx].grid()        
    #frameControls[idx].configure(height=frameControls[0]["height"],width=frameControls[0]["width"])
    #frameControls[idx].grid_propagate(0)
    
    if idx is 0:
       None
       #frameControls[idx]['text'] = 'S E T T I N G S'
        #Original grid settings are at bottom of code
    elif idx is 1:
        None
        #frameControls[idx]['text'] = 'ACCOUNT-LEVEL MANAGEMENT'
    elif idx is 2:
        #frameControls[idx]['text'] = 'USER-LEVEL MANAGEMENT'
        frameUser.grid(\
            row = pos(0,rowPos),
            column = posC(0,colPos),
            columnspan = 3,
            sticky = NSEW
        )
    elif idx is 3:
        None
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
    actionMenuHeight = frameSubMenuCntrl[idx].winfo_height()
    
    #framesHeight =  - (logHeight + statusHeight)
    
    # Distance between action frame and log frame
    gapHeight = abs(appFrameHeight - actionMenuHeight)
    sizeDiff = (maxAppHeight - (totalHeight + gapHeight))
    
    
    
    if totalHeight < maxAppHeight:
        diff = maxAppHeight - totalHeight
    else:
        diff = 0
        
           
    #print (f'total: ({totalHeight}x{totalWidth}), update: {updateHeight}, size Diff {sizeDiff}, frame Height: {appFrameHeight}, action menu: {actionMenuHeight}, Gap: {gapHeight}')
    if diff > 4:
        #(col,row) = frameControls[0].grid_size
        #print(f'G0: {col}, {row}')
      
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
    
        
    frameSettings[frIdx].grid(row = 0, rowspan = rows, column = frColumns+1, sticky = W)   
    
    
    
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

def stdLabelLinkStyle(origin, text, theme = ""):
    
    objLabel = Label(\
        origin,
        text = text,
        bg = colorScheme['3'],
        fg = "blue",
        cursor = "hand2",
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
        None
        
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
        textvariable = None,
        state = 'normal',
        relief = 'groove',
        width = width,
        justify = 'left'
    )
    
    return entryObj

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
        
    
def onListAPISelect(event):
    objWidget = event.widget
    try:
        idx = int(objWidget.curselection()[0])
    except:
        idx = 0
    objWidget.update()
    value = objWidget.get(idx)
    print('You selected item {}: {} in {}'.format(idx, value, apiMenu))
    
    if value == "<- Back to API Categories":
        apiListCategory()   
    elif apiMenu == 'category':
        apiListCommands(value)
    else:
        apiCommandPopulate(value)
   
        

def apiCommandPopulate(command):
    #
    #
    category = apiCategory
    menuAPICmdValues(category)
    etxtAPI.delete(0,END)
    etxtAPIParam.delete(0,END)
    etxtAPIBody.delete(0,END)
    emenuAPICmd.delete(0,END)
    
    RESTmethod.set(apiData[category][command]['method']) # initialize
    if "query_param" in apiData[category][command]:
        text = json.dumps(apiData[category][command]["query_param"])
        etxtAPIParam.insert(0,text)

    if "body" in apiData[category][command]:
        text = json.dumps(apiData[category][command]["body"])
        etxtAPIBody.insert(0,text)
        
    if "url" in apiData[category][command]:
        text = json.dumps(apiData[category][command]["url"])
        etxtAPI.insert(0,text)
        emenuAPICmd.insert(0, text)
        apiCommand.set(text)
        #emenuAPICmd.current(emenuAPICmd['values'].index(text))
        if "{" not in text:
            eLblApiId.grid_remove()
            eTxtApiId.grid_remove()
        else:
            eLblApiId.grid()
            eTxtApiId.grid()
    
        
def apiListCategory():
    global apiMenu
    
    apiMenu = "category"
    apiCommandsList.delete(0,END)
    for category in apiData:
        apiCommandsList.insert(0, category)
        
    if len(apiData) > 15:
        sbAPI.grid()
    else:
        try:
            sbAPI.destroy()
        except:
            None
    
    
def apiListCommands(category):
    global apiMenu
    
    apiMenu = "commands"
    emenuAPICat.set(category)
    apiCommandsList.delete(0,END) 
    for command in apiData[category]:
        apiCommandsList.insert(0, command)
    apiCommandsList.insert(0, "<- Back to API Categories")
    
    if len(apiData[category]) > 15:
        sbAPI.grid()
    else:
        try:
            sbAPI.destroy()
        except:
            None
        
        

def apiList(origin):
    apiListVAR = StringVar(origin)

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
        name='apiListVAR'
        )

    lbAPI.bind('<<ListboxSelect>>',onListAPISelect )
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
        row = 0,
        column = colPos+1,
        rowspan=40,
        sticky = N+S+W
    )
    
    
    lbAPI.config(yscrollcommand = scrollbar.set)  
    sbAPI.config(command = lbAPI.yview)
    
    apiData = openAPIListDetailed()
    
    for category in apiData:
        lbAPI.insert(0, category)
    
    if len(apiData) > 15:
        sbAPI.grid()
    else:
        sbAPI.destroy()
        
    apiMenuType = 'category'
    return (apiData,lbAPI,category,apiMenuType)

    
rowPos = 0
colPos = 0
colPosMax = 12

# Build Primary Window
root = Tk()
root.option_add('*font', ('verdana', 8, 'bold'))
root.configure(bg=colorScheme["3"])
root.title('Zeus Tool:  Zoom Enterprise User Support Tool v0.8.12')
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

for i in range(0,4):
    frameSubMenuCntrl.append(
            stdFrameSubMenuStyle(frameApp)
        )
    frameSubMenuCntrl[i].propagate(0) 
    frameSubMenuCntrl[i].grid_remove()
    

frameControls = []

for i in range(0,4):
    frameControls.append(\
        LabelFrame(\
            frameApp,
            bg= colorScheme['3'],
            fg= colorScheme['1'],
            highlightcolor = colorScheme['3'],
            relief='flat',
            labelanchor = N+W,
            width=200,
            height=200,            
            font= ('verdana', 10, 'bold'),
            text = ""
        )
    )
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
        columnspan = colPosMax + 2,
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
eAPIKey = stdEntryStyle(frameSettings[-1])
eLblAPIKey = stdLabelStyle(frameSettings[-1], text="API Key*")
eLblAPISecret = stdLabelStyle(frameSettings[-1], text="API Secret*")
eAPISecret = stdEntryStyle(frameSettings[-1], show='*')
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


eLblAPI.grid(row = pos(0,rowPos), column = posC(0,colPos), sticky = NSEW)
eLblAPIKey.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = E)
eAPIKey.grid(row = rowPos, column = posC(1,colPos), sticky = W)

eLblAPISecret.grid(row = pos(1,rowPos), column = posC(0,colPos), sticky = E)
eAPISecret.grid(row = rowPos, column = posC(1,colPos), sticky = W)

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




logConfig = {}
logConfig['timestamp'] = IntVar(value = 1)
logConfig['wrap'] = IntVar(value = 1)
logConfig['inactive'] = IntVar(value = 1)
logConfig['noGroup'] = IntVar(value = 1)
logConfig['save'] = IntVar(value = 1)
logConfig['debug'] = IntVar()
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

btnRetrieve = stdButtonStyle(frameSubMenuCntrl[1], text = "Retrieve All User Data", width = 25, command = callback)
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


stdButtonActionGrid(btnRetrieve)
stdButtonActionGrid(btnOpen)
stdButtonActionGrid(btnOpenDelete)
stdButtonActionGrid(btnDeleteInactive)
stdButtonActionGrid(btnSettingsStats)


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


elblProcEmail = stdLabelStyle(frameProcess, text="Email")
etxtProcEmail = stdEntryStyle(frameProcess)
elblProcEmail.grid(row = pos(0,rowPos), column = posC(0,colPos), sticky = NSEW)
etxtProcEmail.grid(row = rowPos, column = posC(1,colPos), sticky = E)












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

btn = stdButtonMenuStyle(\
    frameMenu,
    text='Settings',
    command = lambda: menuButtons(0)
    )

btnMenu.append(btn)

btn = stdButtonMenuStyle(\
    frameMenu,
    text="Account Level",
    command= lambda: menuButtons(1)
    )

btnMenu.append(btn)


btn = stdButtonMenuStyle(\
    frameMenu,
    text="User Level",
    command= lambda: menuButtons(2)
    )

btnMenu.append(btn)

btn = stdButtonMenuStyle(\
    frameMenu,
    text="Custom API",
    command= lambda: menuButtons(3)
    )

btnMenu.append(btn)

btn = stdButtonMenuStyle(\
    frameMenu,
    text="LDAP",
    command= lambda: menuButtons(3)
    )

btnMenu.append(btn)

for btnItem in btnMenu:
    btnItem.grid(\
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

eLblUserLogStart = stdLabelStyle(txtUserLogFrame, text="Log Start (mm/dd/yyyy)")
eTxtUserLogStart = stdEntryStyle(txtUserLogFrame, width=20)


eLblUserLogEnd = stdLabelStyle(txtUserLogFrame, text="Log End (mm/dd/yyyy)")
eTxtUserLogEnd = stdEntryStyle(txtUserLogFrame, width=20)




eLblUserLogStart.grid(row = pos(1,rowPos), column = 0, sticky = E)
eTxtUserLogStart.grid(row = rowPos, column = 1, columnspan=2, sticky = W)
eLblUserLogEnd.grid(row = pos(1,rowPos), column = 0, sticky = E)
eTxtUserLogEnd.grid(row = rowPos, column = 1, columnspan=2, sticky = W)


txtUserFrame = stdLabelFrameStyle(frameUserFields[-1], text = "User Configuration - select <Update User> to accept changes")
txtUserFrame.grid(column = 0, row = pos(1,rowPos), sticky = N+W)

rowPos = 0
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




tempRow = pos(1,rowPos)

btnInfo = stdButtonStyle(frameSubMenuCntrl[2], text="User Info", command=UpdateUser_Info)
btnUpdateEmail = stdButtonStyle(frameSubMenuCntrl[2], text="Update User", command=UpdateUser_Email)
btnLogOps = stdButtonStyle(frameSubMenuCntrl[2], text="Operations Log", command=getOpsLog)
btnLogSignin = stdButtonStyle(frameSubMenuCntrl[2], text="Sign In/Out Log", command=getSigningLog)
btnLogout = stdButtonStyle(frameSubMenuCntrl[2], text="Log Out User", command=logoutUser)
btnUpdateLicensed = stdButtonStyle(frameSubMenuCntrl[2], text="Set Licensed", command=UpdateUser_Licensed)
btnUpdateBasic = stdButtonStyle(frameSubMenuCntrl[2], text="Set Basic", command=UpdateUser_Basic)
btnUpdateWebinar = stdButtonStyle(frameSubMenuCntrl[2], text="Toggle Webinar", command=UpdateUser_Webinar)
btnUpdateLargeMtg = stdButtonStyle(frameSubMenuCntrl[2], text="Toggle Large Mtg", command=UpdateUser_LargeMtg)
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
stdButtonActionGrid(btnLogOps)
stdButtonActionGrid(btnLogSignin)
stdButtonActionGrid(btnLogout)
stdButtonActionGrid(btnUpdateLicensed)
stdButtonActionGrid(btnUpdateBasic)
stdButtonActionGrid(btnUpdateWebinar)
stdButtonActionGrid(btnUpdateLargeMtg)
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


(apiData, apiCommandsList,apiCategory, apiMenu) = apiList(frameSubMenuCntrl[3])

RADIOMODES = [\
        ("POST", "post"),
        ("GET", "get"),
        ("PUT", "put"),
        ("PATCH", "patch"),
        ("DELETE", "delete"),
    ]

RESTmethod = StringVar()
RESTmethod.set("get") # initialize

rowPos = 0
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


elblAPIURL = stdLabelLinkStyle(frameAPI, text="https://marketplace.zoom.us/docs/api-reference/zoom-api")
elblAPIURL.bind("<Button-1>", lambda e: urlOpen("https://marketplace.zoom.us/docs/api-reference/zoom-api"))
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

elblAPIURL.grid(row = pos(1,rowPos), column= 0, columnspan=6, sticky = NSEW)

btnAPIUpdate = stdButtonStyle(frameAPI, text="SEND", width=10, command=customAPI)
btnAPIUpdate.grid(row = 0, rowspan=4, column = 6, sticky = E)


frameApiPresets = stdEntryStyle(frameAPI)
frameApiPresets.grid(row = pos(1,rowPos), columnspan = 6, column= 0,)
btnApiPresetAdd = stdButtonStyle(frameApiPresets, text="Add Step to Preset", command=customAPI)
btnApiPresetAdd.grid(row = pos(1,rowPos), rowspan = 2, column = 0, sticky = E)
btnApiPresetSave = stdButtonStyle(frameApiPresets, text="Save Preset", command=customAPI)
btnApiPresetSave.grid(row = rowPos, rowspan=2, column = 2, sticky = E)


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
    'connection':stdLabelStatusStyle(frameStatus, textvariable = statusZoom, text="No Communication"),
    'license':stdLabelStatusStyle(frameStatus, width = 30, textvariable = statusLicense, text="Licenses:  No Data"),
    'cloud':stdLabelStatusStyle(frameStatus, textvariable = statusCloud, text="Cloud Storage:  No Data") 
    }

colPos = 0

for lbl in lblStatus:
    lblStatus[lbl].grid(row = 0, column = posC(1,colPos), sticky = W)

progress_var = DoubleVar() #here you have ints but when calc. %'s usually floats
progress = stdProgressBarStyle(frameStatus, length = 100, variable = progress_var)
progress.grid(row = 0, column = posC(1,colPos), sticky = W)


maxAppHeight = 694

btnTxtUpdates()

menuButtons(0)


#Testing
#get_InactiveDate()
#print(f"Local Time Coversion Check: {timeLocal('2020-06-08T21:59:43Z')}")
mainloop()




