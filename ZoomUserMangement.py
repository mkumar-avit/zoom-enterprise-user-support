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
#from PIL import Image, ImageTk
import csv
import json
import jwt
import linecache
import os
import requests
import time
from dateutil.relativedelta import relativedelta
from dateutil import tz
from tkinter import *
from tkinter import ttk
from tkinter import filedialog


## GLOBAL CONSTANTS ##
FROM_ZONE = tz.tzutc()
TO_ZONE = tz.tzlocal()
DATE_CHECK = ""

API_SCIM2_USER = 'https://api.zoom.us/scim2/Users'
USER_DB_FILE = "ZoomRetrievedUserList.csv"
EMAIL_FILE = 'email-list.csv'
API_FILE = 'ZoomAPI.json'

## GLOBAL VARIABLES ##
maxMonths = 0
maxNum = 0
cancelAction = False
fileLog = ""
dateStr=\
    {
        'log':'%m/%d/%y %H:%M:%S.%f',
        'std':'%m/%d/%Y %H:%M:%S',
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
        'plan': 'accounts/@/plans/usage',
        'account':'v2/accounts/@',
        'roles':'v2/roles',
        'rolesList':'v2/roles/@/members',
        'meetings':'v2/users/@/meetings',
        'subaccount':'v2/accounts',
        'recording':'v2/users/@/recordings',
        'settings':'v2/users/@/settings',
        'logout':'v2/users/@/token',
        'logs':'v2/report/operationlogs',
        'signin':'v2/report/activities',
        'trackingList':'v2/tracking_fields',
        'trackingGet':'v2/tracking_fields/@',
        'emailUpdate':'v2/users/@/email',
        'groupSettings':'v2/groups/@/settings'       
    }

userDB = []
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

    lineLen = 69    

    
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
     
        if len(text) >= lineLen and logConfig['wrap'].get() == 1:
            if '{' in text:
                text.replace('{', '{\n')  
            if '}' in text:
                text.replace('}', '}\n')
            
            textChunk = [text[i:i+lineLen] for i in range(0, len(text), lineLen)]
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

def PrintException():
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
    msg = f"++Exception in ({filename}, LINE {lineno}, {line.strip()}: {exc_obj}"
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
        PrintException()
        print(f'Error saving file {e}')

def timeLocal(utcTimeStr):
    
    localTZ = utcTimeStr
    
    try:
        # utc = datetime.utcnow()
        utc = datetime.datetime.strptime(utcTimeStr, dateStr["epoch"])

        # Tell the datetime object that it's in UTC time zone since 
        # datetime objects are 'naive' by default
        utc = utc.replace(tzinfo=from_zone)

        # Convert time zone
        localTZ = utc.astimezone(to_zone)    
        localTZ = datetime.datetime.strftime(localTZ, dateStr["12h"])
    except:
        PrintException()
        
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

    return csvData

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
        PrintException()
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
            
    except Exception as e:
        logging(f'Error in reading file: {e}')
    

    
    btnDeleteInactive["state"] = "normal"
    btnOpenDelete["state"] = "normal"
    btnSettingsStats["state"] = "normal"
    

def csvOpenDelete():
    cpUser = []
    rowCount = 0
    progress_var.set(0)
    listboxTop()
    try:
        root.filename = filedialog.askopenfilename(initialdir = "/",title = "Select file",filetypes = (("csv files","*.csv"),("all files","*.*")))
        logging (f"Open File: {root.filename}")
        fileName = root.filename
    except:
        PrintException()
        fileName = EMAIL_FILE
        
    try:
        with open(EMAIL_FILE) as csvfile:
            readCSV = csv.reader(csvfile, delimiter=',')
            #csvLen = len(readCSV)
            
            cpUser.clear()
            #print(f"{readCSV}")
            for row in readCSV:
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
            PrintException()
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
            PrintException()
            logging(f'!Error getting all meeting count:{e}')
            
    if meetings is not None:
        try:
            meetingCnt = meetings['total_records']
            
        except Exception as e:
            PrintException()
            logging(f'!Error getting meeting count:{e}')        
        try:     
            for record in meetings["meetings"]:
                if record['type'] == 2 or record['type'] == 8:
                    meetingScheduled += 1
        except Exception as e:
            PrintException()
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

def getLicenseInfo(desc):
    planInfo = send_REST_request('plan', 'me')
    (subAccount, seats) = get_subaccount_data()

    
    try:
        planLicenses = planInfo["plan_base"]["hosts"] + seats
        planUsers = planInfo["plan_base"]["usage"]
        remainingNow = planLicenses - planUsers
        remainingPct = round(((remainingNow / planLicenses) * 100),2)
        
        returnStr =  f"\nRemaining licenses:  {remainingPct}%, {remainingNow} (out of {planLicenses})"
            
        return returnStr
    except Exception as e:
        print ("Exception in License info: {}".format(e))
        return planInfo
    
    return ""

def logoutUser():
    global userDB
    
    userID = get_userID(eEmail.get())
    
    send_REST_request('logout', data=userID, rType = "delete", note=f"Attempt to Logout {eEmail.get()} from all devices")
    
    
def set_user_Email(userID, newEmail):
    
    update = {"email":newEmail}
    
    try:
        send_REST_request('emailUpdate', data=userID, body=update, rType = "put", note=f"Attempt to Update Zoom acct user {eEmail.get()} to {newEmail}")
    except Exception as e:
        logging(f"user {eEmail.get()} email update failed.  {e}")
        PrintException()
    
def get_userID(userEmail):
    licNo = 1
    emailIdx = 1
    userIDIdx = 2
    licenseIdx =  8
    userDBdef = ["Flags","Email","User ID","First Name", "Last Name", "Last Login", "Client Ver", "Group", "License","Months"]
    
    userEmail = eEmail.get()

    try:
        for user in userDB:
            if user[emailIdx] == userEmail:
                return user[userIDIdx]
    except:
        None
        
    return None

def delete_user(userID, userEmail=""):
    logging (f'Attempting to delete {userEmail}')
    
    
    deleteStatus = send_REST_request('user', data = userID, param = {"action":"delete"}, rType = "delete", note=userEmail)
    
    
def UpdateUser_Delete():
    listboxTop()
    
    userEmail = eEmail.get()
    userID =  get_userID(userEmail)
    
    delete_user(userID,userEmail)
    
    
def UpdateUser_Email():
    email = eEmail.get()
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
    userIDIdx = 2
    licenseIdx =  8
    groupIdx = 7
    userDBdef = ["Flags","Email","User ID","First Name", "Last Name", "Last Login", "Client Ver", "Group", "License","Months"]
    
    userEmail = eEmail.get()
    try:
        for user in userDB:
            if user[emailIdx] == userEmail:
                print(f"{user}")
                for item in user:
                    try:
                        key = userDBdef[user.index(item)]    
                    except Exception as e:
                        key = f"{e}"
                    
                    logging(f'{key}: {item}')
                
                
                try:
                    userSettings = get_user_settings(user[userIDIdx],  count = 0)
                   
                    for setting in userSettings['feature']:
                        text = setting.replace("_", " ")
                        logging(f'{text}: {userSettings["feature"][setting]}')
                    
                   
                except Exception as e:
                    logging (f'User settings could not be retrieved:{e}')
                
                try:
                    k = ''
                    if user[groupIdx] != 'No Group':
                        groups = user[groupIdx].split(":  ")
                        group = groups[1]
                        for category in userSettings:
                            try:
                                groupVal = groupDB[group][category]
                                userVal = userSettings[category]
                                diffSettings = {k: userVal[k] for k in groupVal if k in userVal and groupVal[k] != userVal[k]}
                                logging(diffSettings)
                            except:
                                None
                        logging(f'#Differences to group settings {len(diffSettings)}, {k}')
                except Exception as e:
                    logging(f'#Error in group setting comparison: {e}')
                    PrintException()
                
                try:
                    logging(f'Recordings: {check_user_recording_count(user[2])}')
                except Exception as e:
                    logging(f'Recordings in the last {eRecMonths.get()} months: {e}')
                
                try:
                    (meetingsAll, meetingsUpcoming, meetingsSched) = get_user_meetings(user[2])
                    logging(f'All Time Meeting Total:{meetingsAll}')
                    logging(f'Upcoming Meeting Total:{meetingsUpcoming}')
                    logging(f'Upcoming Scheduled Meetings:{meetingsSched}')
                except Exception as e:
                    logging(f'Upcoming Meetings {e}')
                
                logging(f'User Info: {userEmail}')
        else:
            if len(userDB) < 1:
                logging(f'Please retrieve Zoom user\'s data first.')
                
    except Exception as e:
        logging(f"No additional info: {e}")
        
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
    userEmail = eEmail.get()
    userID =  get_userID(userEmail)
    userSetting = get_user_settings(userID,  count = 0)
    
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
     
    userSetting = get_user_settings(userID,  count = 0)
      
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
    userIDIdx = 2
    licenseIdx =  8
    
    listboxTop()
    userEmail = eEmail.get()
    for user in userDB:
        if user[emailIdx] == userEmail:
            logging(f'Updating {userEmail} to {licType}')
            userID = user[userIDIdx]
            userCurrLicense = user[licenseIdx] 
            modify_user_license(userID,userEmail, userCurrLicense, userType=licNo)
            break
            
def UpdateUser_Licensed():
    global userDB
    licType = 'Licensed'
    licNo = 2
    emailIdx = 1
    userIDIdx = 2
    licenseIdx =  8
    listboxTop()
    userEmail = eEmail.get()
    for user in userDB:
        if user[emailIdx] == userEmail:
            logging(f'Updating {userEmail} to {licType}')
            userID = user[userIDIdx]
            userCurrLicense = user[licenseIdx] 
            modify_user_license(userID,userEmail, userCurrLicense, userType=licNo)
            break            
    
def xref_UpdateUser(userList):
    emailIdx = 1
    userIDIdx = 2
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
    


  
            
    
    chkParam = [False, False, False, False]
        
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
                        recordings = check_user_recording_count(user[userIDIdx])
                    
                    if recordings > 0:
                        chkParam[1] = True
                   
                    logging('{}: {} has {} recordings and last logged in {} months ago'.format(userGroup,email,recordings,months))
                    
                if chkMeetings.get() == 1:
                    (meetingsAllCnt, meetingCnt, meetingScheduled) = get_user_meetings(user[userIDIdx])
                    if meetingScheduled > 0:
                        chkParam[2] = True
                
                if chkBasic.get() == 1:
                    chkParam[3] = True
            
                   
                try:
                    if True not in chkParam:
                        delete_users_list(user[userIDIdx], email)
                    elif chkParam[3] is True:
                        chkParam[3] = False
                        if True not in chkParam:
                            modify_user_license(user[userIDIdx],email, userLicense)
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
    userIDIdx = 2
    monthsIdx = 6
    groupIdx = 7
    licenseIdx =  8
    userCount = 0
    recordings = 0
    months = ""
    progress_var.set(0)
    
    monthsActive = None
    recMonths = None
    meetings = None
    noDeletes = None
    
    chkParam = [False, False, False, False]
    logging(f'Cross ref {email} with retrieved users')   
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
                
                recordings = check_user_recording_count(user[userIDIdx])
                
                if recordings > 0:
                    chkParam[1] = True
               
                logging('{}: {} has {} recordings and last logged in {} months ago'.format(userGroup,email,recordings,months))
                
            if chkMeetings.get() == 1:
                (meetingsAllCnt, meetingCnt, meetingScheduled) = get_user_meetings(user[userIDIdx])
                if meetingScheduled > 0:
                    chkParam[2] = True
            
            if chkBasic.get() == 1:
                chkParam[3] = True
        
               
            try:
                if True not in chkParam:
                    delete_users_list(user[userIDIdx], email)          
                elif chkParam[3] is False:
                    if True in chkParam:
                        modify_user_license(user[userIDIdx],email, userLicense)   
                elif chkParam[3] is True:
                    chkParam[3] = False
                    if True not in chkParam:
                        modify_user_license(user[userIDIdx],email, userLicense)
                    else:
                        logging(f"{email} is not being deleted or modified.")
                else:
                    logging("{} is not being deleted or modified.".format(email))     
            except Exception as e:
                logging(f'Error Updating User: {e}')
        


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
    
    send_REST_request(api, data="", param = "", rType = "delete", note = 'userDesc')
    
    
    
        
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
        "email": eEmail.get(),
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
                            PrintException()
                            print(f'Error in CSV flag data: {e}')
                            None
                except:
                    PrintException()
                    #None
        except:
            PrintException()
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
                root.update_idletasks()
                
                userID = user[2]
                email = user[1]
                group = user[7]
                if flagFindUser == 1 and email == startingUser:
                        flagFindUser = 0
                
                if flagFindUser == 0:
                    logging(f'{count} Retrieving {group}, {email} settings')
                    userSettings = get_user_settings(userID,  count)
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
                                            PrintException()
                                            print(f'Error in CSV flag data: {e}')
                                            None
                                except:
                                    PrintException()
                                    #None
                        except:
                            PrintException()
                            #None

                
    except Exception as e:
        logging (f'Error with creating file: {e}')

def get_groups_settings(groupData):
    global cancelAction
    global groupDB
    
    listboxTop()
    cancelActions(False)
    fileName = "Zoom Group Setting Tracking.csv"
    groupDB = {}      
    try:
        count = 0
        with open(fileName, 'w', newline='') as csvFile:
            writer = csv.DictWriter(csvFile, fieldnames = ["Group", "Category", "Setting","Value"])
            writer.writeheader()
            
            for groupID in groupData:
                if cancelAction is True:
                    cancelAction = False
                    break
                
                count += 1
                root.update_idletasks()
                
                group = groupData[groupID]
                logging(f'{count} Retrieving {group} settings')
                groupSettings = get_group_settings(groupID, count)
                try:
                    groupDB[group] = groupSettings
                except:
                    PrintException()
                    logging(f'###Error:{e}')
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
                                        PrintException()
                                        print(f'Error in CSV flag data: {e}')
                                        None
                            except:
                                PrintException()
                                #None
                    except:
                        PrintException()
                        #None               
    except Exception as e:
        logging (f'Error with creating file: {e}')


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
        PrintException()
        print(f'Error getting Settings: {e}')
    
    return groupSettings
        
def get_user_settings(userID,  count = 0):   
    userSettings = None
    
    try:
        
        timeStart = time.time()
        userSettings = send_REST_request('settings', data = userID, rType = "get")
        userSettings2 = send_REST_request('settings', data = userID, param = {"option":"meeting_authentication"}, rType = "get")
        userSettings3 = send_REST_request('settings', data = userID, param = {"option":"recording_authentication"}, rType = "get")
        userSettings['auth'] = {}
        userSettings['auth'].update(userSettings2)
        userSettings['rec_auth'] = {}
        userSettings['rec_auth'].update(userSettings3)
        
        timeEnd = time.time()            
        timeTotal = timeEnd - timeStart
        btnSettingsText.set(f"Backup User Settings {timeTotal:.2f}s per user/{((timeTotal*(len(userDB)-count))/60):.3f}mins")          
    except Exception as e:
        PrintException()
        print(f'Error getting Settings: {e}')
    
    
    
    return userSettings
                
def get_user_data(groupsDict):
    global progress_var
    global progress
    global root
    global userDB
    global userInactiveDB
    global cancelAction
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
        todaysDate = datetime.datetime.now()
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

                            try:
                                userEmail = user['email']
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
                                try:
                                    userLastLogin = user['last_login_time']
                                except:
                                    #No valid Login, so creation date should be used.
                                    try:
                                        userLastLogin = user['created_at']
                                    except:
                                        userLastLogin = '2015-01-01T00:00:00Z'
                                
                                UTCdate = datetime.datetime.strptime(userLastLogin,'%Y-%m-%dT%H:%M:%SZ')
                                loginDate =  UTCdate.date()
                                
                                #print("{} & {}".format(loginDate, DATE_CHECK))
                                
                                if DATE_CHECK is not None:
                                    try:
                                        
                                        delta =  (DATE_CHECK - loginDate).days
                                        #logging("Delta date: {}".format(delta))
                                    except Exception as e:
                                        PrintException()
                                        print('Date Error: {}'.format(e))
                                        
                                        
                                    
                                elapsedTime = relativedelta(todaysDate,UTCdate)
                                
                                userLoginYears = elapsedTime.years 
                                userLoginMonths = (elapsedTime.years * 12) + elapsedTime.months
                                
                                #if userLoginMonths >= maxMonths:
                            except Exception as e:
                                print ("Error in date-time conversion: {}".format(e))
                            
                            try:
                                if DATE_CHECK is not None:
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
                                print ('No Valid Last Login Data for{}: {}'.format(userEmail,e))
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
                    progress_var.set(int((record_count/recordsTotal)*100))
                    root.update()
                    #root.update_idletasks()
                    
                    #print("Time Remaining: {:.2f}s, {}/{} : {}".format(runAvg,page,total_pages,user_ids))
                # print the contents using zip format.

                    
                logging('Total Flagged Users: {}'.format(flagUserCount))
                
                logging('User Data Pulled:  {}'.format(len(userDB)))
                logging('Users Inactive: {}'.format(len(userInactiveDB)))
                btnDeleteInactive["state"] = "normal"
                btnOpenDelete["state"] = "normal"
                btnSettingsStats["state"] = "normal"
                
        except Exception as e:
            logging ('File Write Error, please close file it may be open in Excel\n{}'.format(e))
            data = None
        
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

def getLicenseInfo(desc):
    planInfo = \
        send_REST_request(\
            apiType ='plan',
            data = "me",
            rType = "get",
            note="",
        )
    
    (subAccount, seats) = get_subaccount_data()

    
    try:
        planLicenses = planInfo["plan_base"]["hosts"]
        planUsers = planInfo["plan_base"]["usage"]
        remainingNow = planLicenses - planUsers
        remainingPct = round(((remainingNow / planLicenses) * 100),2)
        
        returnStr =  f"\nRemaining licenses:  {remainingPct}%, {remainingNow} (out of {planLicenses})"
             
        return returnStr
    except Exception as e:
        print ("Exception in License info: {}".format(e))
        return planInfo
    
    return ""
    
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
    value = MAX_NUM
    progress_var.set(0)
    usersCnt = len(userInactiveDB)
    
    logging(f'Relicensing {usersCnt} users')
    cancelActions(False)
    for userData in userInactiveDB:
        if cancelAction is True:
            cancelAction = False
            break
        
        
        
        if counter >= value and value != 0:
            break
        
        #userID = userData[0]
        userEmail = userData[5]
        userName = "{}".format(userEmail)
        userLicense = userData[4]
        logging('Modifying: {}, {} License'.format(userName,userLicense))
        start_modify_user(userEmail)
        #modify_user_license(userID,userName, userLicense)
        counter += 1
        progress_var.set(int((counter/usersCnt)*100))
        
def onListSelect(event):
    global eDomain
    global eEMail
    # Note here that Tkinter passes an event object to onselect()
    objWidget = event.widget
    try:
        idx = int(objWidget.curselection()[0])
    except:
        idx = 0
    value = objWidget.get(idx)
    print('You selected item {}: {}, checking for domain: {}'.format(idx, value, eDomain.get()))
    data = value.split()
    for item in data:
        if f'@{eDomain.get()}' in item:
            eEmail.delete(0,"end")
            eEmail.insert(0, item)

def menuAPICommand(eventObject):
    #logging('Triggered API Command')
    command = emenuAPICmd.get()
    

    etxtAPI.delete(0, END)
    etxtAPI.insert(0, command)
    emenuAPICmd.configure(width=20)
    
    
def menuAPICategory(eventObject):
    global apiCommandList
    #logging('Triggered API Category')
    category = emenuAPICat.get()
    
    apiCommandList.clear()
    
    for cmd in apiDict[category]:
        apiCommandList.append(cmd)
        
    emenuAPICmd['values'] = apiCommandList
    apiCommand.set(apiCommandList[0])
    
    #resizeFuncAPICat()
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
    userDailyOpLog(eEmail.get())
def getSigningLog():
    listboxTop()
    userDailySignInLog(eEmail.get())

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
                            userLog[item] = timeLocal(userLog[item])
                        logging(f"{text}: {userLog[item]}")
        logging(f'Done checking Daily Operation log for: {userEmail}')
    except:
        PrintException()
    
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
                            userLog[item] = timeLocal(userLog[item])
                        logging(f"{text}: {userLog[item]}")

        logging(f'Done checking Daily SignIn/Out log for: {userEmail}')
    except:
        PrintException()

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


def clearLog():
    logging(f'Clearing Log...')
    listbox.delete(0,END)    


def callback():
    global listbox
    global userDB
    global cancelAction
    
    startTime = time.time()
    cancelActions(False)
    userDB.clear()
    listboxTop()
    #listbox.delete(0,END)
    zoom_token_auth()
    groupsData = get_group_data()
            
    get_groups_settings(groupsData)
            
    #testdata
    data = get_user_data(groupsData)
    endTime = time.time()
    timeTotal = endTime - startTime
    #btn.set(f"Retrieve all users: {((timeTotal*(len(userDB)))/60):.3f}mins")          


def zoom_token_auth():
    global maxMonths
    global maxNum
 
    global DATE_CHECK
    
    try:
        maxMonths = int(eMonths.get())
    except:
        maxMonths = 10
    
    try:
        maxNum = int(eNumber.get())
    except:
        maxNum = 0
    
    try:
        
        if eDate.get() != '':
            DATE_CHECK = datetime.datetime.strptime(eDate.get(), '%m/%d/%Y').date()
            print ("{}".format(DATE_CHECK))
        else:
            DATE_CHECK = None
    except Exception as e:
        logging ("Invalid inactive date")
        DATE_CHECK = "No Date"
    
    logging("Inactive Date:  {}".format(DATE_CHECK))
    
def customAPI():
      
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
    
def cancelActions(state):
    global cancelAction
    
    #if state == cancelAction:
    #    cancelAction = not cancelAction
        
    if state is True:
        logging("Cancelling last request...")
        cancelAction = True
        btnCancel["state"] = "disabled"
    else:
        cancelAction = False
        btnCancel["state"] = "normal"

def cancelActionsBtn():
    listboxTop()
    cancelActions(True)


def posCol(inc,val):
    global colPos
    
    val = None
    
    if inc == 0:
        colPos = 0
    colPos += inc
    return colPos
    
def pos(inc,val):
    global rowPos
    
    val = None
    
    if inc == 0:
        rowPos = 0
    rowPos += inc
    return rowPos

def btnTxtUpdates():
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
def logConfigBox():
    
    global logConfig
    try:
        logConfig['open'] = not logConfig['open']
    except:
        logConfig['open'] = True
        
        
    #if not logConfigWindow.top.winfo_exists():
    #logConfigWindow.top.lift(root)
    
    if logConfig['open'] == True:
        logConfigWindow = Toplevel(root)
        logConfigWindow.title('Log Settings')
        logConfigWindow.resizable(height = False, width = False)
        
        frameConfig = LabelFrame(logConfigWindow, padx = 100, pady = 10, text = "Logging Options")
        frameConfig.grid(row = 0 , column = 0, sticky = W)   
        
        chkbxLogTimeStamp = Checkbutton(frameConfig,text='Timestamp', variable = logConfig['timestamp'])
        chkbxLogTimeStamp.grid(row = pos(0,rowPos) , column = 0, sticky = W)
        chkbxLogTimeStamp.config(bd=2)
        
        chkbxLogWrap = Checkbutton(frameConfig,text='Wrap Lines', variable = logConfig['wrap'])
        chkbxLogWrap.grid(row = pos(1,rowPos) , column = 0, sticky = W)
        chkbxLogWrap.config(bd=2)
        
        chkbxLogInactive = Checkbutton(frameConfig,text='Inactive Users', variable = logConfig['inactive'])
        chkbxLogInactive.grid(row = pos(1,rowPos), column = 0, sticky = W)
        chkbxLogInactive.config(bd=2)
        
        chkbxLogNoGroup = Checkbutton(frameConfig,text='Users in no group', variable = logConfig['noGroup'])
        chkbxLogNoGroup.grid(row = pos(1,rowPos), column = 0, sticky = W)
        chkbxLogNoGroup.config(bd=2)
        
        chkbxLogSave = Checkbutton(frameConfig,text=f'Save Logs', variable = logConfig['save'])
        chkbxLogSave.grid(row = pos(1,rowPos), column = 0, sticky = W)
        chkbxLogSave.config(bd=2)
        
        chkbxDebug = Checkbutton(frameConfig,text='Debug Mode', variable = logConfig['debug'])
        chkbxDebug.grid(row = pos(1,rowPos), column = 0, sticky = W)
        chkbxDebug.config(bd=2)


rowPos = 0
colPos = 0
colPosMax = 6

# Build Primary Window
root = Tk()
root.option_add('*font', ('verdana', 8, 'bold'))
root.title('Zeus Tool:  Zoom Enterprise User Scan Tool v0.7.10')
root.resizable(height = False, width = False)


#try:
#    background_image=PhotoImage('.\bgimage.png')
#    background_label = Label(root, image=background_image)
#    background_label.photo=background
#    background_label.place(x=0, y=0, relwidth=900, relheight=900)
#except Exception as e:
#print(f'Image Error: {e}')

#Display Title within application

iconFolder = PhotoImage(master=root, file='folder.png')

#style = ttk.Style() 
#style.configure('TButton', font =
#               ('calibri', 10, 'bold', 'underline'), 
#                foreground = 'red')
#style.map('TButton', foreground = [('active', '! disabled', 'green')], 
#                     background = [('active', 'black')]) 


frameApp = LabelFrame(root, text = "ZEUS by Maneesh Kumar")
frameStep1 = LabelFrame(frameApp, padx=5, pady = 5, text = "Required Info")
frameProcess = LabelFrame(frameApp, padx=5, pady = 5, text = "Restart Processing")
frameButtons = LabelFrame(frameApp,text = "Actions")
frameStep2 = LabelFrame(frameApp, padx = 5, pady =5, text="Options that prevent user updates")
frameUser = LabelFrame(frameApp, text = "User Configuration")
frameLog = LabelFrame(frameApp)
frameAPI = LabelFrame(frameApp, text = "Custom API Commands")

frameApp.grid()   
frameStep1.grid(\
        row = pos(0,rowPos), columnspan = int(colPosMax/3), sticky = N)
frameProcess.grid(\
        row = pos(1,rowPos), columnspan = int(colPosMax/3), sticky = NSEW)

frameButtons.grid(\
        row = pos(1,rowPos), column= colPos + 0, columnspan = colPosMax, sticky = NSEW)
frameLog.grid(\
        row = pos(1,rowPos), column = colPos + 0, columnspan = colPosMax, sticky = NSEW)


frameAPI.grid(\
        row = pos(1,rowPos), column = colPos + 0, columnspan = colPosMax, sticky = NSEW)

frameUser.grid(\
        row = pos(1,rowPos), column = colPos + 0, columnspan = colPosMax, sticky = NSEW)



frameStep2.grid(\
        row = pos(0,rowPos), column = colPos + 2, rowspan = 2, columnspan = int(colPosMax/3), sticky = NSEW)


btnOpenCreds = Button(\
    frameStep1,
    text="Open Credentials File",
    image=iconFolder,
    compound = LEFT,
    width=20,
    command=openCredentials
    )


btnOpenCreds.grid(row = pos(1,rowPos), columnspan = 2, column = 0, sticky = NSEW )


eLbl1 = Label(frameStep1, text="API Key")
eAPIKey = Entry(frameStep1)
eLbl2 = Label(frameStep1, text="API Secret")
eAPISecret = Entry(frameStep1, show='*')
eLbl3 =  Label(frameStep1, text="Email Domain")
eDomain = Entry(frameStep1)
eLbl4 = Label(frameStep1, text="LDAP Host")
eLDAPHost = Entry(frameStep1)
eLbl5 = Label(frameStep1, text="LDAP Login")
eLDAPUser = Entry(frameStep1)
eLbl6 = Label(frameStep1, text="LDAP Password")
eLDAPPass = Entry(frameStep1, show='*')


eLbl1.grid(row = pos(1,rowPos), column= colPos, sticky = E)
eAPIKey.grid(row = rowPos, column = colPos+1)

eLbl2.grid(row = pos(1,rowPos), column = colPos, sticky = E)
eAPISecret.grid(row = rowPos, column = colPos + 1)
eLbl3.grid(row = pos(1,rowPos), column = colPos, sticky = E)
eDomain.grid(row = rowPos, column = colPos + 1)

eLbl4.grid(row = pos(1,rowPos), column = colPos, sticky = E)
eLDAPHost.grid(row = rowPos, column = colPos + 1)

eLbl5.grid(row = pos(1,rowPos), column = colPos, sticky = E)
eLDAPUser.grid(row = rowPos, column = colPos + 1)

eLbl6.grid(row = pos(1,rowPos), column = colPos, sticky = E)
eLDAPPass.grid(row = rowPos, column = colPos + 1)


#eLbl3 = Label(root, text="Number to Relicense (debug)")
#eLbl3.pack()
#eNumber = Entry(root)
#eNumber.pack()


eAPIKey.focus_set()

elblProcEmail =  Label(frameProcess, text="Email")
etxtProcEmail = Entry(frameProcess)
elblProcEmail.grid(row = pos(1,rowPos), column = colPos, sticky = E)
etxtProcEmail.grid(row = rowPos, column = colPos + 1)


btnOpenDeleteText = StringVar()
btnDeleteInactiveText = StringVar()
btnSettingsText = StringVar()

btn = Button(frameButtons, text="Retrieve All User Data", width=30, command=callback)
btnOpen = Button(frameButtons, text="Open All User Data", image=iconFolder, compound = LEFT, width=35, command=csvOpen)
btnOpenDelete = Button(frameButtons, textvariable=btnOpenDeleteText,image=iconFolder, compound = LEFT, width=60, command=csvOpenDelete, state=DISABLED)
btnDeleteInactive = Button(frameButtons, textvariable=btnDeleteInactiveText, width=60, command=Relicense_Inactive, state=DISABLED)
btnSettingsStats = Button(frameButtons, textvariable = btnSettingsText, width=60, command=get_users_settings, state=DISABLED)
btnRoles = Button(frameButtons, text="List Zoom user roles", width=60, command=get_acct_roles)


btn.grid(column = colPos, row = pos(1,rowPos), sticky = NSEW)
btnOpen.grid(column = colPos+1, row = rowPos, sticky = NSEW)
btnOpenDelete.grid(column = colPos, columnspan = 2, row = pos(1,rowPos), sticky = NSEW)
btnDeleteInactive.grid(column = colPos, columnspan = 2, row = pos(1,rowPos), sticky = NSEW)
btnSettingsStats.grid(column = colPos, columnspan = 2, row = pos(1,rowPos), sticky = NSEW)
btnRoles.grid(column = colPos, columnspan = 2, row = pos(1,rowPos), sticky = NSEW)

#btnDeleteInvalid = Button(root, text="Delete All Invalid Users", width=30, command=callback, state=DISABLED)
#btnDeleteInvalid.pack()
#btnSAMLReorg = Button(root, text="Relicense users based on SAML", width=30, command=callback, state=DISABLED)
#btnSAMLReorg.pack()
#btnOpen = Button(root, text="Save Log", width=30, command=logSave)
#btnOpen.pack()


chkBasic = IntVar(value=1)
chkbxBasic = Checkbutton(frameStep2,text='Change user to Basic (No Deletes)', variable = chkBasic, command = btnTxtUpdates)
chkbxBasic.grid(row = pos(1,rowPos) , column = colPos + 2, sticky = W)
chkbxBasic.config(bd=2)


chkMeetings = IntVar()
chkbxMeetings = Checkbutton(frameStep2,text='Check for Upcoming Meetings', variable = chkMeetings, command = btnTxtUpdates)
chkbxMeetings.grid(row = pos(1,rowPos) , column = colPos + 2, sticky = W)
chkbxMeetings.config(bd=2)


chkRec = IntVar()
chkbxRecordings = Checkbutton(frameStep2,text='Check for Cloud Recordings', variable = chkRec, command = btnTxtUpdates)
chkbxRecordings.grid(row = pos(1,rowPos), column = colPos + 2, sticky = W)
chkbxRecordings.config(bd=2)

chkActivity = IntVar()
chkbxActivity = Checkbutton(frameStep2,text='Check for user Activity', variable = chkActivity, command = btnTxtUpdates)
chkbxActivity.grid(row = pos(1,rowPos) , column = colPos + 2, sticky = W)
chkbxActivity.config(bd=2)

eLbl8 = Label(frameStep2, text="No. of months to check for recordings")
eLbl8.grid(row = pos(1,rowPos), column = colPos + 2)
eRecMonths = Entry(frameStep2)
eRecMonths.grid(row = pos(1,rowPos), column = colPos + 2)
eRecMonths.delete(0, END)
eRecMonths.insert(0, "6")



eLblMonthsActive = Label(frameStep2, text="Months to be considered still active")
eLblMonthsActive.grid(row = pos(1,rowPos), column = colPos + 2)
eActiveUser = Entry(frameStep2)
eActiveUser.grid(row = pos(1,rowPos), column = colPos + 2)
eActiveUser.delete(0, END)
eActiveUser.insert(0, "0")

#eLbl = Label(frameStep2, text="Months since last signin to be Inactive")
#eLbl.grid(row = pos(1,rowPos), column = colPos, columnspan = int(colPosMax / 3))
#eMonths = Entry(root)
#eMonths.pack()


eLblInactive = Label(frameStep2, text="Date of last login for an inactive user")
eLblInactive.grid(row = pos(1,rowPos), column = colPos + 2)

elblDate = Label(frameStep2, text= "mm/dd/yyyy  ")
elblDate.grid(row=pos(1,rowPos), column = colPos + 2, sticky = W)

eDate = Entry(frameStep2)
eDate.grid(row = rowPos, column = colPos + 2,sticky = E)
eDate.delete(0, END)
eDate.insert(0, "01/01/2019")


frameUserFields = LabelFrame(frameUser)
frameUserFields.grid(column = 0, row = pos(1,rowPos), columnspan = int(colPosMax), sticky=NSEW)
tempRow = pos(1,rowPos)

eLblUserEmail = Label(frameUserFields, text="User Email")
eEmail = Entry(frameUserFields,width=30)
btnLogOps = Button(frameUserFields, text="Op Log", width=10, command=getOpsLog)
btnLogSignin = Button(frameUserFields, text="Signing Log", width=10, command=getSigningLog)



elblUpdateEmail = Label(frameUserFields, text="Updated email")
etxtUpdateEmail = Entry(frameUserFields, width=30)
btnUpdateEmail = Button(frameUserFields, text="Update", width=10, command=UpdateUser_Email)

eLblUserEmail.grid(row = pos(0,rowPos), column = 0, sticky=E)
eEmail.grid(row = rowPos, column = 1, columnspan=2, sticky = W)
btnLogOps.grid(row = rowPos, column = 2, sticky = W)
btnLogSignin.grid(row = rowPos, column = 3, sticky = W)

elblUpdateEmail.grid(row = pos(1,rowPos), column = 0, sticky = W)
etxtUpdateEmail.grid(row = rowPos, column = 1,sticky = NSEW)
btnUpdateEmail.grid(row = rowPos, column =2, sticky = E)


frameUserBtn = LabelFrame(frameUser)
rowPos = tempRow
frameUserBtn.grid(column = 0, row = pos(1,rowPos), columnspan = int(colPosMax/3))


btnInfo = Button(frameUserBtn, text="Info", width=8, command=UpdateUser_Info)
btnInfo.grid(row = rowPos, column = colPos + 2)


btnLogout = Button(frameUserBtn, text="Log Out", width=8, command=logoutUser)
btnLogout.grid(row = rowPos, column = colPos + 3)


btnUpdateLicensed = Button(frameUserBtn, text="Licensed", width=8, command=UpdateUser_Licensed)
btnUpdateLicensed.grid(row = rowPos, column = colPos + 4)

btnUpdateBasic = Button(frameUserBtn, text="Basic", width=8, command=UpdateUser_Basic)
btnUpdateBasic.grid(row = rowPos, column = colPos + 5)


btnUpdateWebinar = Button(frameUserBtn, text="Webinar", width=8, command=UpdateUser_Webinar)
btnUpdateWebinar.grid(row = rowPos, column = colPos + 6)


btnUpdateLargeMtg = Button(frameUserBtn, text="Large Mtg", width=8, command=UpdateUser_LargeMtg)
btnUpdateLargeMtg.grid(row = rowPos, column = colPos + 7)

btnUpdateDelete = Button(frameUserBtn, text="Delete", width=8, command=UpdateUser_Delete, state=DISABLED)
btnUpdateDelete.grid(row = rowPos, column = colPos + 8)

btnCancel = Button(frameLog, text="Cancel Action", width=15, command=cancelActionsBtn, state=DISABLED)
btnCancel.grid(row = 1, column = 1, sticky = W)

btnClearLog = Button(frameLog, text="Clear log", width=15, command=clearLog)
btnClearLog.grid(row = 1, column = 1, sticky = S )

progress_var = DoubleVar() #here you have ints but when calc. %'s usually floats
progress = ttk.Progressbar(frameLog, orient = HORIZONTAL, variable=progress_var, length = 100, mode = 'determinate') 
progress.grid(row = 1, column = 1, sticky = E)
    

logData = StringVar(frameLog)
logData.set("Program Started")

listbox = Listbox(frameLog, setgrid = 1, width = 60, name='log')
listbox.bind('<<ListboxSelect>>',onListSelect )
# Adding Listbox to the left 
# side of root window 
listbox.grid(row = 2, column = 1) 

scrollbar = Scrollbar(frameLog) 
scrollbar.grid(row = 2 , column = 2, rowspan=2,  sticky=N+S+W) 
listbox.config(yscrollcommand = scrollbar.set)  
scrollbar.config(command = listbox.yview)


logConfig = {}
logConfig['timestamp'] = IntVar(value = 1)
logConfig['wrap'] = IntVar(value = 1)
logConfig['inactive'] = IntVar(value = 1)
logConfig['noGroup'] = IntVar(value = 1)
logConfig['save'] = IntVar(value = 1)
logConfig['debug'] = IntVar()



btnLogConfig = Button(frameLog,text='Log Config', command=logConfigBox)
btnLogConfig.grid(column = 1, row = 3, sticky = E)



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
                    variable=RESTmethod, value=mode)
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

    eLblAPICat = Label(frameAPI, text="API Category")
    emenuAPICat = ttk.Combobox(frameAPI, textvariable=apiCategories, values=apiCategoryList)
    resizeFuncAPICat()
    
    eLblAPICmd = Label(frameAPI, text="API Command")
    emenuAPICmd = ttk.Combobox(frameAPI, textvariable=apiCommand,postcommand=resizeFuncAPICmd, values=apiCommandList)
    #etxtAPI.delete(0, END)
    #etxtAPI.insert(0, "/report/operationlogs")

    emenuAPICat.bind("<<ComboboxSelected>>", menuAPICategory)
    emenuAPICmd.bind("<<ComboboxSelected>>", menuAPICommand)
    
    
    eLblAPICat.grid(row = pos(1,rowPos), column= 0, columnspan=2, sticky = E)
    emenuAPICat.grid(row = rowPos, column = 2, columnspan=4, sticky = W)    
    eLblAPICmd.grid(row = pos(1,rowPos), column= 0, columnspan=2, sticky = E)
    emenuAPICmd.grid(row = rowPos, column = 2, columnspan=4, sticky = W)   


elblAPIParam = Label(frameAPI, text="Parameters (JSON)")
etxtAPIParam = Entry(frameAPI)
etxtAPIParam.delete(0, END)
#etxtAPIParam.insert(0, '{"page_size":300}')

elblAPIBody = Label(frameAPI, text="Body (JSON)")
etxtAPIBody = Entry(frameAPI)


elblAPIURL = Label(frameAPI, text="https://marketplace.zoom.us/docs/api-reference/zoom-api")
elblAPI = Label(frameAPI, text="Commmand (URL End)")
etxtAPI = Entry(frameAPI)
    
elblAPI.grid(row = pos(1,rowPos), column= 0, columnspan=2, sticky = E)
etxtAPI.grid(row = rowPos, column = 2, columnspan=4, sticky = W)

elblAPIParam.grid(row = pos(1,rowPos), column= 0, columnspan=2, sticky = E)
etxtAPIParam.grid(row = rowPos, column = 2, columnspan=4, sticky = W)

elblAPIBody.grid(row = pos(1,rowPos), column= 0, columnspan=2, sticky = E)
etxtAPIBody.grid(row = rowPos, column = 2, columnspan=4, sticky = W)

elblAPIURL.grid(row = pos(1,rowPos), column= 0, columnspan=6, sticky = W)

btnAPIUpdate = Button(frameAPI, text="SEND", width=10, command=customAPI)
btnAPIUpdate.grid(row = 0, rowspan=4, column = 6, sticky = E)

#screenHeight = root.winfo_screenheight() 
#screenWidth = root.winfo_screenwidth() 
#windowHeight = root.winfo_height()
#windowWidth = root.winfo_width()

#if screenHeight > windowHeight:
#    scrollbarApp = Scrollbar(frameApp) 
#    scrollbarApp.grid(row = 0 , column = 7, rowspan=5,  sticky=N+S+W) 
#    frameApp.config(yscrollcommand = scrollbarApp.set)  
#    scrollbar.config(command = frameApp.yview)


btnTxtUpdates()




mainloop()




