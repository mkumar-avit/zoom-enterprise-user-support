#import os
#import webbrowser
#import sys
import time
import requests
import datetime
import linecache
import os
#import io
#from PIL import Image, ImageTk
import csv
from dateutil.relativedelta import relativedelta
#from dateutil.parser import parse
#from signal import signal, SIGINT
from sys import exit

from tkinter import *
from tkinter import ttk
from tkinter import filedialog



import jwt

DATE_CHECK = ""
jwtToken = ""
ACCESS_TOKEN = ""
AUTHORIZATION_HEADER = {}
MAX_MONTHS = 8
MAX_NUM = 1
MAX_WEEKS = 52
API_ENDPOINT_USER_LIST = 'https://api.zoom.us/v2/users'
API_GROUP_LIST = 'https://api.zoom.us/v2/groups'
API_SCIM2_USER = 'https://api.zoom.us/scim2/Users'

TOTAL_LICENSES = 25000
userDB = []
userInactiveDB = []

def logging(text):
    global logData
    global listbox
    global root
    logData.set(text)
    listbox.insert(0, text)
    print("Log:  {}".format(text))
    root.update()

def PrintException():
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    logging(f"++Exception in ({filename}, LINE {lineno}, {line.strip()}: {exc_obj}")

def logSave():
    try:
        file = "ZoomAppLog.txt"
        with open(file, 'w') as f:
            f.write(''.join(listbox.get(0, END)))
            f.write('\n')
            logging('Log File Saved: {}'.format(file))
    except Exception as e:
        logging("Error saving log: {}".format(e))

def JWT_Token(key,secret):    
    TIMESTRING_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
    today = datetime.datetime.now()
    leaseTime = 6000 + (60*60*7)
    expTime = today + datetime.timedelta(seconds=leaseTime)
    logging ("Token Expiration: {},{}".format(expTime,datetime.datetime.strftime(expTime, TIMESTRING_FORMAT)))
    
    payload =\
            {
                "iss":key,
                "exp":expTime
            }
    
    encoded_jwt = jwt.encode(payload, secret, algorithm='HS256')
    
    return encoded_jwt.decode("utf-8")
    
def csvOpen():
    global userDB
    global userInactiveDB
    
    try:
        root.filename = filedialog.askopenfilename(initialdir = "/",title = "Select file",filetypes = (("csv files","*.csv"),("all files","*.*")))
        logging (f"Open File: {root.filename}")
        fileName = root.filename
    except:
        PrintException()
        fileName = 'InactiveZoomUsers.csv'
    
    
    try:
        with open(fileName) as csvfile:
            readCSV = csv.reader(csvfile, delimiter=',')
            
            userDB.clear()     
            for row in readCSV:
                userDB.append(row)
                logging('Read data: {}'.format(row[1]))
                #fieldnames = ['flag','userID','email','first_name', 'last_name','last_login','months_since','app_ver','group','license']
            
            logging('Number of Entries opened: {}'.format(len(userDB)))
    except Exception as e:
        logging('Error in reading file: {}'.format(e))
    
    
    userInactiveDB = userDB
    
    btnDeleteInactive["state"] = "normal"
    btnOpenDelete["state"] = "normal"
    
    

def csvOpenDelete():
    cpUser = []
    rowCount = 0
    progress_var.set(0)
    
    try:
        root.filename = filedialog.askopenfilename(initialdir = "/",title = "Select file",filetypes = (("csv files","*.csv"),("all files","*.*")))
        logging (f"Open File: {root.filename}")
        fileName = root.filename
    except:
        PrintException()
        fileName = 'email-list.csv'
        
    try:
        with open('email-list.csv') as csvfile:
            readCSV = csv.reader(csvfile, delimiter=',')
            #csvLen = len(readCSV)
            
            cpUser.clear()
            #print("{}".format(readCSV))
            for row in readCSV:
                rowCount += 1
                try:
                    cpUser.append(row[0])
                except Exception as e:
                    log("Error appending email")
                
                logging('Read CSV data: {}'.format(row))
                #fieldnames = ['flag','userID','email','first_name', 'last_name','last_login','months_since','app_ver','group','license']
                #progress_var.set(int((rowCount/csvLen)*100))
            logging('Number of Entries opened: {}'.format(len(cpUser)))
        try:
            xref_UpdateUser(cpUser)
        except Exception as e:
            logging('Err xref user')
    except Exception as e:
        logging('Error in reading Email file: {}'.format(e))        
    
   


def xref_UpdateUser(userList):
    ##@@TODO
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
    
    print("\nData:::\n{}\n{}".format(userList,userDB))
    userEmails = len(userList) - 1

    try:
        monthsActive = int(eActiveUser.get())
    except:
        monthsActive = 0

    try:
        recMonths = int(eRecMonths.get())
    except:
        recMonths = 0

    for email in userList:
        userCount += 1
        for user in userDB:
            if user[emailIdx] == email:
                userGroup = user[7]
                userLicense = user[8]
                months = user[9]
                if months < recMonths:
                    recordings = check_user_recording_count(user[userIDIdx])
                
                logging('{}: {} has {} recordings and last logged in {} months ago'.format(userGroup,email,recordings,months))

                if recordings == 0:
                    try:
                        
                        if months > monthsActive:
                            delete_users_list(user[userIDIdx], email)
                        elif userLicense.lower() != 'basic':
                            modify_user_license(user[userIDIdx],email, userLicense)
                        else:
                            logging("{} is not being deleted or modified due to recent activity.".format(email))     
                    except Exception as e:
                        logging('Error Deleting user: {}'.format(e))
                else:
                    try:
                        if userLicense.lower() != 'basic':
                            None
                            #modify_user_license_scim2(user[userIDIdx],email, userLicense, userType="Basic")
                    except Exception as e:
                        logging('Error modifying user to Based: {}'.format(e))
                            
                
                logging("Deactivate: {}".format(email))
            
        progress_var.set(int((userCount/userEmails)*100))            
    else:
        logging("No users to remove")
    logging("Finished removing users....")


def get_group_data():
    response = None
    groupData = {}

    
        
    try:
        groups = send_request(API_GROUP_LIST, sendData = None)
    except Exception as e:
        groups = None
        print('Exception:{}'.format(e))    
   
    if groups != None:
        try:
            total_groups = groups['total_records']
            logging('Number of groups found: {}'.format(total_groups))
            print('{}'.format(groups))
        except Exception as e:
            logging('Groups Count issue:{}'.format(e))
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
                logging('No Group ID:'.format(e))
                gID = ''
            
            try:
                groupData.update({gID:gName})
            except Exception as e:
                logging('Error in storing group data: {}'.format(e))
    return groupData

def modify_user_license(userID,userEmail, userCurrLicense, userType=1):
    api = f"https://api.zoom.us/v2/users/{userID}"
    
    api = f"{api}?action=delete"
    
    userDesc = f"{userEmail} will be updated to {userType}"
    
    data =\
        {
            "type": 1
        }   
    
    response = patch_request(api,body=data,info=userDesc)   
   
               
            
def modify_user_license_scim2(userID,userName, userCurrLicense, userType="Basic"):
    # userInactiveDB = [[userID,userLoginMonths, userFirstName, userLastName, License],...]
    global chkRec
     
    if userCurrLicense.lower() != userType.lower():
        userURL = '{}/{}'.format(API_SCIM2_USER,userID)
        #https://api.zoom.us/scim2/Users/{userId}
        userSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
        data =\
             {
                 "schemas":userSchema,
                 "userType":userType
             }                     
        try:      
            logging("{} has {} cloud recordings.".format(userName,recordings))
        except Exception as e:
            None
        
        put_request(userURL,data,'Set {} to {} license'.format(userName,userType))

def modify_user_scim2(userType, scim2data):
    ## @To Do
    userName = scim2data['displayName']
    userID = scim2data['id']
    userURL = '{}/{}'.format(API_SCIM2_USER,userID)

    
    if userType.lower() == 'basic':
        userType = "Basic"
        #https://api.zoom.us/scim2/Users/{userId}
        data =\
             {
                 "schemas":scim2data["schemas"],
                 "userType":userType
             }                     

    put_request(userURL,data,'Set {} to {}'.format(userName,userType))
    
def delete_users_list(userID, userDesc):
    api = "https://api.zoom.us/v2/users/{}".format(userID)
    
    api = "{}?action=delete".format(api)
    
    
    response = delete_request(api,userDesc)
    
    
def delete_user_scim2(userStatus,userID,userType=""):
    ##@@ToDo
    
    
    
    if userStatus.lower() == 'inactive':
        userURL = '{}/{}'.format(API_SCIM2_USER,userID)
        
        #response = delete_request(userURL,)
        response = requests.get(url=apiType, headers=AUTHORIZATION_HEADER) 
        
        
def get_user_scim2_data(userID):
    logging('Checking SCIM2 Data for {}'.format(userID))
    urn = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
    
    try:
        userURL = '{}/{}'.format(API_SCIM2_USER,userID)
        
        scim2_data = send_request(userURL, sendData = None)
        
        print('SCIM2 Response: {}'.format(scim2_data))
    except Exception as e:
        print('SCIM2 Exception:{}'.format(e))
        
    
    return scim2_data


def put_request(url, data, info = ""):
    response = ""
    try:
        response = requests.put(url, json=data, headers=AUTHORIZATION_HEADER)
        respCode = response.status_code
        logging('{}:  {}'.format(info,respCode))
    except Exception as e:
        logging('Send Put Request {}, {} error:{}'.format(url,info,e))
        
        
def patch_request(url, body="", info = ""):
    response = ""
    try:
        response = requests.patch(url, json=body, headers=AUTHORIZATION_HEADER)
        respCode = response.status_code
        logging(f'{info}:  {respCode}')
    except Exception as e:
        logging('Send patch request {}, {} error:{}'.format(url,info,e))
        
def delete_request(url, info = ""):
    response = ""
    
    
    try:
        response = requests.delete(url=url, headers=AUTHORIZATION_HEADER)
        logging('Deleting {}: {}'.format(info,response))
    except Exception as e:
        logging('Send Delete Request {}, {} error:{}'.format(url,info,e))
        
    
def send_request(apiType, sendData = None):
    response = ""
    print ("Sending GET request for: {}".format(apiType))
    try:
        if sendData == None:
            response = requests.get(url=apiType, headers=AUTHORIZATION_HEADER)
        else:
            api = "{}?".format(apiType)
            ampersand = ""
            for key in sendData:
                if sendData[key] != '' and sendData[key] != None:
                    api = "{}{}{}={}".format(api,ampersand,key,sendData[key])
                    ampersand = "&"          
            
            response = requests.get(url=api, headers=AUTHORIZATION_HEADER)
            
    except Exception as e:
        logging('Send Request {} error:{}'.format(apiType,e))
        
    return response.json()

def get_plan_data(token,accountID):
    
    # https://api.zoom.us/v2/accounts/{accountId}/plans/usage
    None



def check_user_recording_count(userID):
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
            #api = "{}?access_token={}".format(api,jwtToken)
            api = '{}?to={}&from={}&page_size=1'.format(api,monthEnd,monthStart)
            
            
            response = requests.get(url=api, headers=AUTHORIZATION_HEADER)        
            
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
    
def get_user_data(token, groupsDict):
    global progress_var
    global progress
    global root
    global userDB
    global userInactiveDB
    # get total page count, convert to integer, increment by 1
    total_pages = None
    record_count = 0
    pageCount = 0
    page_data = None
    data = None
    print ('Groups:  {}'.format(groupsDict))
    print ('Token:  {}\nAPI_ENDPOINT: {}\nAUTH: {}'.format(token,API_ENDPOINT_USER_LIST,AUTHORIZATION_HEADER))
    
    pageSize = 1
    JSONData = {\
        'status':"",
        'page_size':pageSize,
        'role_id':"",
        'page_number':'0'
        }
    
            

    try:
        page_data = send_request(API_ENDPOINT_USER_LIST,sendData = JSONData)
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
        except:
            print('{}'.format(page_data))
            logging(page_data['message'])
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
        try:
            with open('InactiveZoomUsers.csv', 'w', newline='') as csvfile:
                fieldnames = ['flag','user_id','email','first_name', 'last_name','last_login','months_since','app_ver','group','license']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                                    
                for page in range(0, int(pageCount)):
                    flagUser = ['None','None']
                    startTime[cntTime] = time.time()
                    
                    
                    url = API_ENDPOINT_USER_LIST
                    
                    JSONData = {\
                        'status':"",
                        'page_size':pageSize,
                        'role_id':"",
                        'page_number':str(page)
                    }
                    
                    #logging("Pulling: {}".format(JSONData))
                    
                    try:
                        user_data = send_request(url,sendData = JSONData)
                        
                        #user_data = requests.get(url=url, headers=AUTHORIZATION_HEADER).json()
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
                                try:
                                    delta =  (DATE_CHECK - loginDate).days
                                    #logging("Delta date: {}".format(delta))
                                except:
                                    print('Date Error: {}'.format(e))
                                    
                                    
                                    
                                elapsedTime = relativedelta(todaysDate,UTCdate)
                                userLoginMonths = elapsedTime.months
                                #if userLoginMonths >= MAX_MONTHS:
                            except Exception as e:
                                print ("Error in date-time conversion: {}".format(e))
                            
                            try:
                                if delta >= 0:
                                    try:
                                        flagUser = ['Inactive','Login']
                                    except Exception as e:
                                        logging("Error in flagging: {}".format(e))
                                        
                                    logging("{} has been inactive for {} months: {}".format(userEmail, userLoginMonths))
                                else:
                                    try:
                                        flagUser = ['Active','Login']     
                                    except Exception as e:
                                        logging("Error in flagging: {}".format(e))
                            except Exception as e:
                                print ('No Valid Last Login Data for{}: {}'.format(userEmail,e))
                                flagUser = ['Invalid','Login']
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
                                    userLicense = "None"
                                
                                if userLicense in licenseCnt['total']:
                                    licenseCnt[userLicense] += 1
                                else:
                                    licenseCnt['total'][userLicense] = 1
                                    
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
                                            flagUser = ['Invalid','GroupID']
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
                                flagUser = ['Invalid','Group']
                                userGroup = 'No Group'    
                            
                            try:
                                if userLoginMonths >= MAX_MONTHS:
                                    userInactive = [userID,userLoginMonths, userFirstName, userLastName, userLicense, userEmail]
                                    userInactiveDB.append(userInactive)
                            except Exception as e:
                                logging ("Error with inactive user check process: {}".format(e))
                                    
                                    
                            if flagUser[0] == 'Invalid' or flagUser[0] == 'Inactive':
                                logging("{}:{}: {}".format(flagUser[0],flagUser[1],userEmail))
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

                    root.update_idletasks()
                    
                    #print("Time Remaining: {:.2f}s, {}/{} : {}".format(runAvg,page,total_pages,user_ids))
                # print the contents using zip format.

                    
                logging('Total Flagged Users: {}'.format(flagUserCount))
                
                logging('User Data Pulled:  {}'.format(len(userDB)))
                logging('Users Inactive: {}'.format(len(userInactiveDB)))
                btnDeleteInactive["state"] = "normal"
                btnOpenDelete["state"] = "normal"
                
        except Exception as e:
            logging ('File Write Error, please close file it may be open in Excel\n{}'.format(e))
            data = None
        
    return data

def total_licenses():
    try:
        logging('Total Licenses:')
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
    counter = 0
    value = MAX_NUM
    
    for userData in userInactiveDB:
        if counter >= value and value != 0:
            break
        
        userID = userData[0]
        userEmail = userData[5]
        userName = "{}".format(userEmail)
        userLicense = userData[4]
        logging('Modifying: {}, {} License'.format(userName,userLicense))
        modify_user_license_scim2(userID,userName, userLicense)
        counter += 1

def onListSelect(event):
    # Note here that Tkinter passes an event object to onselect()
    objWidget = event.widget
    idx = int(objWidget.curselection()[0])
    value = objWidget.get(idx)
    print('You selected item {}: {}'.format(idx, value))    

def testdata():
    #Used to validate if recordings is returning appropriate data
    userID = ""
    get_user_scim2_data(userID)
    rec = check_user_recording_count(userID)
    input("Press Enter to continue...")
    print ("Cloud Recording Count Test: {}".format(rec))
    
def callback():
    global listbox
    listbox.delete(0,END)
    zoom_token_auth()
    groupsData = get_group_data()
    #testdata
    
    data = get_user_data(jwtToken, groupsData)


def zoom_token_auth():
    global ACCESS_TOKEN
    global AUTHORIZATION_HEADER    
    global MAX_MONTHS
    global MAX_NUM
    global jwtToken
    global DATE_CHECK
    
    try:
        MAX_MONTHS = int(eMonths.get())
    except:
        MAX_MONTHS = 10
    
    try:
        MAX_NUM = int(eNumber.get())
    except:
        MAX_NUM = 0
    
    try:
        API_KEY = eAPIKey.get()
    except:
        API_KEY = ""
        
    try:
        API_SECRET = eAPISecret.get()
    except:
        API_SECRET = ""
     
     
    jwtToken = JWT_Token(API_KEY,API_SECRET)
    
    try:
        DATE_CHECK = datetime.datetime.strptime(eDate.get(), '%m/%d/%Y').date()
        print ("{}".format(DATE_CHECK))
    except Exception as e:
        logging ("Invalid inactive date")
        DATE_CHECK = "No Date"
    
    logging("Inactive Date:  {}".format(DATE_CHECK))
    
    ACCESS_TOKEN = 'Bearer {}'.format(jwtToken)
    
    print(ACCESS_TOKEN)
    AUTHORIZATION_HEADER = { 'Authorization': ACCESS_TOKEN }
    print(AUTHORIZATION_HEADER)

root = Tk()
root.title('Zoom User Enterprise Scan')
#root.withdraw()

eLbl1 = Label(root, text="API Key")
eLbl1.pack()

eAPIKey = Entry(root)
eAPIKey.pack()

eLbl2 = Label(root, text="API Secret")
eLbl2.pack()

eAPISecret = Entry(root, show='*')
eAPISecret.pack()

#eLbl = Label(root, text="Months since last signin to be Inactive")
#eLbl.pack()
#eMonths = Entry(root)
#eMonths.pack()

eLbl4 = Label(root, text="Date to Be considered inactive user (mm/dd/yyyy)")
eLbl4.pack()
eDate = Entry(root)
eDate.pack()


#eLbl3 = Label(root, text="Number to Relicense (debug)")
#eLbl3.pack()
#eNumber = Entry(root)
#eNumber.pack()


eAPIKey.focus_set()

logData = StringVar(root)
logData.set("Program Started")


separator = Frame(height=2, bd=1, relief=SUNKEN)
separator.pack(fill=X, padx=5, pady=5)

btn = Button(root, text="Retrieve Zoom User Data", width=30, command=callback)
btn.pack()
btnOpen = Button(root, text="Open Existing User Data", width=30, command=csvOpen)
btnOpen.pack()
btnOpenDelete = Button(root, text="Delete Users with Email list file", width=30, command=csvOpenDelete, state=DISABLED)
btnOpenDelete.pack()
btnDeleteInactive = Button(root, text="Relicense All Inactive", width=30, command=Relicense_Inactive, state=DISABLED)
btnDeleteInactive.pack()
#btnDeleteInvalid = Button(root, text="Delete All Invalid Users", width=30, command=callback, state=DISABLED)
#btnDeleteInvalid.pack()
#btnSAMLReorg = Button(root, text="Relicense users based on SAML", width=30, command=callback, state=DISABLED)
#btnSAMLReorg.pack()
#btnOpen = Button(root, text="Save Log", width=30, command=logSave)
#btnOpen.pack()

separator2 = Frame(height=2, bd=1, relief=SUNKEN)
separator2.pack(fill=X, padx=5, pady=5)
eLbl6 = Label(root, text="Options that prevent user deletion:")
eLbl6.pack()
chkRec = IntVar()
chkbxRecordings = Checkbutton(root,text='Check for Cloud Recordings', variable = chkRec)
chkbxRecordings.pack(side=TOP,fill=X)
chkbxRecordings.config(relief=GROOVE, bd=2)
eLbl8 = Label(root, text="No. of months to check for recordings")
eLbl8.pack()
eRecMonths = Entry(root)
eRecMonths.pack()
eRecMonths.delete(0, END)
eRecMonths.insert(0, "6")



eLbl7 = Label(root, text="Months to be considered still active")
eLbl7.pack()
eActiveUser = Entry(root)
eActiveUser.pack()
eActiveUser.delete(0, END)
eActiveUser.insert(0, "0")

separator2 = Frame(height=2, bd=1, relief=SUNKEN)
separator2.pack(fill=X, padx=5, pady=5)

progress_var = DoubleVar() #here you have ints but when calc. %'s usually floats
progress = ttk.Progressbar(root, orient = HORIZONTAL, variable=progress_var, length = 100, mode = 'determinate') 
progress.pack()

listbox = Listbox(root, width=40, name='log')
listbox.bind('<<ListboxSelect>>',onListSelect )
# Adding Listbox to the left 
# side of root window 
listbox.pack(side = LEFT, fill = BOTH, expand=True) 
  
# Creating a Scrollbar and  
# attaching it to root window 
scrollbar = Scrollbar(root) 
  
# Adding Scrollbar to the right 
# side of root window 
scrollbar.pack(side = RIGHT, fill = BOTH) 
# Attaching Listbox to Scrollbar 
# Since we need to have a vertical  
# scroll we use yscrollcommand 
listbox.config(yscrollcommand = scrollbar.set) 
  
# setting scrollbar command parameter  
# to listbox.yview method its yview because 
# we need to have a vertical view 
scrollbar.config(command = listbox.yview) 
mainloop()
