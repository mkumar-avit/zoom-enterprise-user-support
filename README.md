# zoom-enterprise-user-deprovisioning

Standalone Python program that manages deprovisoning or relicensing users in Zoom to basic based on either an email list of users, or their last sign-in date.  It uses the TKinter module to provide a very basic GUI interface.  A code-signed Windows App will be forthcoming, and I may also generate a Mac version once the code moves into a "beta" state.

Users need an API Key and API Secret with admin-level access from a JWT Token App in Zoom's marketplace.  The code will generate the JWT Token. 

The program will retrieve all users in account, check against the specified inactive data, and relicense users to Basic if they still have cloud recordings (if checked in the program) or else delete them if they also haven't been active for the specified number of months.  The program will save the user data to file, so it can be opened by the program again later.

As an option, the email list is just a list of email addresses of users with a header at the top of the csv file (i.e. Emails) that will be used to delete users from Zoom  en masse

Ultimately this is an interim tool for Zoom enterprise/business users that don't have a full user provisioning workflow in place and need to free up licenses.

## Basic Instructions
1. At a minimum you will need to populate the API Key and API Secret pulled from a Zoom JWT app
2. Select "Retrieve All Users" to initiate the building of a local file of all users in Zoom account associated with JWT Token (Excludes subaccounts currently)
3. Most other functionality in app requires step 2 to be completed.

Notes:  If processing of any function takes too long, you can select the "Cancel Action" button.  

## What big feature doesn't work yet
Currently the LDAP feature is not yet functional, but some basic coding for LDAP connectivity and attribute retrieval does exist in the code.

## Bugs:
This is a functional alpha release and will license and delete users from your Zoom account.  There are bugs with re-opening the saved user file generated by the program, but that will be addressed soon.

Backing up user settings can take a long time for large accounts (can be 7 hours).  At this time the program may freeze if between 1000-4000 user settings are backed up.   The CSV file will be generated, and if you want to continue backing up users from where it left off, you can enter the last email address listed in the CSV file under the "Restart Processing" frame.  The issue lies with the use of the TKinter GUI module and certain calls, so multi-threading will be introduced in the future to alleviate the issue.

## Considerations
The program will retrieve a single user in multiple Zoom groups, but at this time any other functionality that processes group information will only look at one group.

## GUI
![Alt text](https://github.com/mkumar-avit/zoom-mass-de-provisioning/blob/master/Zoom%20Zeus.png?raw=true "Current GUI")
![Alt text](https://github.com/mkumar-avit/zoom-mass-de-provisioning/blob/master/Zoom%20Zeus%20log%20config.png?raw=true "user inteface - log configuration settings.")

## Requirements
User can now have a lower resolution to comfortably view the entire program GUI.  Future updates are still being planned for the GUI.


## Files Generated by Program
The program will generate multiple files, based on your choice of actions in the same folder as the program:
- A log file of all the contents of the log window, if the log window is cleared, and new log file will be started
- User Setting Tracking.csv - backup of user settings (can be used to generate pivot tables to see how many users made certain setting changes)
- Zoom Group Setting Tracking.csv - backup of all the groups setting in the account
 -Zoom Retrieved User List.csv - backup of retrieve user data from Zoom, can be used as a basis to generate an update list that can be imported into the Zoom webportal
 
## Button Functionality
###Settings
#### Required Info
##### Open Credentials file
(optional) Open a CSV file that contains the API Key, API Secret, Domain, LDAP Host LDAP Login, and LDAP Password.  This is not a recommended method since this is pulling data from a cleartext source.   May investigate alternatives in the future like LastPass integration.
##### API Key
API Key pulled from Zoom JWT app in Zoom Marketplace.  Will need account-level access (admin user typically or account owner)

##### API Secret
API Secret pulled from Zoom JWT app in Zoom Marketplace.  Will need account-level access (admin user typically or account owner)

##### Email Domain
(optional) Enter your organization's domain, and and entries that are clicked in the log window that contain the domain will automatically populate the User Email field

#### LDAP Configuration
##### LDAP Host
Currently not used
#### LDAP Login
Currently not used
#### LDAP Password
Currently not used

#### Logging Options
####Account Actions
####Actions
#####Retrieve all user data
#####Open all user data
#####Modify/Delete Users via CSV email list file
#####Modify/Delete inactive users to Basic
#####Backup user settings
#####List Zoom user roles

### Options that prevent user updates
#### Change user to Basic (No Deletes)
Checkbox will toggle to allow user deletes (when off), or update user to "Basic" license type (when on).  Button text will update in Action buttons that are applicable
#### Check for Upcoming Meetings
Checkbox will toggle checking if a user has an upcoming scheduled meeting in zoom, and prevent the user from being deleted/updated.   Button text will update in Action buttons that are applicable
### Log Window
#### Cancel Action
Will end any processing that is happening (i.e. retrieving all user Data, backing user settings,..) that may have long processing times.  Any data pulled to the point that the Cancel Action button was triggered will be saved or processed.

#### Clear Log
Will clear contents of log window, and if Save File is enabled will start an new timestamped log file.

#### Progress Bar
Shows progress of any action that has long processing times

#### Log window
This is a list box that contains text of any action the program is performing on Zoom.  The contents will be automatically saved to a log file as it is updated (if that feature is enabled).  Selecting an item in the log window that contains the '@' symbol will populate the user email field below with that value.

#### Log config
This will bring up another window with options for what should be displayed in the log window.

### User Configuration
#### User Email
User email address that is linked to the buttons in the User Configuration frame.  Must first trigger "Retrieve All User Data" button for this to work appropriately

#### Op Log
Button that will pull that last 300 operation log entries and see if there are any entries that match the user email.  Contents will be placed into the log window.

#### Signing Log
Button that will pull the last 300 sign in/sign out log entries and see if there are any entries that match the user email.  Contents will be placed into the log window.

#### Updated Email
If the user has a new email address (perhaps they had a name change), you can update their account to reflect their new email address.  Enter the user's new email address here.

#### Update
Button that will trigger updating the User Email to be changed to the Updated Email (currently this feature does not update the retrieved user data, so you will have to "Retrieve All User Data" again to be able to use the new email with the "User Email" field.

#### Info
Pulls info on User Email including:  number of cloud recordings, difference in settings to the group settings they may be in, last sign in, client version, number of meetings listed in zoom records, Zoom user ID, and a few other items.

#### Log Out
Will revoke the SSO Token for the user and in effect, log them out of all devices they are using Zoom with.

#### Licensed
Will assign user "Licensed" status in Zoom

#### Basic
Will assign user "Basic" status in Zoom

#### Webinar
Toggles to either assign or remove a webinar license for user

#### Large Mtg
Toggles to either assign or remove a Large Meeting license for user

#### Delete
Button to Delete user from Zoom account (enabled when the checkbox "Change user to Basic (No Deletes)" is disabled) 
