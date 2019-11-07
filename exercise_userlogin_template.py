#!/usr/bin/python2.7

"""
Requirements:
0. Parse the provided `users_legacy.csv`
1. Complete the `login_user(...)` function so that:
  a. If a user provides valid credentials then copy their record to the SQLite file `users.db` and log them in.
  b. If the user does not exist, create a new record in `user.db` and log them in.

Create any additional classes and functions as needed, the final solution is not limited to stubs provided.

Bonus:
1. Require a more complex password for new users
2. Store new passwords as salted hash
3. Make forward compatible with Python3
"""

import csv
import sqlite3
import pandas as pd
import hashlib
import binascii
import os

LEGACY_USER_DB_FILE = 'users_legacy.csv'
CURRENT_USER_DB_FILE = 'users.db'


class User:
    """
    Simple class so we have concrete properties for user data.
    """
    # -- Complete this class --
    def __init__(self,userId, email, phone):
        self.id = userId
        self.email = email
        self.phone = phone

def send_email(recipient_email_address, body_html):
    """
    Accepts an email address and html body for the message. Only a placeholder function, nothing more needed. 
    """
    pass
    

def login_user(email, password, phone=None):
    """
    Entry point for all user login and signup requirements.
    
    Returns:
    1. If the email exists and the password is correct, return a tuple of True and the existing row data.
    2. If the email exists and the password is incorrect, return a tuple of False and an error message.
    3. If the email doesn't already exist but the password is fewer than 7 characters, return a tuple of False and an
        error message indicating why.
    4. If the email doesn't already exist and password is acceptable, add the new user data to users.db.
       Then send an email notifying the new user using the existing `send_email(...)` function. Then return a tuple
       of True and the new record.
    """
    # -- Complete this function --
    if email is None:
        return (False, "Email field cannot be empty.")
    if password is None:
        return (False, "Password field cannot be empty.")
    conn = sqlite3.connect(CURRENT_USER_DB_FILE)
    cursor = conn.cursor()
    try:
        query = "SELECT * FROM USERS WHERE email = '{emailV}';".format(emailV = email)
        cursor.execute(query)
        result = cursor.fetchone()
        if result is None or len(result) == 0:

            if check_password_strength(password) == False:
                return(False, "Password must be at least 7 characters long")
 
            insertRes = create_user(email, password, phone)
            if insertRes[0]:
                email_body = '''Dear User,
                Your account has been created successfully.                 
                '''
                send_email(email, email_body)
                login_user(email, password)
            else:
                return (False, "Failed Creating New User. Try again.")
        else:
            saved_password = result[2]
            if verify_password(saved_password, password):
                if phone is not None and phone != result[3]:
                    updateRes = update_user(conn, email, password, phone)
                    if updateRes:
                        login_user(email, password)                        
                user_obj = User(result[0],result[1],result[3]) 
                return (True, user_obj)
            else:
                return (False, "Invalid Password")            
        cursor.close()
        conn.commit()        
    except Exception as e:
        print(e)
        return (False, "Login Failed. Try again")
    finally:        
        conn.close()

"""
Create New User Record into Database
""" 
def create_user(email, password, phone):
    conn1 = sqlite3.connect(CURRENT_USER_DB_FILE)
    cursor1 = conn1.cursor()
    try:
        hashed_password = hash_password(password)
        query = "INSERT INTO USERS (email, password, phone) VALUES ('{emailV}', '{passV}', '{phoneV}');".format(emailV=email, passV= hashed_password, phoneV= phone)
        cursor1.execute(query)        
        conn1.commit()
        return (True, cursor1.lastrowid)
    except Exception as e:
        print(e)
        print("Failed Creating New User. Try again.")
        return (False, "Failed Creating New User. Try again.")
    finally:
        cursor1.close()
        conn1.close()


"""
Update User Record into Database
""" 
def update_user(conn, email, password, phone):
    cursor1 = conn.cursor()
    try:
        hashed_password = hash_password(password)
        "UPDATE ExampleTable SET Age = 18 WHERE Age = 17"
        query = "UPDATE USERS SET phone = '{phoneV}' WHERE email = '{emailV}' AND password = '{passV}';".format(emailV=email, passV= hashed_password, phoneV= phone)
        cursor1.execute(query)
        cursor1.close()
        conn.commit()
        return True
    except Exception as e:
        print(e)
        print("Failed Creating New User. Try again.")
        return False


"""
Check if provided password meets requirement
""" 
def check_password_strength(password):
    print("Checking Password Strength")
    if password is None or len(password) < 7:
        return False
    else:
        return True
"""
Hash a password for storing.
"""
def hash_password(password):    
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), 
                                salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')

"""
Verify a stored password against one provided by user
""" 
def verify_password(stored_password, provided_password):
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512', 
                                  provided_password.encode('utf-8'), 
                                  salt.encode('ascii'), 
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password 
    
def delete_all_rows():
    conn2 = sqlite3.connect(CURRENT_USER_DB_FILE)
    cursor2 = conn2.cursor()
    try:
        cursor2.execute("DELETE FROM USERS;")
        cursor2.close()
        conn2.commit()
    except Exception as e:
        print("Error deleting all rows")
        print(e)
    finally:
        conn2.close()

def upload_legacy_data():
    try:
        with open(LEGACY_USER_DB_FILE, 'r' ) as f:
            reader = csv.DictReader(f)
            for line in reader:
                email_val = line['EMAIL']
                password_val = line['PASSWORD']
                phone_val = line['PHONE']
                
                insertRes = create_user(email_val, password_val, phone_val)
                if insertRes == False:
                    return (False, "Error Uploading Legacy Data")
            return (True, "Legacy Data Uploaded Successfully")
    except Exception as e:
        print("Error Uploading Legacy Data")
        print(e)
        return (False, "Error Uploading Legacy Data")
            
def run_tests():

    print (login_user("katie@example.com", "katie's,password"))  # Should successfully log in and be migrated
    
    print (login_user("john@example.com", "1234567"))  # Incorrect password

    print (login_user("jack@example.com", "gfru,843//", "555-555-5555"))  # User does not exist, should be created
    
    print (login_user("jim@example.com", "123$bc", "555-555-5555"))  # User does not exist, but new password too short.


if __name__ == "__main__":
    """
    Modify this as needed, but must include the `run_tests()` function
    """
    #upload_legacy_data()
    run_tests()
    #delete_all_rows()


