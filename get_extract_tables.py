# --------------------------------------------
# --- Setup libraries and secret variables ---
# --------------------------------------------

import os
import requests
import json
from dotenv import load_dotenv
import binascii
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from base64 import b64decode
import pandas as pd

#Pull in values from secrets
load_dotenv()
UN = os.getenv("USERNAME")
PW = os.getenv("PASSWORD")
server_url = os.getenv("SERVER_URL")
site_id = os.getenv("SITE_ID")

#establish a session so we can retain the cookies

session = requests.Session()

# ---------------------------------------
# --- Get a public key for encryption ---
# ---------------------------------------

#make the generatepublickey function
def generate_public_key() -> dict:
    url = f"{server_url}/vizportal/api/web/v1/generatePublicKey"
    headers = {"Content-Type": "application/json;charset=UTF-8"}
    try:
        response = session.post(url, json={"method": "generatePublicKey", "params": {}}, headers=headers)
        response.raise_for_status()
        response_data = response.json()["result"]
        return {"keyId": response_data["keyId"], "n": response_data["key"]["n"], "e": response_data["key"]["e"]}
    except requests.RequestException as e:
        raise SystemExit(f"Error fetching public key: {e}")


#generate a public key that will be used to encrypt the password
public_key = generate_public_key()
pk = public_key["keyId"]

# ----------------------------
# --- Encrypt our password ---
# ----------------------------

# Encrypt with RSA public key (it's important to use PKCS11)
def asymmetric_encrypt(value: str, public_key: dict) -> bytes:
    modulus_decoded = int(public_key["n"], 16)
    exponent_decoded = int(public_key["e"], 16)
    key_pub = RSA.construct((modulus_decoded, exponent_decoded))
    cipher = PKCS1_v1_5.new(key_pub)
    return cipher.encrypt(value.encode())


#encrypt the password using the key
encryptedPassword = asymmetric_encrypt(PW,public_key)


# ----------------------------------------------
# --- Log into Tableau and get cookie values ---
# ----------------------------------------------


#login to the vizportalAPI using the username, encrypted password and keyid
def vizportal_login(encrypted_password: bytes, key_id: str):
    encoded_password = binascii.b2a_hex(encrypted_password).decode()
    url = f"{server_url}/vizportal/api/web/v1/login"
    headers = {"Content-Type": "application/json;charset=UTF-8"}
    payload = {"method": "login", "params": {"username": UN, "encryptedPassword": encoded_password, "keyId": key_id}}
    response = session.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return response

# Capture the response
login_response = vizportal_login(encryptedPassword, pk)

# Parse the cookie
sc = login_response.headers["Set-Cookie"]

# Step 1: Split on semicolons, then further split on commas
sc_list = [attr.strip() for item in sc.split(";") for attr in item.split(",")]

# Step 2: Process into a dictionary
cookie_dict = {}

for item in sc_list:
    if "=" in item:
        key, value = item.split("=", 1)  # Split only on first '='
        cookie_dict[key.strip()] = value.strip()
    else:
        cookie_dict[item] = True  # Store standalone flags as True


#Parse the cookie
xsrf_token, workgroup_session_id = cookie_dict["XSRF-TOKEN"], cookie_dict["workgroup_session_id"]
#Set the cookies to the parsed values
session.cookies.set("workgroup_session_id",workgroup_session_id)
session.cookies.set("XSRF-TOKEN",xsrf_token)


# ----------------------------------------------
# --- Change from the first site to selected ---
# ----------------------------------------------


# Use the xsrf_token you got from the login response cookie
def switch_site(site_id: str, xsrf_token: str):
    url = f"{server_url}/vizportal/api/web/v1/switchSite"
    headers = {"Content-Type": "application/json;charset=UTF-8", "X-XSRF-TOKEN": xsrf_token}
    payload = {"method": "switchSite", "params": {"urlName": site_id}}
    response = session.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return response


newsite = switch_site(site_id, xsrf_token)

# use the new site cookie
# Parse the cookie
sc = newsite.headers["Set-Cookie"]

# Step 1: Split on semicolons, then further split on commas
sc_list = [attr.strip() for item in sc.split(";") for attr in item.split(",")]

# Step 2: Process into a dictionary
cookie_dict = {}

for item in sc_list:
    if "=" in item:
        key, value = item.split("=", 1)  # Split only on first '='
        cookie_dict[key.strip()] = value.strip()
    else:
        cookie_dict[item] = True  # Store standalone flags as True

#Parse and set the cookies for the new site
xsrf_token, workgroup_session_id = cookie_dict["XSRF-TOKEN"], cookie_dict["workgroup_session_id"]
session.cookies.set("workgroup_session_id",workgroup_session_id)
session.cookies.set("XSRF-TOKEN",xsrf_token)


# -------------------------------------------
# --- Get info on all virtual connections ---
# -------------------------------------------

#Use the XSRF token and get all published virtual connections on the site
def get_published_connections(xsrf_token: str):
    url = f"{server_url}/vizportal/api/web/v1/getPublishedConnections"
    headers = {"Content-Type": "application/json;charset=UTF-8", "X-XSRF-TOKEN": xsrf_token}
    payload = {"method": "getPublishedConnections", "params": {"order": [{"field": "name", "ascending": True}], "page": {"startIndex": 0, "maxItems": 100}}}
    response = session.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()


# Try and get info on all virtual connections
pubvcs = get_published_connections(xsrf_token)

# Pull out all the VC Ids, Names and extract refresh times as a list
vcs_info = [(table["id"],table["name"], table.get("extractsRefreshedAt","N/A")) for table in pubvcs["result"]["publishedConnections"]]

# Convert to a data frame with column names
df = pd.DataFrame(vcs_info, columns=['ID','Name','Extracts_Refreshed_At'])

# Filter to just VCs that have extracts
rl_vcs = df[df['Extracts_Refreshed_At']!= "N/A"]


# -------------------------------------------------------------
# --- Get the table information for all virtual connections ---
# -------------------------------------------------------------

# Use the xsrf_token and get all tables within a specified virtual connection
def get_published_connection(pubc_id: str, xsrf_token: str):
    url = f"{server_url}/vizportal/api/web/v1/getPublishedConnection"
    headers = {"Content-Type": "application/json;charset=UTF-8", "X-XSRF-TOKEN": xsrf_token}
    payload = {"method": "getPublishedConnection", "params": {"id": pubc_id}}
    response = session.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()

#make an empty data frame
temp = []
#Loop through all the VC ids and use them to find the tables within the VCs, appending them to the empty data frame
for row in rl_vcs.itertuples():
    # get the published connection info for the VC ID
    pubtabs = get_published_connection(row.ID, xsrf_token)
    #Pull out as a list the ids, name, has extract and extract refreshed timestamp for every table
    table_info = [(table["id"], table["name"], table["hasExtract"], table.get("extractsRefreshedAt", "N/A")) for table in pubtabs["result"]["tables"]]
    # Turn into a dataframe with column names
    dfnew = pd.DataFrame(table_info, columns=['Table_ID', 'Table_Name', 'Has_Extract', 'Extracts_Refreshed_At'])
    # Insert the Id and Name of the Virtual Connection
    dfnew['VC_ID'] = row.ID
    dfnew['VC_Name'] = row.Name
    # Add to the empty dataframe
    temp.append(dfnew)

# -------------------
# --- Final Clean ---
# -------------------

#Clean up the union  
extract_tables = pd.concat(temp)
#re order columns
extract_tables = extract_tables.loc[:,['VC_ID','VC_Name','Table_ID','Table_Name','Has_Extract','Extracts_Refreshed_At']]
#re-do the index
extract_tables =  extract_tables.reset_index(drop = True)
#Just keep the tables which have an extract
output = extract_tables[extract_tables['Has_Extract']==True]

# -----------------------
# --- Finished Output ---
# -----------------------
print(output)