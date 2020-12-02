import base64
import json
import requests
from requests.exceptions import HTTPError
import sys
import pathlib
import time
import argparse


parser = argparse.ArgumentParser(description = "Provide Inputs for Malware Hash Check")
parser.add_argument('-f','--file', metavar='', required = True, help='Txt File with Hashes seperated by Spaces')
parser.add_argument('-i','--id', metavar='', required = True, help='API Key(ID) of length 36')
parser.add_argument('-p','--password', metavar='', required = True, help='API Password of length 36')
args = parser.parse_args()


base_url = 'https://api.xforce.ibmcloud.com/malware'

def basic_auth():
    username = args.id
    if(len(username)!= 36):
        sys.exit("Invalid API Key! Please check your key/ Enter a valid Key.")
    print("\n")
    password = args.password
    if(len(password)!= 36):
        sys.exit("Invalid API Password! Please check your Password/ Enter a valid Password.")
    print("\n")

    credentials = (username + ':' + password).encode('utf-8')
    base64_encoded_credentials = base64.b64encode(credentials).decode('utf-8')

    headers = {
        'Authorization': 'Basic ' + base64_encoded_credentials
    }
    return headers

def req(header, c):
    open('High.txt', 'w').close()
    open('Low.txt', 'w').close()
    open('Not Found.txt', 'w').close()
    for i in c:
        try:
            response = requests.get(base_url + '/' + i, headers=header)
            r=response.json()
            t = str(r["malware"]["type"])
            if((r["malware"]["risk"]) == 'high'):
                T = r["malware"]["origins"]["external"]["malwareType"]
                fam= r["malware"]["origins"]["external"]["family"][0]
                with open('High.txt', 'a') as g1:
                    g1.write("Hash Type:"+t+" --- "+"Hash Value:"+i+" --- "+"Malware Type:"+T+" --- "+"Malware Family:"+fam+"\n")
            elif((r["malware"]["risk"]) == 'low'):
                with open('Low.txt', 'a') as g2:
                    g2.write("Hash Type:"+t+" --- "+"Hash Value:"+i+"\n")
            else:
                with open('Not Found.txt', 'a') as g3:
                    g3.write("%s\n" % i)    
        except HTTPError as http_err:
            print(f'HTTP error occurred: {http_err}')
        except:
            with open('Not Found.txt', 'a') as g4:
                    g4.write("%s\n" % i)
        #print('Status:', response.status_code)
        #print('Body:', r.content.decode("utf-8"))
        #print (json.dumps(response.json(), indent=4, sort_keys=True))

def main():
    h=basic_auth()
    f=args.file
    Infile = pathlib.Path(str(f))
    if Infile.exists():
        print("\n")
        file = open(f,'r')
        content = file.read()
        content_list=content.split()
        #print (content_list) 
        file.close()
        start = time.time()
        req(h, content_list)
        end = time.time()
        print(end - start)
    else: 
        sys.exit("Please enter a Valid File name/ Check if the File Exixts!! ")
    


if __name__ == "__main__":
    main()    
    