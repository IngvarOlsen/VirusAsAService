# Faux virus programme to feign authentic malicious activity for
# Adjustable settings by and for a client

import os
import sys
import subprocess
import schedule
import time
import winreg
from math import floor

CMD = ['group', 'user', 'localgroup', 'user /domain']
CLIENT_DATA = []
#CLIENT_DATA.append(os.uname()[1])

# NET.exe recon imitation functionality
def net_exe():
    print("Executing NET.exe recon")

    for i in CMD:
        print("running : net {}".format(i))
        command = "net {}".format(i)
        subprocess.run(['powershell', command], shell=True)
    
    print(os.uname())

# Registry memory edit functionality
def register_edits():
    print("Executing registry edit")

    location_access = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)

    access_key = winreg.OpenKey(location_access, r"SOFTWARE\Microsoft\Windows\CurrentVersion")

    for i in range(10):
        try:
            value = winreg.EnumKey(access_key, i)
            print(value)
        except:
            break

    print("Successfully exiting registry edit sequence...")
    #print(os.uname())

# Scheduled tasks functionality
def secheduled_tasks():
    print("Executing scheduled tasks")

    start = time.time()
    calc = 0

    subprocess.Popen(['notepad','text.txt'])

    while True:
        time.sleep(1)
        current = time.time()
        #print("time 1: {}, time 2: {}".format(start, current))
        calc = round(float(format(current - start, '.2f')))
        #print("time difference : {}".format(calc))
        if calc < 5:
            continue
        else:
            break

    print("Scheduled task timeframe execution : {}".format(calc))
    print("Succesfully exiting sechuled task sequence...")
    #print(os.uname())

# dll sideloading functionality
def dll_sideloading():
    print("Executing DLL sideloading")

def post_test_autoremoval():
    print("Removing test virus")
    current_path = os.getcwd()
    print(current_path)

    #os.remove(current_path+"%s" % sys.argv[0])

if __name__ == "__main__":
    while True:
        print("select one of the following options:")
        print("1 : net recon")
        print("2 : registry edits")
        print("3 : scheduled task")
        print("4 : dll sideloading")
        test = input('please input an option:')
        if len(test) == 1:
            option = int(test)
            match option:
                case 1:
                    net_exe()
                case 2:
                    register_edits()
                case 3:
                    secheduled_tasks()
                case 4:
                    dll_sideloading()
                case 0:
                    post_test_removal()
                    sys.exit(0)
        else:
            print("invalid input")