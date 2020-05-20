#!/usr/bin/env python3


from flask import Flask, request, jsonify
from flask_restful import Resource, Api
import threading, json
from queue import Queue
import sys

import requests, pdb
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import pathlib
absPathScript = pathlib.Path(__file__).parent.absolute()


with open(str(absPathScript)+"/config.json") as config_json:
    ConfigJson = json.load(config_json)

Config = ConfigJson["config"]
SN_WhiteList = []
for device in Config["ztpDevices"]:
    SN_WhiteList.append(device["serialNumber"])


CWUser = Config["cwUser"]
CWPswd = Config["cwPswd"]
ServerURL = Config["serverURL"]
CWUrl = ServerURL+'crosswork/'


app = Flask(__name__)
api = Api(app)


class ZtpHook(Resource):
    def get(self):
            description = { "Description": "This is a ZTPHook Server" }
            kv_pairs = { "serialNumber" : "<>",
                         "ZTP_Result" : "Error/Success",
                         "IPv4_Address":  
                              {
                                  "ipaddrs": "<>",
                                  "mask": "<>"
                              }
                        }

            instruction = {  
                         "Issue a POST Request with Data:" : kv_pairs}

            message = {}
            message.update(description)
            message.update({"Usage": instruction})
                   
            print(message)
            return jsonify(message)

    def post(self):
        try:
            posted_data = request.json
            if posted_data["serialNumber"] in SN_WhiteList:
                if posted_data["ZTP_Result"] == "Success":
                    app.config["eventq"].put(posted_data)
                    SN_WhiteList.remove(posted_data["serialNumber"])
                    if not SN_WhiteList:
                        print("\nAll devices in SN_WhiteList onboarded, wrapping up....")
                        app.config["eventq"].put("quit")
                message = {"Result": "Success",
                           "msg" : "Device onboarding initiated"}

            else:
                print("\nDevice not in Serial Number Whitelist")
                message = {"Result": "Error",
                           "msg" : "Device not in Serial Number Whitelist"}

        except Exception as e:
            print("\nFailed to handle POST request. Error is "+str(e))
        
            message = {"Result": "Error",
                       "msg" : "Failed to handle request. Error is "+str(e)}


        return jsonify(message)

api.add_resource(ZtpHook, '/')


if __name__ == "__main__":

    eventQ = Queue()
    app.config["eventq"] = eventQ #ztp_event
    eventThread = threading.Thread(target=app.run, kwargs=dict(debug=True, use_reloader=False, host='0.0.0.0', port=5000))
    eventThread.daemon = True
    eventThread.start()


    for ztpDevice in Config["ztpDevices"]:

        SerialNumber = ztpDevice['serialNumber']
        ZtpScriptConfigName = ztpDevice["ztpScriptConfigName"]
        ZtpScriptConfigFile= ztpDevice["ztpScriptConfigFile"]
        config_uuid= ztpDevice["ztpScriptConfigUUID"]
        OSName = ztpDevice["osName"]
        OSVersion = ztpDevice["osVersion"]
        ImageTitle = ztpDevice["imageTitle"]
        DeviceFamily= ztpDevice["deviceFamily"]
        ZtpProfile = ztpDevice["ztpProfile"]
        ZTPCredentialProfile = ztpDevice["ztpCredentialProfile"]
        Device = ztpDevice["device"]
   
        # Get authorization ticket using admin username/password

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'text/plain',
            
        }

        params = (
            ('username', CWUser),
            ('password', CWPswd),
        )


        response = requests.post(str(CWUrl)+'sso/v1/tickets', headers=headers, params=params, verify=False)

        if response.status_code == 201:
            ticket = response.text
        else:
            print("\nFailed to obtain Ticket from Crosswork, aborting....")
            sys.exit(1)


        # Fetch time limited authentication token based on Ticket obtained

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        data= 'service='+ ServerURL + 'app-dashboard'

        response = requests.post(str(CWUrl)+"sso/v1/tickets/"+str(ticket), data=data, headers=headers, verify=False)
        if response.status_code == 200:
            token = response.text
        else:
            print("\nFailed to obtain token for current session, aborting....")
            sys.exit(1)



        # Now, utilizing the token,  fetch already uploaded images and their IDs
        headers = {
            'Content-Type': 'application/vnd.yang.data+json',
            'Authorization': 'Bearer '+str(token)
        }

        response = requests.get(str(CWUrl)+'imagesvc/v1/images', headers=headers, verify=False)
        
        if response.status_code == 200:
            image_content = response.text
        else:
            print("\nFailed to obtain images on the server, aborting....")
            sys.exit(1)

        for image in json.loads(image_content)['content']:
            if image['imageTitle'] == ImageTitle:
                image_uuid = image['id']


        # Create Configuration and upload before creating ZTP profile
        headers1 = {
            'Authorization': 'Bearer '+str(token)
        }

        params = (
            ('confname', ZtpScriptConfigName),
            ('osname', OSName),
            ('version', OSVersion),
            ('devicefamily', DeviceFamily),
        )
        

        # Now set up update request

        with open(ZtpScriptConfigFile, 'rb') as config_file:
            response = requests.put(str(CWUrl)+'configsvc/v1/configs/'+str(config_uuid), headers=headers1, files={"configFile" : config_file},  params=params, verify=False)

        
        if response.status_code == 200:
            print("\nConfiguration successfully updated")
        elif response.status_code == 404:
            print("\nFailed to update configuration, config uuid does not exist, creating a new one...")

            with open(ZtpScriptConfigFile, 'rb') as config_file:
                response = requests.post(str(CWUrl)+'configsvc/v1/configs/upload', headers=headers1, files={"configFile" : config_file},  params=params, verify=False)

            if response.status_code == 201:
                print("\nConfiguration successfully uploaded.")
                config_uuid = json.loads(response.text)["confId"]
                print("\nNew config ID is "+str(config_uuid)+" . Please update DHCP servers to reflect new URL.")
            else:
                print("\nFailed to update or upload  configuration to server, aborting....")
                print(response.content)
                sys.exit(1)

                # # Fetch the Configurations uploaded to view and extract Config ID
                # headers = {
                #     'Content-Type': 'application/vnd.yang.data+json',
                #     'Authorization': 'Bearer '+str(token)
                # }

                # response = requests.get(str(CWUrl)+'configsvc/v1/configs/', headers=headers, verify=False)

                # if response.status_code == 200:
                #     config_content = response.text
                # else:
                #     print("Failed to obtain config files on the server, aborting....")
                #     sys.exit(1)
                
                # for config in json.loads(config_content)['content']:
                #     if config['confName'] == ZtpScriptConfigName:
                #         config_uuid = config['confId']
        else:
             print("\nFailed to update configuration.")
             print(response.content)
             sys.exit(1)
        # Create ZTP profile using Image and Config IDs determined


        headers = {
            'Content-Type': 'text/plain',
            'Authorization': 'Bearer '+str(token)
        }

        ZtpProfile['config'] = config_uuid
        ZtpProfile['image'] = image_uuid
        data = { 'profiles' : [ZtpProfile]}

        response = requests.post(str(CWUrl)+'ztp/v1/profiles', headers=headers, data=json.dumps(data), verify=False)


        if json.loads(response.text)["code"] is 201:
            print("\nProfile Created successfully")
        else:
            print("\nFailed to create ZTP profile, might cause issues later...")
        
        # Create Credential Profile for the Device to be added

        headers = {
            'Content-Type': 'text/plain',
            'Authorization': 'Bearer '+str(token)
        }

        data = {"data": [ZTPCredentialProfile ], "user": "admin"}

        response = requests.post(str(CWUrl)+'inventory/v1/credentials', headers=headers, data=json.dumps(data), verify=False)

        if response.status_code is 200:
            print("\nZTP Credential Profile Created successfully")
        else:
            print("\nFailed to create ZTP credential profile, aborting....")



        # Add Device to ZTP Device list using the created ZTP Profile and Credential Profiles


        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer '+str(token)
        }

        #Device["image"] = image_uuid
        #Device["config"] = config_uuid
        #Device["version"] = OSVersion
        Device["serialNumber"] = SerialNumber
        Device["profileName"] = ZtpProfile["profileName"]


        data = {"nodes": [Device]}
        response = requests.post(str(CWUrl)+'ztp/v1/devices', headers=headers, data=json.dumps(data), verify=False)

        if response.status_code == 200:
            print("\nDevice Added successfully")
        else:
            print("\nFailed to Add ZTP Device, aborting....")




        # Pre-Fetch CDG Info, will use post ZTP provisioning

        headers = {
            'Content-Type': 'text/plain',
            'Authorization': 'Bearer '+str(token)
        }
        data = {"limit": 100, "filter": {}}
        response = requests.post(str(CWUrl)+'inventory/v1/dg/query', headers=headers, data=json.dumps(data), verify=False) 
       
        if response.status_code is 200:
            cdg_duuid = json.loads(response.text)["data"][0]["duuid"]
        else:
            print("\nFailed to Fetch CDG info, aborting")
            sys.exit(1)

        # Initiate ZTP (Device reload or new device powered on or ZTP initiate)
        # Look for event from device to running server


    while True:
        try:
            ztpsuccess_data = eventQ.get()
            if ztpsuccess_data == "quit":
                break
            else:
                ztpsuccess_sn = ztpsuccess_data["serialNumber"]

            headers = {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer '+str(token)
            }

   
            # ZTP was successful, set ZTP device status to "Provisioned"
            data =  { 
                      "serialNumber": ztpsuccess_sn,
                      "status": "Provisioned",
                      "ipAddress": {
                          "inetAddressFamily": "IPV4",
                          "ipaddrs": ztpsuccess_data["IPv4_Address"]["ipaddrs"],
                          "mask": int(ztpsuccess_data["IPv4_Address"]["mask"])
                        }
                    }

            response = requests.patch(str(CWUrl)+'ztp/v1/deviceinfo/status', headers=headers, data=json.dumps(data), verify=False)
            if response.status_code is 200:
                print("\nDevice with Serial-Number: "+ str(ztpsuccess_sn)+ " successfully Provisioned using ZTP. Now, proceeding to onboard for Day1+ Change Management...")
            else:
                print("\nFailed to update ZTP device state to provisioned, aborting for this device...")
                continue

            # Device onboarded with ZTP, now attach to CDG to continue onboarding for Day 1 change management
            # First determine the auto-generated device uuid for Change manangement post ZTP

            headers = {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer '+str(token)
            }

            data =  { 
                        "limit": 100,
                        "filter": {
                            "serial_number": ztpsuccess_sn
                        },
                        "filterData": {}
                    }

            response = requests.post(str(CWUrl)+'inventory/v1/nodes/query', headers=headers, data=json.dumps(data), verify=False)

            if response.status_code is 200:
                cdg_device_uuid = json.loads(response.text)["data"][0]["uuid"]
            else:
                print("\nFailed to fetch device uuid for cdg attachment, aborting for this device...")
                continue


            headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer '+str(token)
            }

            data = { "dgDeviceMappings": 
                        [ 
                            { 
                                "cdg_duuid": cdg_duuid,  
                                "device_uuid": 
                                    [
                                        cdg_device_uuid
                                    ],
                                "mapping_oper": "ADD_OPER"
                            }
                        ]
                    }

            response = requests.put(str(CWUrl)+'inventory/v1/dg/devicemapping', headers=headers, data=json.dumps(data), verify=False)
            if response.status_code is 200:
                print("\nDevice with Serial-Number: "+ str(ztpsuccess_sn)+ " successfully onboarded for Day 1+ Change Management Workflows.")
            else:
                print("\nFailed to attach device to CDG, might require intervention to complete onboarding...")
                continue

        except Exception as e:
            print("\nFailed to read from Event Queue, Error is "+str(e))


        
