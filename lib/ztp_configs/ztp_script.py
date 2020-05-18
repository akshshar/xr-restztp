#!/usr/bin/env python

#Test 5
import sys
sys.path.append("/pkg/bin/")
from ztp_helper import ZtpHelpers
import json, tempfile
from pprint import pprint
import json, urllib, urllib2
import subprocess

REST_SERVER_URL="http://192.168.152.30:5000/"

CLONE_NEWNET = 0x40000000

class ZtpFunctions(ZtpHelpers):

    def set_root_user(self):
        # Password is set to "lab" with the config below
        config = """ !
                     username netops
                     group root-lr
                     group cisco-support
                     secret 5 $1$7kTu$zjrgqbgW08vEXsYzUycXw1
                     !
                     end"""



        with tempfile.NamedTemporaryFile(delete=True) as f:
            f.write("%s" % config)
            f.flush()
            f.seek(0)
            result = self.xrapply(f.name)

        if result["status"] == "error":

            self.syslogger.info("Failed to apply root user to system %s"+json.dumps(result))

        return result



    def run_bash(self, cmd=None, vrf="global-vrf", pid=1):
        """User defined method in Child Class
           Wrapper method for basic subprocess.Popen to execute 
           bash commands on IOS-XR in specified vrf (or global-vrf 
           by default).
           :param cmd: bash command to be executed in XR linux shell. 
           :type cmd: str 
           
           :return: Return a dictionary with status and output
                    { 'status': '0 or non-zero', 
                      'output': 'output from bash cmd' }
           :rtype: dict
        """

        with open(self.get_netns_path(nsname=vrf,nspid=pid)) as fd:
            self.setns(fd, CLONE_NEWNET)

            if self.debug:
                self.logger.debug("bash cmd being run: "+cmd)
            if cmd is not None:
                process = subprocess.Popen(cmd, 
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE,
                                           shell=True)
                out, err = process.communicate()
                if self.debug:
                    self.logger.debug("output: "+out)
                    self.logger.debug("error: "+err)
            else:
                self.syslogger.info("No bash command provided")
                return {"status" : 1, "output" : "",
                        "error" : "No bash command provided"}

            status = process.returncode

            return {"status" : status, "output" : out, "error" : err}



    def get_serial_number(self):
        """User defined method in Child Class
           Method to fetch the serial number of the router
           that this script is running on. Can be useful in
           invoking router/device specific URLs to take specific
           action based on the router.
           :return: Returns Serial number of the device (also used
                    by ZTP DHCP requests) on success
                    Returns empty string on failure
           :rtype: str 
        """
        cmd = "dmidecode -s system-serial-number | grep -v -e \"^#\""        
        response = self.run_bash(cmd)
        if not response["status"]:
            self.syslogger.info("Successfully fetched Serial Number:")
            if self.debug:
                self.logger.debug(response["output"])
            return response["output"].strip()
        else:
            self.syslogger.info("Failed to fetch Serial Number:")
            if self.debug:
                self.logger.debug(response["output"])
                self.logger.debug(response["error"])
            return ""


if __name__ == "__main__":

    # Create an Object of the child class, syslog parameters are optional. 
    # If nothing is specified, then logging will happen to local log rotated file.

    ztp_script = ZtpFunctions(syslog_file="/root/ztp_python.log", syslog_server="192.168.152.2", syslog_port=514)

    print "\n###### Debugs enabled ######\n"

    # Enable verbose debugging to stdout/console. By default it is off
    ztp_script.toggle_debug(1)

    # Change context to XR VRF in the linux shell when needed. Depends on when user changes config to create network namespace.

    print "\n###### Change context to user specified VRF ######\n"
    ztp_script.set_vrf("global-vrf")



    # Use the child class methods
    print "\n###### Using Child class method, setting the root user ######\n"
    ztp_script.set_root_user()


    # Disable debugs
    print "\n###### Debugs Disabled ######\n"
    ztp_script.toggle_debug(0)

    # Show commands using Parent class helper method: xrcmd

    print "\n###### Executing a show command ######\n"
    pprint(ztp_script.xrcmd({"exec_cmd" :  "show running-config"}))

    # Set up Crypto rsa keys for SSH access

    show_pubkey = ztp_script.xrcmd({"exec_cmd" : "show crypto key mypubkey rsa"}) 

    if show_pubkey["status"] == "success":
        if show_pubkey["output"] == '':
            ztp_script.syslogger.info("No RSA keys present, Creating...")
            ztp_script.xrcmd({"exec_cmd" : "crypto key generate rsa", "prompt_response" : "2048\\n"})
        else:
            ztp_script.syslogger.info("RSA keys already present, Recreating....")
            ztp_script.xrcmd({"exec_cmd" : "crypto key generate rsa", "prompt_response" : "yes\\n 2048\\n"}) 
    else:
        ztp_script.syslogger.info("Unable to get the status of RSA keys: "+str(show_pubkey["output"]))
        # Not quitting the script because of this failure
   
    # Config apply with string using Parent class helper method: xrapply_string

    print "\n###### Apply valid configuration using a string ######\n"
    out = ztp_script.xrapply_string("domain name-server 171.70.168.183")
    pprint(out)
    
    # Config apply with file using Parent class helper method: xrapply

    print "\n###### Apply valid configuration using a file ######\n"
    config = """ !
                 hostname rtr1
                 !
                 snmp-server community cisco RO
                 ntp
                  server ntp.esl.cisco.com
                 !
                 router static
                  address-family ipv4 unicast
                   0.0.0.0/0 192.168.152.2
                  !
                 !
                 ssh server v2
                 !
                 end"""


    with tempfile.NamedTemporaryFile(delete=True) as f:
        f.write("%s" % config)
        f.flush()
        f.seek(0)
        print ztp_script.xrapply(f.name)




# Determine Final IPv4 address applied to Mgmt port
    try:
        mgmt_config = ztp_script.xrcmd({"exec_cmd" : "show running-config interface MgmtEth0/RP0/CPU0/0"})
        mgmt_ip = mgmt_config['output'][1].split()[2] 
        mgmt_netmask= mgmt_config['output'][1].split()[3] 
        # Convert netmask X.X.X.X format to CIDR format for POST request.
        mgmt_cidr = sum([ bin(int(bits)).count("1") for bits in mgmt_netmask.split(".") ])
    except Exception as e:
        ztp_script.syslogger.info("Failed to fetch Management port configuration, aborting.... Error is "+str(e))
        sys.exit(1)


    # Determine Device Serial Number using helper method in child class

    serial_no = ztp_script.get_serial_number()

    # ZTP configuration done! Send a POST request with information expected by the REST server

    data = json.dumps({
                "serialNumber": serial_no,
                "ZTP_Result": "Success",
                "IPv4_Address": {
                    "ipaddrs": str(mgmt_ip),
                    "mask": int(mgmt_cidr)
                }
        })

    req = urllib2.Request(REST_SERVER_URL, data)
    req.add_header('Content-Type', 'application/json')
    response = urllib2.urlopen(req)
    

    json_response = json.loads(response.read())
    if str(json_response["Result"]) == "Error":
        ztp_script.syslogger.info("Failed to notify ZTP completion to server, will try again. ZTP failed...")
        sys.exit(1)
    elif str(json_response["Result"]) == "Success":
        ztp_script.syslogger.info("Successfully notified server. ZTP complete.")

    sys.exit(0)
