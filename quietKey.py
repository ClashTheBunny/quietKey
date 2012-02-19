#!/usr/bin/env python

# a quick bash equivilent of most of the things that need to happen, with some PHP
#for foo in $(cat known_hosts | awk '{print $1}'); do echo "<?= base64_encode(hash_hmac('sha1', 'localhost', base64_decode('"$(echo $foo | cut -d \| -f 3)"'),TRUE)); echo \"\n\"; ?>" | php; done | xargs -I{} grep {} known_hosts | awk '{print $3}' | xargs -I{} grep {} known_hosts

import os
import hmac
import hashlib
import binascii

class quietKey(object):
    """This will help you work with your known_hosts file when it is hashed"""
    def __init__(self,known_hosts="~/.ssh/known_hosts"):
        """This reads in all of the keys in your known_hosts"""
        known_hosts=os.path.expanduser(known_hosts)
        fh = open(known_hosts,'rb')
        self.knownHostLines = fh.readlines()
    def findOtherHostsByName(self,hostname):
        self.hostDict = {}
        self.hostKeyDict = {}
        for line in self.knownHostLines:
            lineArray = line.strip().split(" ")
            [ null, null, salt, hashedHost ] = lineArray[0].split("|")
            self.hostDict[hashedHost] = [item for sublist in  [ lineArray, [ salt ], [ hashedHost ] ] for item in sublist]
            if self.hostKeyDict.has_key(lineArray[2]):
                self.hostKeyDict[lineArray[2]] = [item for sublist in  [ self.hostKeyDict[lineArray[2]] , [ ( salt , hashedHost ) ] ] for item in sublist]
            else:
                self.hostKeyDict[lineArray[2]] = [ ( salt , hashedHost ) ]
            mysha1hmac = hmac.new(binascii.a2b_base64( salt ), hostname, hashlib.sha1)
            if binascii.b2a_base64( mysha1hmac.digest() ).strip() == hashedHost:
                host = hashedHost
        print self.hostDict[host]
        print self.hostKeyDict[self.hostDict[host][2]]

if __name__ == '__main__':
    qK = quietKey()
    qK.findOtherHostsByName("g5.mason.ch")
