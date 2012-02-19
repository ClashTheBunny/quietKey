#!/usr/bin/env python

# a quick bash equivilent of most of the things that need to happen, with some PHP
#for foo in $(cat known_hosts | awk '{print $1}'); do echo "<?= base64_encode(hash_hmac('sha1', 'localhost', base64_decode('"$(echo $foo | cut -d \| -f 3)"'),TRUE)); echo \"\n\"; ?>" | php; done | xargs -I{} grep {} known_hosts | awk '{print $3}' | xargs -I{} grep {} known_hosts

import os, sys
import hmac
import hashlib
import binascii

class quietKey(object):
    """This will help you work with your known_hosts file when it is hashed"""
    def lineToFingerprint(self,base64Key):
        key = binascii.a2b_base64(base64Key)
        fp_plain = hashlib.md5(key).hexdigest()
        return ':'.join(a+b for a,b in zip(fp_plain[::2], fp_plain[1::2]))
    def __init__(self,known_hosts="~/.ssh/known_hosts"):
        """This reads in all of the keys in your known_hosts"""
        known_hosts=os.path.expanduser(known_hosts)
        fh = open(known_hosts,'rb')
        self.knownHostLines = fh.readlines()
    def findOtherHostsByName(self,hostname):
        self.hostDict = {}
        self.hostKeyDict = {}
        self.host = None
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
                self.host = hashedHost

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Help parse hashed known_hosts.')

    generalGroup = parser.add_mutually_exclusive_group(required=True)
    generalGroup.add_argument('--find-other','-f', action="store_true", default=False, help='Find occurances in the hosts file of this host')
    parser.add_argument('hostname', action="store")

    argDict = parser.parse_args(sys.argv[1:])

    if argDict.find_other:
        qK = quietKey()
        qK.findOtherHostsByName(argDict.hostname)
        if qK.host != None:
            print argDict.hostname
            print qK.hostDict[qK.host]
            print qK.hostKeyDict[qK.hostDict[qK.host][2]]
            print qK.lineToFingerprint(qK.hostDict[qK.host][2])
        else:
            print "Couldn't find that host."
