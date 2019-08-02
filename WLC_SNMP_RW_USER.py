#! /usr/bin/env python3
# # -*- coding: utf-8 -*-
"""this is a script"""
__version__ = '0.0.1'
from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto import rfc1902

# USER EDITABLE ITEMS
# Host to send SNMP packet to
host = '192.168.1.6'
# UDP Port to send SNMP packet
port = 161
# SNMP Write Community
writeStr = 'private'
# Username to Create
# You *can* use all spaces...or anything in the ascii table lol ಠ_ಠ
uName = 'svcAccnt'
# User's Password (to be safe use 1 upper, 1 lower, 1 digit or special char)
# Look at default policies below
uPass = 'Pwn3d-hard'
'''
## WLC Default Password Policies ##
Password must contain characters from at least 3 different classes
No character can be repeated more than 3 times consecutively
Password cannot be the default words like cisco, admin
Password cannot contain username or reverse of username
Strong password minimum length - 3
'''
'''OID for pass policy is .1.3.6.1.4.1.9.9.618.1.5 maybe add this later?'''


#
# This function takes the name it's given and returns the decimal equiv
# strung together which the WLC uses for the user's OID value
def name_string(name):
    end_string = ''
    for i, thing in enumerate(name):
        # print(thing)
        end_string += str(ord(thing))
        # print(i)
        if i+1 < len(name):
            end_string += '.'
        # print(ord(thing))
    # end_string = '.' + str(len(name)) +'.' + end_string
    end_string = '.' + end_string
    return end_string


def main():
    # Username length - Used to create oid
    uL = str(len(uName))
    # Name String - Used to create oid
    nS = name_string(uName)
    # SNMP Stuff ### DO NOT CHANGE ###
    base = '1.3.6.1.4.1'
    ent = '.14179'
    dev = '.2.5.11.1.'
    errorIndication, errorStatus, errorIndex, varBinds = cmdgen.CommandGenerator().setCmd(
    cmdgen.CommunityData('my-agent', writeStr, 1),
    cmdgen.UdpTransportTarget((host, port)),
    # create user cmd
    (base+ent+dev+'23.'+uL+nS, rfc1902.Integer(4)),
    # set username
    (base+ent+dev+'1.'+uL+nS, rfc1902.OctetString(uName)),
    # set password
    (base+ent+dev+'2.'+uL+nS, rfc1902.OctetString(uPass)),
    # set read/write (1:ro, 2:rw)
    (base+ent+dev+'3.'+uL+nS, rfc1902.Integer(2)))  # NOQA
    # Check for errors and print out results
    if errorIndication:
        print(errorIndication)
    else:
        if errorStatus:
            print('%s at %s' % (
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex)-1] or '?'
                )
            )
        else:
            for name, val in varBinds:
                print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))


if __name__ == '__main__':
    main()
