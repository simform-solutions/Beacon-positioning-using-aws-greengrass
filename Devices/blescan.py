

DEBUG = False

import kalman
import os
import sys
import struct
import bluetooth._bluetooth as bluez
import math
from datetime import *
import time
import uuid
import json
import logging
import argparse
from AWSIoTPythonSDK.core.greengrass.discovery.providers import DiscoveryInfoProvider
from AWSIoTPythonSDK.core.protocol.connection.cores import ProgressiveBackOffCore
from AWSIoTPythonSDK.MQTTLib import AWSIoTMQTTClient
from AWSIoTPythonSDK.exception.AWSIoTExceptions import DiscoveryInvalidRequestException

LE_META_EVENT = 0x3e
LE_PUBLIC_ADDRESS=0x00
LE_RANDOM_ADDRESS=0x01
LE_SET_SCAN_PARAMETERS_CP_SIZE=7
OGF_LE_CTL=0x08
OCF_LE_SET_SCAN_PARAMETERS=0x000B
OCF_LE_SET_SCAN_ENABLE=0x000C
OCF_LE_CREATE_CONN=0x000D

LE_ROLE_MASTER = 0x00
LE_ROLE_SLAVE = 0x01

# these are actually subevents of LE_META_EVENT
EVT_LE_CONN_COMPLETE=0x01
EVT_LE_ADVERTISING_REPORT=0x02
EVT_LE_CONN_UPDATE_COMPLETE=0x03
EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE=0x04

# Advertisment event types
ADV_IND=0x00
ADV_DIRECT_IND=0x01
ADV_SCAN_IND=0x02
ADV_NONCONN_IND=0x03
ADV_SCAN_RSP=0x04


def returnnumberpacket(pkt):
    myInteger = 0
    multiple = 256
    for c in pkt:
        myInteger +=  struct.unpack("B",c)[0] * multiple
        multiple = 1
    return myInteger 

def returnstringpacket(pkt):
    myString = "";
    for c in pkt:
        myString +=  "%02x" %struct.unpack("B",c)[0]
    return myString 

def printpacket(pkt):
    for c in pkt:
        sys.stdout.write("%02x " % struct.unpack("B",c)[0])

def get_packed_bdaddr(bdaddr_string):
    packable_addr = []
    addr = bdaddr_string.split(':')
    addr.reverse()
    for b in addr: 
        packable_addr.append(int(b, 16))
    return struct.pack("<BBBBBB", *packable_addr)

def packed_bdaddr_to_string(bdaddr_packed):
    return ':'.join('%02x'%i for i in struct.unpack("<BBBBBB", bdaddr_packed[::-1]))

def hci_enable_le_scan(sock):
    hci_toggle_le_scan(sock, 0x01)

def hci_disable_le_scan(sock):
    hci_toggle_le_scan(sock, 0x00)

def hci_toggle_le_scan(sock, enable):
    cmd_pkt = struct.pack("<BB", enable, 0x00)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, cmd_pkt)


def hci_le_set_scan_parameters(sock):
    old_filter = sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)

    SCAN_RANDOM = 0x01
    OWN_TYPE = SCAN_RANDOM
    SCAN_TYPE = 0x01

def le_handle_connection_complete(pkt):
    status, handle, role, peer_bdaddr_type = struct.unpack("<BHBB", pkt[0:5])
    device_address = packed_bdaddr_to_string(pkt[5:11])
    interval, latency, supervision_timeout, master_clock_accuracy = struct.unpack("<HHHB", pkt[11:])

def awsgreengrass_connect(distance):
    distance = distance
    
    AllowedActions = ['both', 'publish', 'subscribe']

# General message notification callback
    def customOnMessage(message):
         print('Received message on topic %s: %s\n' % (message.topic, message.payload))

    MAX_DISCOVERY_RETRIES = 10
    GROUP_CA_PATH = "./groupCA/"

    host = "a3drj1nn7u6229.iot.us-east-1.amazonaws.com"
    rootCAPath = "root-ca-cert.pem"
    certificatePath = "62f5a3886d.cert.pem"
    privateKeyPath = "62f5a3886d.private.key"
    clientId = "rpi4"
    thingName = "rpi4"
    topic = "hello/world/send"
    mode = "publish"
    if mode not in AllowedActions:
        parser.error("Unknown --mode option %s. Must be one of %s" % (mode, str(AllowedActions)))
        exit(2)

    if not certificatePath or not privateKeyPath:
        parser.error("Missing credentials for authentication.")
        exit(2)

    # Configure logging
    logger = logging.getLogger("AWSIoTPythonSDK.core")
    logger.setLevel(logging.DEBUG)
    streamHandler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    streamHandler.setFormatter(formatter)
    logger.addHandler(streamHandler)

    # Progressive back off core
    backOffCore = ProgressiveBackOffCore()

    # Discover GGCs
    discoveryInfoProvider = DiscoveryInfoProvider()
    discoveryInfoProvider.configureEndpoint(host)
    discoveryInfoProvider.configureCredentials(rootCAPath, certificatePath, privateKeyPath)
    discoveryInfoProvider.configureTimeout(10)  # 10 sec

    retryCount = MAX_DISCOVERY_RETRIES
    discovered = False
    groupCA = None
    coreInfo = None
    while retryCount != 0:
        try:
            discoveryInfo = discoveryInfoProvider.discover(thingName)
            caList = discoveryInfo.getAllCas()
            coreList = discoveryInfo.getAllCores()

            # We only pick the first ca and core info
            groupId, ca = caList[0]
            coreInfo = coreList[0]
            print("Discovered GGC: %s from Group: %s" % (coreInfo.coreThingArn, groupId))

            print("Now we persist the connectivity/identity information...")
            groupCA = GROUP_CA_PATH + groupId + "_CA_" + str(uuid.uuid4()) + ".crt"
            if not os.path.exists(GROUP_CA_PATH):
                os.makedirs(GROUP_CA_PATH)
            groupCAFile = open(groupCA, "w")
            groupCAFile.write(ca)
            groupCAFile.close()

            discovered = True
            print("Now proceed to the connecting flow...")
            break
        except DiscoveryInvalidRequestException as e:
            print("Invalid discovery request detected!")
            print("Type: %s" % str(type(e)))
            print("Error message: %s" % e.message)
            print("Stopping...")
            break
        except BaseException as e:
            print("Error in discovery!")
            print("Type: %s" % str(type(e)))
            print("Error message: %s" % e.message)
            retryCount -= 1
            print("\n%d/%d retries left\n" % (retryCount, MAX_DISCOVERY_RETRIES))
            print("Backing off...\n")
            backOffCore.backOff()

    if not discovered:
        print("Discovery failed after %d retries. Exiting...\n" % (MAX_DISCOVERY_RETRIES))
        sys.exit(-1)

    # Iterate through all connection options for the core and use the first successful one
    myAWSIoTMQTTClient = AWSIoTMQTTClient(clientId)
    myAWSIoTMQTTClient.configureCredentials(groupCA, privateKeyPath, certificatePath)
    myAWSIoTMQTTClient.onMessage = customOnMessage

    connected = False
    for connectivityInfo in coreInfo.connectivityInfoList:
        currentHost = connectivityInfo.host
        currentPort = connectivityInfo.port
        print("Trying to connect to core at %s:%d" % (currentHost, currentPort))
        myAWSIoTMQTTClient.configureEndpoint(currentHost, currentPort)
        try:
            myAWSIoTMQTTClient.connect()
            connected = True
            break
        except BaseException as e:
            print("Error in connect!")
            print("Type: %s" % str(type(e)))
            print("Error message: %s" % e.message)

    if not connected:
        print("Cannot connect to core %s. Exiting..." % coreInfo.coreThingArn)
        sys.exit(-2)

    # Successfully connected to the core
    if mode == 'both' or mode == 'subscribe':
        myAWSIoTMQTTClient.subscribe(topic, 0, None)
    time.sleep(2)
    if mode == 'both' or mode == 'publish':
        # publish distance over greengrass 
        message = {}
        message['message'] = "rpi4"
        message['distance4'] = distance
        messageJson = json.dumps(message)
        myAWSIoTMQTTClient.publish(topic, messageJson, 0)
        if mode == 'publish':
            print('Published topic %s: %s\n' % (topic, messageJson))
                                
    time.sleep(2)
    
    
def parse_events(sock, loop_count=100):
    old_filter = sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)
    mode = "publish"
    # perform a device inquiry on bluetooth device #0
    # The inquiry should last 8 * 1.28 = 10.24 seconds
    # before the inquiry is performed, bluez should flush its cache of
    # previously discovered devices
    flt = bluez.hci_filter_new()
    bluez.hci_filter_all_events(flt)
    bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, flt )
    done = False
    results = []
    myFullList = []
    for i in range(0, loop_count):
        pkt = sock.recv(255)
        ptype, event, plen = struct.unpack("BBB", pkt[:3])
        #print "--------------" 
        if event == bluez.EVT_INQUIRY_RESULT_WITH_RSSI:
                i =0
        elif event == bluez.EVT_NUM_COMP_PKTS:
                i =0 
        elif event == bluez.EVT_DISCONN_COMPLETE:
                i =0 
        elif event == LE_META_EVENT:
            subevent, = struct.unpack("B", pkt[3])
            pkt = pkt[4:]
            if subevent == EVT_LE_CONN_COMPLETE:
                le_handle_connection_complete(pkt)
            elif subevent == EVT_LE_ADVERTISING_REPORT:
                #print "advertising report"
                num_reports = struct.unpack("B", pkt[0])[0]
                report_pkt_offset = 0
                for i in range(0, num_reports):
                
                    if (DEBUG == True):
                        print "-------------"
                        #print "\tfullpacket: ", printpacket(pkt)
                        print "\tUDID: ", printpacket(pkt[report_pkt_offset -22: report_pkt_offset - 6])
                        print "\tMAJOR: ", printpacket(pkt[report_pkt_offset -6: report_pkt_offset - 4])
                        print "\tMINOR: ", printpacket(pkt[report_pkt_offset -4: report_pkt_offset - 2])
                        print "\tMAC address: ", packed_bdaddr_to_string(pkt[report_pkt_offset + 3:report_pkt_offset + 9])
                        # commented out - don't know what this byte is.  It's NOT TXPower
                        txpower, = struct.unpack("b", pkt[report_pkt_offset -2])
                        print "\t(Unknown):", txpower
        
                        rssi, = struct.unpack("b", pkt[report_pkt_offset -1])
                        print "\tRSSI:", rssi
                    # build the return string
                    Adstring = "MAC:"
                    Adstring += packed_bdaddr_to_string(pkt[report_pkt_offset + 3:report_pkt_offset + 9])
                    Adstring += ","
                    Adstring += "UUID:"
                    Adstring += returnstringpacket(pkt[report_pkt_offset -22: report_pkt_offset - 6]) 
                    Adstring += ","
                    Adstring += "%i" % returnnumberpacket(pkt[report_pkt_offset -6: report_pkt_offset - 4]) 
                    Adstring += ","
                    Adstring += "%i" % returnnumberpacket(pkt[report_pkt_offset -4: report_pkt_offset - 2]) 
                    Adstring += ","
                    Adstring += "Tx:"
                    #Adstring += ","
                    Adstring += "%i" % struct.unpack("b", pkt[report_pkt_offset -2])
                    Adstring += ","
                    Adstring += "RSSI:"
                    Adstring += "%i" % struct.unpack("b", pkt[report_pkt_offset -1])
                    mac = packed_bdaddr_to_string(pkt[report_pkt_offset + 3:report_pkt_offset + 9]) # return mac address from packets
                    tx = -64 # tx power of beacon
                    p=100
                    r=10 #kalman filter measurement noise 
                    q=0.125 #kalman filter process noise
                    x=0
                    timestamp = datetime.now().strftime("%Y-%m-%d ,%H:%M:%S")
                    if (mac == "d4:a4:e2:8c:af:9c"):
                        print "\tUDID: ", printpacket(pkt[report_pkt_offset -22: report_pkt_offset - 6])
                        print "\tMAJOR: ", printpacket(pkt[report_pkt_offset -6: report_pkt_offset - 4])
                        print "\tMINOR: ", printpacket(pkt[report_pkt_offset -4: report_pkt_offset - 2])
                        print "\tMAC address: ", packed_bdaddr_to_string(pkt[report_pkt_offset + 3:report_pkt_offset + 9])
                        myFullList.append(Adstring)
                        rss = "%i" % struct.unpack("b", pkt[report_pkt_offset -1]) #return rssi value from packets
                        # kalman filter formula
                        x = x
                        p = p + q;
                        k = p / (p + r);
                        x = x + k * (int(rss) - x);
                        p = (1 - k) * p;
                        print "frssi:","%.2f" % x, timestamp #filter rssi value
                        #Distance Formula
                        ratio = int(x)*1.0/int(tx)
                        if ratio <1.0:
                             distance = pow(ratio,10)
                             print "distance:","%.2f" % distance
                             awsgreengrass_connect(distance)
                        else :
                             distance = (0.89976)*pow(ratio,7.7095)+0.1111
        
                             print "distance:", "%.2f" % distance
                             awsgreengrass_connect(distance)
                            
                    else:
                        myFullList = []    
                done = True
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, old_filter )
    return myFullList
