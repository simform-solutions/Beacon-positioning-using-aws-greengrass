#python basicdiscovery.py --endpoint a3drj1nn7u6229.iot.us-east-1.amazonaws.com --rootCA root-ca-cert.pem --cert c511834aea.cert.pem --key c511834aea.private.key --thingName rpi2 --topic 'hello/world/send' --mode both

import os
import sys
import time
import uuid
import json
import logging
import argparse
from AWSIoTPythonSDK.core.greengrass.discovery.providers import DiscoveryInfoProvider
from AWSIoTPythonSDK.core.protocol.connection.cores import ProgressiveBackOffCore
from AWSIoTPythonSDK.MQTTLib import AWSIoTMQTTClient
from AWSIoTPythonSDK.exception.AWSIoTExceptions import DiscoveryInvalidRequestException

AllowedActions = ['both', 'publish', 'subscribe']
x = 0
y = 0

# General message notification callback
def customOnMessage(message):
    print('Received message on topic %s: %s\n' % (message.topic, message.payload)) # recieved beacon distance message
    data =json.loads(message.payload) 
    
    if data['message'] == "rpi3":  # parse distance value and write to file from recieved message from rpi3 thing 
       distance3 = data['distance3']
       f = open("rpi3.txt","w+r") # open rpi3.txt file
       f.truncate() # remove all previous content
       f.write(str(float(distance3))) # write distance value to file
       f.close() # close file
       print (distance3)
    if data['message'] == "rpi1": # parse distance value and write to file from recieved message from rpi1 thing 
       distance1 = data['distance1']
       f = open("rpi1.txt","w+r") #open rpi1.txt file
       f.truncate() # remove all previous content 
       f.write(str(float(distance1))) # write distance value to file
       f.close() #close file
       print (distance1)
    if data['message'] == "rpi4": # parse distance value and write to file from recieved message from rpi4 thing 
       distance4 = data['distance4']
       f = open("rpi4.txt","w+r") # open rpi4.txt file
       f.truncate() # remove all previous content 
       f.write(str(float(distance4))) # write distance value to file
       f.close() # close file
       print (distance4)
 # Read three raspberrypi beacon distance from file   
    f = open("rpi4.txt","r")
    dis3 = f.read()
    d3 = float(dis3) # rpi4 thing distance value
    print ("d3="+str(float(d3)))
    f.close()
    f = open("rpi3.txt","r")
    dis2 = f.read()
    d2 = float(dis2) # rpi2 thing distance value
    print ("d2="+str(float(d2)))
    f.close()
    f = open("rpi1.txt","r")
    dis1 = f.read()
    d1 = float(dis1) # rpi1 thing distance value
    print ("d1="+str(float(d1)))
    f.close()
       
#Trilateration Formula   
    x1 = 0
    y1 = 0
    x2 = 4.2
    y2 = 0
    x3 = 2.4
    y3 = 1.8

    R1 = (x1,y1)
    R2 = (x2,y2)
    R3 = (x3,y3)

    # if d1 ,d2 and d3 in known
    # calculate A ,B and C coifficents
    A = R1[0]**2 + R1[1]**2 - d1**2
    B = R2[0]**2 + R2[1]**2 - d2**2
    C = R3[0]**2 + R3[1]**2 - d3**2
    X32 = R3[0] - R2[0]
    X13 = R1[0] - R3[0]
    X21 = R2[0] - R1[0]

    Y32 = R3[1] - R2[1]
    Y13 = R1[1] - R3[1]
    Y21 = R2[1] - R1[1]

    # calculate beacon position cordinates
    global x
    x = (A * Y32 + B * Y13 + C * Y21)/(2.0*(R1[0]*Y32 + R2[0]*Y13 + R3[0]*Y21))
    global y
    y = (A * X32 + B * X13 + C * X21)/(2.0*(R1[1]*X32 + R2[1]*X13 + R3[1]*X21))
    
MAX_DISCOVERY_RETRIES = 10
GROUP_CA_PATH = "./groupCA/"

# Read in command-line parameters
parser = argparse.ArgumentParser()
parser.add_argument("-e", "--endpoint", action="store", required=True, dest="host", help="Your AWS IoT custom endpoint")
parser.add_argument("-r", "--rootCA", action="store", required=True, dest="rootCAPath", help="Root CA file path")
parser.add_argument("-c", "--cert", action="store", dest="certificatePath", help="Certificate file path")
parser.add_argument("-k", "--key", action="store", dest="privateKeyPath", help="Private key file path")
parser.add_argument("-n", "--thingName", action="store", dest="thingName", default="Bot", help="Targeted thing name")
parser.add_argument("-t", "--topic", action="store", dest="topic", default="sdk/test/Python", help="Targeted topic")
parser.add_argument("-m", "--mode", action="store", dest="mode", default="both",
                    help="Operation modes: %s"%str(AllowedActions))
parser.add_argument("-M", "--message", action="store", dest="message", default="Hello World!",
                    help="Message to publish")

args = parser.parse_args()
host = args.host
rootCAPath = args.rootCAPath
certificatePath = args.certificatePath
privateKeyPath = args.privateKeyPath
clientId = args.thingName
thingName = args.thingName
topic = args.topic

if args.mode not in AllowedActions:
    parser.error("Unknown --mode option %s. Must be one of %s" % (args.mode, str(AllowedActions)))
    exit(2)

if not args.certificatePath or not args.privateKeyPath:
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
if args.mode == 'both' or args.mode == 'subscribe':
    myAWSIoTMQTTClient.subscribe(topic, 0, None)
time.sleep(2)

loopCount = 0

while True:
    if args.mode == 'both' or args.mode == 'publish':
        print('x=%d, y=%d' %(x,y))
        if x != 0 and y != 0:
            #publish Trilateration cordinates
            message = {}
            message['x'] = str(x)
            message['y'] = str(y)
            messageJson = json.dumps(message)
            myAWSIoTMQTTClient.publish("hello/world/position", messageJson, 0) 
        if x > 2 and y > 2:
            #Trigger Lambda function
            messagee = {}
            messagee['message'] = "Hello from AWS IoT console"
            messageJsonn = json.dumps(messagee)
            print (messageJsonn)
            myAWSIoTMQTTClient.publish("hello/world/position/trigger", messageJsonn, 0)
            global x
            x = 0
            global y
            y = 0
            if args.mode == 'both':
                print('Published topic %s: %s\n' % ("hello/world/position", messageJson))
       # loopCount += 1
    time.sleep(1)


