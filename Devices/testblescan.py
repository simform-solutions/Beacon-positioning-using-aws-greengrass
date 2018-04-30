import blescan
import sys
import time

import bluetooth._bluetooth as bluez

dev_id = 0
try:
    sock = bluez.hci_open_dev(dev_id)
    print "ble thread started"

except:
    print "error accessing bluetooth device..."
    sys.exit(1)

blescan.hci_le_set_scan_parameters(sock)
blescan.hci_enable_le_scan(sock)
#blescan.awsgreengrass_connect()

while True:
    returnedList = blescan.parse_events(sock, 100)
    print "----------"
    for beacon in returnedList:
        print beacon
