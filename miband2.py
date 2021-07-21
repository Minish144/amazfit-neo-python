#!/usr/bin/env python2
import struct
import time
import sys
import argparse
from Crypto.Cipher import AES
from bluepy.btle import Peripheral, DefaultDelegate

''' TODO
Key should be generated and stored during init
'''

UUID_SVC_MIBAND2 = "0000fee100001000800000805f9b34fb"
UUID_CHAR_AUTH = "00000009-0000-3512-2118-0009af100700"
UUID_SVC_ALERT = "0000180200001000800000805f9b34fb"
UUID_CHAR_ALERT = "00002a0600001000800000805f9b34fb"
UUID_SVC_HEART_RATE = "0000180d00001000800000805f9b34fb"
UUID_CHAR_HRM_MEASURE = "00002a3700001000800000805f9b34fb"
UUID_CHAR_HRM_CONTROL = "00002a3900001000800000805f9b34fb"

HRM_COMMAND = 0x15
HRM_MODE_SLEEP      = 0x00
HRM_MODE_CONTINUOUS = 0x01
HRM_MODE_ONE_SHOT   = 0x02

CCCD_UUID = 0x2902

class MiBand2(Peripheral):
    # _KEY = b'\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x40\x41\x42\x43\x44\x45'
    _KEY = b'\xa7\x89\x95\xf2\x03\x88\xcbo-\xd7\xbbF\xa2R\x10I'
    _send_key_cmd = struct.pack('<18s', b'\x01\x08' + _KEY)
    _send_rnd_cmd = struct.pack('<2s', b'\x02\x08')
    _send_enc_key = struct.pack('<2s', b'\x03\x08')

    def __init__(self, addr):
        Peripheral.__init__(self, addr)
        print("Connected")

        svc = self.getServiceByUUID(UUID_SVC_MIBAND2)
        self.char_auth = svc.getCharacteristics(UUID_CHAR_AUTH)[0]
        self.cccd_auth = self.char_auth.getDescriptors(forUUID=CCCD_UUID)[0]

        svc = self.getServiceByUUID(UUID_SVC_ALERT)
        self.char_alert = svc.getCharacteristics(UUID_CHAR_ALERT)[0]

        svc = self.getServiceByUUID(UUID_SVC_HEART_RATE)
        self.char_hrm_ctrl = svc.getCharacteristics(UUID_CHAR_HRM_CONTROL)[0]
        self.char_hrm = svc.getCharacteristics(UUID_CHAR_HRM_MEASURE)[0]
        self.cccd_hrm = self.char_hrm.getDescriptors(forUUID=CCCD_UUID)[0]

        self.timeout = 5.0
        self.state = None
        # Enable auth service notifications on startup
        self.auth_notif(True)
        self.waitForNotifications(0.1) # Let Mi Band to settle

    def init_after_auth(self):
        self.cccd_hrm.write(b"\x01\x00", True)

    def encrypt(self, message):
        aes = AES.new(self._KEY, AES.MODE_ECB)
        return aes.encrypt(message)

    def auth_notif(self, status):
        if status:
            print("Enabling Auth Service notifications status...")
            self.cccd_auth.write(b"\x01\x00", True)
        elif not status:
            print("Disabling Auth Service notifications status...")
            self.cccd_auth.write(b"\x00\x00", True)
        else:
            print("Something went wrong while changing the Auth Service notifications status...")

    def send_key(self):
        print("Sending Key...")
        self.char_auth.write(self._send_key_cmd)
        self.waitForNotifications(self.timeout)

    def req_rdn(self):
        print("Requesting random number...")
        self.char_auth.write(self._send_rnd_cmd)
        self.waitForNotifications(self.timeout)

    def send_enc_rdn(self, data):
        print("Sending encrypted random number")
        cmd = self._send_enc_key + self.encrypt(data)
        send_cmd = struct.pack('<18s', cmd)
        self.char_auth.write(send_cmd)
        self.waitForNotifications(self.timeout)

    def initialize(self):
        self.setDelegate(AuthenticationDelegate(self))
        self.send_key()

        while True:
            self.waitForNotifications(0.1)
            if self.state == "AUTHENTICATED":
                return True
            elif self.state:
                return False

    def authenticate(self):
        self.setDelegate(AuthenticationDelegate(self))
        self.req_rdn()

        while True:
            self.waitForNotifications(0.1)
            if self.state == "AUTHENTICATED":
                return True
            elif self.state:
                return False

    def hrmStartContinuous(self):
        self.char_hrm_ctrl.write(b'\x15\x01\x01', True)

    def hrmStopContinuous(self):
        self.char_hrm_ctrl.write(b'\x15\x01\x00', True)


class AuthenticationDelegate(DefaultDelegate):

    """This Class inherits DefaultDelegate to handle the authentication process."""
    def __init__(self, device):
        DefaultDelegate.__init__(self)
        self.device = device

    def handleNotification(self, hnd, data):
        # Debug purposes
        #print("HANDLE: " + str(hex(hnd)))
        print("DATA: ", str(data))
        if hnd == self.device.char_auth.getHandle():
            if data[:3] == b'\x10\x01\x01':
                self.device.req_rdn()
            elif data[:3] == b'\x10\x01\x04':
                self.device.state = "ERROR: Key Sending failed"
            elif data[:3] == b'\x10\x02\x01':
                random_nr = data[3:]
                self.device.send_enc_rdn(random_nr)
            elif data[:3] == b'\x10\x02\x04':
                self.device.state = "ERROR: Something wrong when requesting the random number..."
            elif data[:3] == b'\x10\x03\x01':
                print("Authenticated!")
                self.device.state = "AUTHENTICATED"
            elif data[:3] == b'\x10\x03\x04':
                print("Encryption Key Auth Fail, sending new key...")
                self.device.send_key()
            else:
                self.device.state = "ERROR: Auth failed"
            print("Auth Response", str(data))
        elif hnd == self.device.char_hrm.getHandle():
            rate = struct.unpack('bb', data)[1]
            print("Heart Rate: " + str(rate))
        else:
            print("Unhandled Response", str(data))

def main():
    """ main func """
    parser = argparse.ArgumentParser()
    parser.add_argument('host', action='store', help='MAC of BT device')
    parser.add_argument('-t', action='store', type=float, default=3.0,
                        help='duration of each notification')

    parser.add_argument('--init', action='store_true', default=False)
    parser.add_argument('-n', '--notify', action='store_true', default=False)
    parser.add_argument('-hrm', '--heart', action='store_true', default=False)
    arg = parser.parse_args(sys.argv[1:])

    print('Connecting to ' + arg.host)
    band = MiBand2(arg.host)
    band.setSecurityLevel(level="medium")

    if arg.init:
        if band.initialize():
            print("Init OK")
        band.disconnect()
        return
    else:
        band.authenticate()

    band.init_after_auth()

    if arg.notify:
        print("Sending message notification...")
        band.char_alert.write(b'\x01')
        time.sleep(arg.t)
        print("Sending phone notification...")
        band.char_alert.write(b'\x02')
        time.sleep(arg.t)
        print("Turning off notifications...")
        band.char_alert.write(b'\x00')

    if arg.heart:
        print("Cont. HRM start")
        band.hrmStopContinuous()
        band.hrmStartContinuous()
        while True:
            band.waitForNotifications(1.0)

    print("Disconnecting...")
    band.disconnect()
    del band


if __name__ == "__main__":
    main()