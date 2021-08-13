from sys import platform
if platform != 'linux' and platform != 'linux2':
    raise Exception(f'linux is the only supported OS, your platform is {platform}')

from bluepy.btle import Peripheral, Service, Characteristic, DefaultDelegate, Descriptor
from Crypto.Cipher import AES
from dotenv import load_dotenv
import threading
import binascii
import time
import struct
import sys
import os

load_dotenv()

# Device MAC address
MAC_AMAZFIT_NEO = os.getenv('MAC')

# Auth key

KEY = bytes.fromhex(os.getenv('KEY')[2:]) # where key is a 32 bytes key in .env file
                                          # you got from github.com/argrento/huami-token
# Anhui Huami service
UUID_SVC_HUAMI = '0000fee0-0000-1000-8000-00805f9b34fb'
UUID_CHAR_BATTERY = '00000006-0000-3512-2118-0009af100700'

# Anhui Huami auth service
UUID_SVC_HUAMI_AUTH = '0000fee1-0000-1000-8000-00805f9b34fb'
UUID_CHAR_AUTH = '00000009-0000-3512-2118-0009af100700'
UUID_DESC_AUTH = '00002902-0000-1000-8000-00805f9b34fb'

# Heart Rate service
UUID_SVC_HEART_RATE = '0000180d-0000-10008000-00805f9b34fb'
UUID_CHAR_HRM_MEASURE = '00002a37-0000-1000-8000-00805f9b34fb'
UUID_CHAR_HRM_CONTROL = '00002a39-0000-1000-8000-00805f9b34fb'

class Utils(object):
    '''
    Simple utils class
    '''
    @staticmethod
    def encrypt(key, message):
        aes = AES.new(key, AES.MODE_ECB)
        return aes.encrypt(message)

class AmazfitNeo(Peripheral):
    '''
    AmazfitNeo is a class which provides
    you useful methods to work with
    amazfit neo band
    '''

    def __init__(self, MAC: str) -> Peripheral:
        super().__init__(MAC)

    def inspect(self) -> None:
        '''
        inspect prints available
        services and its characteristics
        '''
        svcs = self.getServices()
        for svc in svcs:
            print(f'\n       {svc.uuid}       ')
            print('--------------------------------------------------')
            for ch in svc.getCharacteristics():
                print(f'[ch.getHandle()]', '0x'+ format(ch.getHandle(),'02X')  +'   '+str(ch.uuid) +' ' + ch.propertiesToString())
        print('\n')

    def read_battery(self) -> any:
        '''
        read_battery returns
        current battery level
        '''
        char = self.get_battery_char()
        if char.supportsRead():
            bytes = char.read()
            return float(struct.unpack('b', bytes[1:2])[0]) if len(bytes) >= 2 else None
        return None


    def auth(self) -> None:
        '''
        auth authorizes the band
        with provided KEY
        '''
        self.get_auth_desc().write(b'\x01\x00', True)
        self.waitForNotifications(0.5)

        self.get_auth_char().write(struct.pack('<2s', b'\x02\x00'))
        self.waitForNotifications(0.5)

    def start_heartrate(self) -> None:
        '''
        start_heartrate requests band
        for heart rate measurements
        notifications
        '''
        self.get_heartrate_control_char().write(b'\x15\x01\x01', True)

    def stop_heartrate(self) -> None:
        '''
        stop_heartrate requests band
        to stop heart rate measurements
        notifications
        '''
        self.get_heartrate_control_char().write(b'\x15\x01\x00', True)

    def get_heartrate_measurement_char(self) -> Characteristic:
        '''
        get_heartrate_measurement_char returns
        control measurements characteristic
        '''
        svc_heartrate = self.getServiceByUUID(UUID_SVC_HEART_RATE)
        chars = svc_heartrate.getCharacteristics(UUID_CHAR_HRM_MEASURE)
        if len(chars) != 0:
            return chars[0]
        else:
            raise Exception(f'failed to get heartrate measure char, could not find such in {UUID_SVC_HEART_RATE} service')

    def get_heartrate_control_char(self) -> Characteristic:
        '''
        get_heartrate_measurement_char returns
        control hr characteristic
        '''
        svc_heartrate = self.getServiceByUUID(UUID_SVC_HEART_RATE)
        chars = svc_heartrate.getCharacteristics(UUID_CHAR_HRM_CONTROL)
        if len(chars) != 0:
            return chars[0]
        else:
            raise Exception(f'failed to get heartrate control char, could not find such in {UUID_SVC_HEART_RATE} service')

    def get_auth_desc(self) -> Characteristic:
        '''
        get_auth_desct returns
        auth descriptor
        '''
        svc_heartrate = self.getServiceByUUID(UUID_SVC_HUAMI_AUTH)
        descs = svc_heartrate.getDescriptors(UUID_DESC_AUTH)
        if len(descs) != 0:
            return descs[0]
        else:
            raise Exception(f'failed to get auth char, could not find such in {UUID_SVC_HEART_RATE} service')

    def get_auth_char(self) -> Characteristic:
        '''
        get_auth_char returns
        auth characteristic
        '''
        svc_heartrate = self.getServiceByUUID(UUID_SVC_HUAMI_AUTH)
        chars = svc_heartrate.getCharacteristics(UUID_CHAR_AUTH)
        if len(chars) != 0:
            return chars[0]
        else:
            raise Exception(f'failed to get auth char, could not find such in {UUID_SVC_HEART_RATE} service')

    def get_battery_char(self) -> Characteristic:
        '''
        get_battery_char returns
        battery info characteristic
        '''
        svc_battery = self.getServiceByUUID(UUID_SVC_HUAMI)
        chars = svc_battery.getCharacteristics(UUID_CHAR_BATTERY)
        if len(chars) != 0:
            return chars[0]
        else:
            raise Exception(f'failed to get battery char, could not find such in {UUID_SVC_HUAMI} service')

class NotificationDelegate(DefaultDelegate):
    '''
    NotificationDelegate is a
    DefaultDelegate class with
    overridden notification handler
    '''
    def __init__(self, device: AmazfitNeo):
        DefaultDelegate.__init__(self)
        self.device = device

    def handleNotification(self, hnd, data):
        '''
        handleNotification handles new notification
        '''
        if hnd == self.device.get_auth_char().getHandle():
            if data[:3] == b'\x10\x01\x01':
                self.device.get_auth_char().write(struct.pack('<2s', b'\x02\x00'))
                self.device.waitForNotifications(0.5)

            elif data[:3] == b'\x10\x01\x04':
                print('Sending key failed')

            elif data[:3] == b'\x10\x02\x01':
                cmd = struct.pack('<2s', b'\x03\x00') + Utils().encrypt(KEY, data[3:])
                send_cmd = struct.pack('<18s', cmd)
                self.device.get_auth_char().write(send_cmd)
                self.device.waitForNotifications(0.5)

            elif data[:3] == b'\x10\x02\x04':
                print('Requesting random key error')

            elif data[:3] == b'\x10\x03\x04':
                print('Ecnryption key failed!')

            elif data[:3] == b'\x10\x03\x01':
                print('Auth completed!')

            else:
                print('Auth failed')

        elif hnd == self.device.get_heartrate_measurement_char().getHandle():
            self.__handle_heartrate_notification(hnd, data)
        else:
            print(f'Unrecognized data: {data}')

    def __handle_heartrate_notification(self, hnd, data):
        rate = struct.unpack('bb', data)[1]
        print('Heart Rate: ', str(rate))

def example():
    print('Starting...')

    band = AmazfitNeo(MAC_AMAZFIT_NEO) # getting band class
    print('Connected successfully!')

    notificationHandler = NotificationDelegate(band)
    band.setDelegate(notificationHandler) # setting notification handler

    band.auth() # authorizing using provided auth key

    print(f'Battery level: {band.read_battery()}') # getting battery level

    band.start_heartrate() # request heart rate measurements
    for _ in range(60):
        band.waitForNotifications(0.5)
        time.sleep(1)

if __name__ == '__main__':
    example()

