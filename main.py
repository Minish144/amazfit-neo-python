from bluepy.btle import Peripheral, Service, Characteristic, DefaultDelegate, Descriptor
from Crypto.Cipher import AES
import threading
import binascii
import time
import struct
import sys

# Device MAC address
MAC_AMAZFIT_NEO = 'C1:CC:A3:0A:B1:94'

# Auth key
KEY = b'\xa7\x89\x95\xf2\x03\x88\xcbo-\xd7\xbbF\xa2R\x10I'

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

CCCD_UUID = 0x2902

class Utils(object):
    @staticmethod
    def encrypt(key, message):
        aes = AES.new(key, AES.MODE_ECB)
        return aes.encrypt(message)

class AmazfitNeo(Peripheral):
    __notifications_thread: threading.Thread

    def __init__(self, MAC: str) -> Peripheral:
        super().__init__(MAC)

    def inspect(self) -> None:
        svcs = self.getServices()
        for svc in svcs:
            print(f'\n       {svc.uuid}       ')
            print('--------------------------------------------------')
            for ch in svc.getCharacteristics():
                print(f'[ch.getHandle()]', '0x'+ format(ch.getHandle(),'02X')  +'   '+str(ch.uuid) +' ' + ch.propertiesToString())
        print('\n')

    def read_battery(self) -> any:
        char = self.get_battery_char()
        if char.supportsRead():
            bytes = char.read()
            return struct.unpack('b', bytes[1:2])[0] if len(bytes) >= 2 else None
        return None
        

    def auth(self) -> None:
        self.get_auth_desc().write(b"\x01\x00", True)
        self.waitForNotifications(0.5)

        self.get_auth_char().write(struct.pack('<2s', b'\x02\x00'))
        self.waitForNotifications(0.5)

    def start_heartrate(self) -> None:
        self.get_heartrate_control_char().write(b'\x15\x01\x01', True)

    def stop_heartrate(self) -> None:
        self.get_heartrate_control_char().write(b'\x15\x01\x00', True)
        self.__notifications_thread.do_run = False

    def get_heartrate_control_measure_char(self) -> Characteristic:
        svc_heartrate = self.getServiceByUUID(UUID_SVC_HEART_RATE)
        chars = svc_heartrate.getCharacteristics(UUID_CHAR_HRM_MEASURE)
        if len(chars) != 0:
            return chars[0]
        else:
            raise Exception(f'failed to get heartrate measure char, could not find such in {UUID_SVC_HEART_RATE} service')

    def get_heartrate_control_char(self) -> Characteristic:
        svc_heartrate = self.getServiceByUUID(UUID_SVC_HEART_RATE)
        chars = svc_heartrate.getCharacteristics(UUID_CHAR_HRM_CONTROL)
        if len(chars) != 0:
            return chars[0]
        else:
            raise Exception(f'failed to get heartrate control char, could not find such in {UUID_SVC_HEART_RATE} service')

    def get_auth_desc(self) -> Characteristic:
        svc_heartrate = self.getServiceByUUID(UUID_SVC_HUAMI_AUTH)
        descs = svc_heartrate.getDescriptors(UUID_DESC_AUTH)
        if len(descs) != 0:
            return descs[0]
        else:
            raise Exception(f'failed to get auth char, could not find such in {UUID_SVC_HEART_RATE} service')

    def get_auth_char(self) -> Characteristic:
        svc_heartrate = self.getServiceByUUID(UUID_SVC_HUAMI_AUTH)
        chars = svc_heartrate.getCharacteristics(UUID_CHAR_AUTH)
        if len(chars) != 0:
            return chars[0]
        else:
            raise Exception(f'failed to get auth char, could not find such in {UUID_SVC_HEART_RATE} service')

    def get_battery_char(self) -> Characteristic:
        svc_battery = self.getServiceByUUID(UUID_SVC_HUAMI)
        chars = svc_battery.getCharacteristics(UUID_CHAR_BATTERY)
        if len(chars) != 0:
            return chars[0]
        else:
            raise Exception(f'failed to get battery char, could not find such in {UUID_SVC_HUAMI} service')

    def listen_to_notifications(self) -> None:
        self.__notifications_thread = threading.Thread(
            target=self.__start_notifications_listening_thread
        )
        self.__notifications_thread.start()

    def __start_notifications_listening_thread(self) -> None:
        t = threading.currentThread()
        while getattr(t, 'do_run', True):
            self.waitForNotifications(0.5)

class NotificationDelegate(DefaultDelegate):
    def __init__(self, device: AmazfitNeo):
        DefaultDelegate.__init__(self)
        self.device = device

    def handleNotification(self, hnd, data):
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

        elif hnd == self.device.get_heartrate_control_measure_char().getHandle():
            self.__handle_heartrate_notification(hnd, data)
        else:
            print(f'Unrecognized data: {data}')

    def __handle_heartrate_notification(self, hnd, data):
        rate = struct.unpack('bb', data)[1]
        print('Heart Rate: ', str(rate))

def main():
    print('Starting...')

    band = AmazfitNeo(MAC_AMAZFIT_NEO) # getting band class
    print('Connected successfully!')

    notificationHandler = NotificationDelegate(band)
    band.setDelegate(notificationHandler)

    band.auth()

    timestart = 0
    while True:
        print(timestart)
        print(band.read_battery())
        time.sleep(10)
        timestart += 10

if __name__ == '__main__':
    main()

    