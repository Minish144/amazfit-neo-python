# amazfit-neo-python

## Turn on bluetooth
```bash
$ bluetoothctl

[bluetooth] power on
```

## Installing dependencies
```bash
$ python3 -m venv env

$ source env/bin/activate

$ pip install -r requirements.txt
```

## Setting MAC address and auth key
set `MAC` and `KEY` in `.env` file according to example in `.env.example`
```
KEY=0xa12345b67890cd1e2fg3hi45j6789012
MAC=AA:AA:AA:AA:AA:AA
```

## Running
```bash
python3 main.py
```

## Services, Characteristics, Descriptors
### Huami
Huami Service - `0000fee0-0000-1000-8000-00805f9b34fb`
Battery Char. - `00000006-0000-3512-2118-0009af100700`

### Huami Auth
Auth Service - `0000fee1-0000-1000-8000-00805f9b34fb`
Auth Char. -  `00000009-0000-3512-2118-0009af100700`
Auth Desc. - `00002902-0000-1000-8000-00805f9b34fb`

### Heartrate
Heartrate Service - `0000180d-0000-10008000-00805f9b34fb`
Heartrate Measurements Char. - `00002a37-0000-1000-8000-00805f9b34fb`
Heartate Control (Enabling/Disabling HR) Char. - `00002a39-0000-1000-8000-00805f9b34fb`

## Pipeline
### Connect
1. Get band's MAC address
2. Connect to the device via bluetooth using the MAC

### Battery Percentage
1. Read byte array from *Battery Char.*
2. The *second byte* from array is the value you need

### Heart Rate
1. Enable notifications for *Heartrate Measurements Char.*
2. Write 3 bytes `0x15, 0x01, 0x01` to *Heartate Control Char.* (enables heart rate measurements on the device)
3. Wait for notifications from *Heartrate Measurements Char.*
4. Take *the second byte* from every new byte array you get - that's the value you need
5. Write `0x15, 0x01, 0x00` to disable measurements

### Auth (to prevent disconnecting after every request)
1. Get Huami auth key - https://github.com/argrento/huami-token (e.g. 0xa3c10e34e5c14637eea6b9efc06106)
2. Convert your hex key to bytes (e.g. `0xa3, 0xc1, 0x0e4, 0xe5, 0xc1F7, 0xee, 0xa6, 0xb9, 0xef, 0xc0a, 0x06`)
3. Create new AES cipher in ECB mode using converted key as a key
4. Enable notifications from *Auth Char.* from *Auth Service*
5. Write 2 bytes `0x01, 0x00` to *Auth Desc.* from *Auth Service* (enables auth service notifications)
6. Write 2 bytes `0x02, 0x00` to *Auth Char.* from *Auth Service* (this requestes random key from device)
7. Wait for response from *Auth Char.*, you should get an array of bytes the first three bytes of which are `0x10, 0x02, 0x01`. Save other bytes, except those three (`data[3:]`)
8. Concat `0x03, 0x00` with `data[3:]` encrypted with cipher made from you auth key
9. Send it to *Auth Char.* from *Auth Service*
10. If you've done everything right you will recive an array of bytes which starts with `0x10, 0x03, 0x01` from *Auth Char.* from *Auth Service*