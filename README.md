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