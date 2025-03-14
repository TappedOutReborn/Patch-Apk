# Patch APK

Simple scripts to patch the Tapped Out APK with new server urls. All credit to tehfens for the patch_native.py script.

---

## Command-Line Patcher

### Requirements
- A Tapped Out APK
- cURL
- Python3
- Python3-venv
- Python3-pip
- openjdk-11-jre
- Radare2 (https://rada.re/n/radare2.html)

### Usage
To use the command-line script, run the following command in your terminal:

```./patch_apk.sh APK_TO_PATCH NEW_GAMESERVER_URL NEW_DLCSERVER_URL```

Example

```./patch_apk.sh tappedout.apk http://192.168.1.42:4242 http://192.168.1.42:4242/dlc/```

---

## GUI Patcher

### Overview
This script provides a graphical user interface (GUI) for patching APK files by entering specific server and DLC IP addresses.

### Requirements
- Python3

### Usage
1. Open the script to launch the GUI.
2. In the provided fields, enter the server IP and DLC IP in the format: `http://[ip_here]:[port_here]`
3. Click on "Patch APK" to start the patching process.

#### Example
- Server IP: `http://192.168.1.2:4242`
- DLC IP: `http://192.168.1.2:4242/dlc/`

---

