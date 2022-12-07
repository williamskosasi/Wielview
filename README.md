# Wielview

Wielview is an open-source computer forensics tool that can display summary as the result of Windows Event Log analysis based on the chosen function(s).

## Functions

List of functions:
1. Storage
	- Showing detailed information of internal and external storages that have ever connected including the partition table, connected timestamps, and disconnected timestamps.
2. Boot
	- Showing list of boot up and sleep timestamps including the boot type.
3. WLAN
	- Showing list of wireless connection profiles that have ever connected including the connected and disconnected timestamps.
	- Showing list of wireless connection profiles that don't have authentication.
4. System Time Change
	- Showing list of system time changes done manually by the user.
5. Windows Defender
	- Showing list of malware detected by Windows Defender.
	- Showing list of malware detected but not protected by Windows Defender.
6. User Logon/Logoff
	- Showing list of user logon and logoff activities.
7. Printer
	- Showing list of printers that have ever connected and the printing activities including Microsoft Print to PDF.
8. Microsoft Office
	- Showing list of alerts that have ever appeared and the list of files that have ever been accessed by using one of Microsoft Office products.
	- Showing list of files that have ever been accessed by using one of Microsoft Office products but the extension is not related to any Microsoft Office products.
9. Powershell
	- Showing list of commands run by using Powershell including the timestamps.
	- Showing list of obfuscated commands run by using Powershell.


## How to Run
Wielview is developed by using Python scripting language and can be run on any command-line interface.

## Requirements

Wielview requires Python 3.

These are some python modules that should be installed:
- python-evtx
    ```sh
    pip install python-evtx
    ```
- pandas
    ```sh
    pip install pandas
    ```
- obfuscation-detection
    ```sh
    pip install obfuscation-detection
    ```

You can simply install all the modules by using the command below (requirements.txt is needed).
```sh
pip install -r requirements.txt
```
