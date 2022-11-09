# Wielview version 0.1.0
# Author: Williams Kosasi
# https://github.com/williamskosasi

import Evtx.Evtx as evtx
import re
import pandas as pd
import base64
import gzip
import obfuscation_detection as od

pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.width', None)
pd.set_option('display.max_colwidth', 100)

def help():
    print("\n============================================")
    print("Wielview version 0.1.0")
    print("Author: Williams Kosasi")
    print("https://github.com/williamskosasi")
    print("============================================")
    print("Wielview - An open-source computer forensics tool that can display summary as the result of Windows Event Log analysis based on the chosen function(s)")
    print("\nNo\tFunctions\t\t\tDescription")
    print("1\tStorage\t\t\t\tShowing detailed information of internal and external storages that have ever connected including the partition table, connected timestamps, and disconnected timestamps.")
    print("2\tBoot\t\t\t\tShowing list of boot up and sleep timestamps including the boot type.")
    print("3\tWLAN\t\t\t\tShowing list of wireless connection profiles that have ever connected including the connected and disconnected timestamps.")
    print("\t\t\t\t\tShowing list of wireless connection profiles that don't have authentication.")
    print("4\tSystem Time Change\t\tShowing list of system time changes done manually by the user.")
    print("5\tWindows Defender\t\tShowing list of malware detected by Windows Defender.")
    print("\t\t\t\t\tShowing list of malware detected but not protected by Windows Defender.")
    print("6\tUser Logon/Logoff\t\tShowing list of user logon and logoff activities.")
    print("7\tPrinter\t\t\t\tShowing list of printers that have ever connected and the printing activities including Microsoft Print to PDF.")
    print("8\tMicrosoft Office\t\tShowing list of alerts that have ever appeared and the list of files that have ever been accessed by using one of Microsoft Office products.")
    print("\t\t\t\t\tShowing list of files that have ever been accessed by using one of Microsoft Office products but the extension is not related to any Microsoft Office products.")
    print("9\tPowerShell\t\t\tShowing list of commands run by using PowerShell including the timestamps.")
    print("\t\t\t\t\tShowing list of obfuscated commands run by using PowerShell.")

def storage(pathPartitionDiagnostic, pathStorageStorportHealth, pathStorsvcDiagnostic, export, outputPath):
    with evtx.Evtx(pathPartitionDiagnostic) as log:
        tableStorage = {"No":[], "Serial Number":[], "Manufacturer":[], "Model Name":[], "Revision":[], "Bus Type":[], "Disk ID":[], "Capacity (bytes)":[], "Bytes Per Sector":[], "Boot Device":[], "Storage Type":[], "File System":[], "Partition Style":[], "Trim Supported":[], "Connected (times)":[], "Disconnected (times)":[]}
        tableConnectedDisconnected = {"No":[], "Serial Number":[], "Event Type":[], "Time":[]}
        dataList = []
        for record in log.records():
            data = record.xml()
            model = re.search('<Data Name="Model">(.*)</Data>', data).group(1)
            serialNumTemp = re.search('<Data Name="SerialNumber">(.*)</Data>', data).group(1).split()
            try:
                serialNum = serialNumTemp[0]
            except:
                serialNum = serialNumTemp
            manufacturer = re.search('<Data Name="Manufacturer">(.*)</Data>', data).group(1)
            revision = re.search('<Data Name="Revision">(.*)</Data>', data).group(1)
            busType = re.search('<Data Name="BusType">(.*)</Data>', data).group(1)
            if(busType == "0"):
                busTypeName = "Unknown"
            elif(busType == "1"):
                busTypeName = "SCSI"
            elif(busType == "2"):
                busTypeName = "ATAPI"
            elif(busType == "3"):
                busTypeName = "ATA"
            elif(busType == "4"):
                busTypeName = "1394"
            elif(busType == "5"):
                busTypeName = "SSA"
            elif(busType == "6"):
                busTypeName = "Fibre Channel"
            elif(busType == "7"):
                busTypeName = "USB"
            elif(busType == "8"):
                busTypeName = "RAID"
            elif(busType == "9"):
                busTypeName = "iSCSI"
            elif(busType == "10"):
                busTypeName = "SAS"
            elif(busType == "11"):
                busTypeName = "SATA"
            elif(busType == "12"):
                busTypeName = "SD"
            elif(busType == "13"):
                busTypeName = "MMC"
            elif(busType == "14"):
                busTypeName = "MAX/Virtual"
            elif(busType == "15"):
                busTypeName = "File Backed Virtual"
            elif(busType == "16"):
                busTypeName = "Storage Spaces"
            elif(busType == "17"):
                busTypeName = "NVMe"
            elif(busType == "18"):
                busTypeName = "Microsoft Reserved"
            fullBusType = f"{busType} ({busTypeName})"
            capacity = re.search('<Data Name="Capacity">(.*)</Data>', data).group(1)
            bps = re.search('<Data Name="BytesPerSector">(.*)</Data>', data).group(1)
            trimSupported = re.search('<Data Name="IsTrimSupported">(.*)</Data>', data).group(1)
            partitionTableBytes = re.search('<Data Name="PartitionTableBytes">(.*)</Data>', data).group(1)
            partitionStyle = re.search('<Data Name="PartitionStyle">(.*)</Data>', data).group(1)
            diskID = re.search('<Data Name="DiskId">(.*)</Data>', data).group(1)
            toBeAppend = [serialNum, manufacturer, model, revision, fullBusType, capacity, bps, partitionTableBytes, trimSupported, partitionStyle, diskID]
            dataList.append(toBeAppend)

            time = re.search('<TimeCreated SystemTime="(.*)"></TimeCreated>', data).group(1)
            partitionTableBytes = re.search('<Data Name="PartitionTableBytes">(.*)</Data>', data).group(1)
            if(partitionTableBytes != "0"):
                eventType = "Connected"
            else:
                eventType = "Disconnected"
            tableConnectedDisconnected["Serial Number"].append(serialNum)
            tableConnectedDisconnected["Time"].append(time + " UTC")
            tableConnectedDisconnected["Event Type"].append(eventType)
        for entry in dataList:
            if(entry[0] not in tableStorage["Serial Number"]):
                tableStorage["Serial Number"].append(entry[0])
                tableStorage["Manufacturer"].append(entry[1])
                tableStorage["Model Name"].append(entry[2])
                tableStorage["Revision"].append(entry[3])
                tableStorage["Bus Type"].append(entry[4])
                tableStorage["Trim Supported"].append(entry[8])
                tableStorage["Disk ID"].append(entry[10])
                if(entry[9] == "0"):
                    tableStorage["Partition Style"].append("MBR")
                elif(entry[9] == "1"):
                    tableStorage["Partition Style"].append("GPT")
                else:
                    tableStorage["Partition Style"].append("Unknown")
                tableStorage["Capacity (bytes)"].append(entry[5])
                tableStorage["Bytes Per Sector"].append(entry[6])
                if(entry[7] == "0"):
                    tableStorage["Disconnected (times)"].append(1)
                    tableStorage["Connected (times)"].append(0)
                else:
                    tableStorage["Connected (times)"].append(1)
                    tableStorage["Disconnected (times)"].append(0)
            else:
                index = tableStorage["Serial Number"].index(entry[0])
                if(tableStorage["Capacity (bytes)"][index] == "0" and entry[5] != "0"):
                    tableStorage["Capacity (bytes)"][index] = entry[5]
                    tableStorage["Bytes Per Sector"][index] = entry[6]
                if(entry[7] == "0"):
                    tableStorage["Disconnected (times)"][index] += 1
                else:
                    tableStorage["Connected (times)"][index] += 1
                if(entry[9] == "1" and tableStorage["Partition Style"][index] == "MBR"):
                    tableStorage["Partition Style"][index] = "GPT"
                if(tableStorage["Manufacturer"][index] != entry[1] or tableStorage["Model Name"][index] != entry[2] or tableStorage["Revision"][index] != entry[3] or tableStorage["Bus Type"][index] != entry[4] or tableStorage["Trim Supported"][index] != entry[8] or tableStorage["Disk ID"][index] != entry[10]):
                    tableStorage["Manufacturer"][index] = entry[1]
                    tableStorage["Model Name"][index] = entry[2]
                    tableStorage["Revision"][index] = entry[3]
                    tableStorage["Bus Type"][index] = entry[4]
                    tableStorage["Trim Supported"][index] = entry[8]
                    tableStorage["Disk ID"][index] = entry[10]

        with evtx.Evtx(pathStorageStorportHealth) as log2:
            listOfInternalStorage = []
            listOfBootDevice = []
            listOfPotentiallyInternal = {"Serial Number":[], "Disk ID":[], "Prod ID":[]}
            listOfPotentiallyBoot = {"Disk ID":[], "Prod ID":[]}
            for record in log2.records():
                data = record.xml()
                try:
                    serialNumTemp = re.search('<Data Name="SerialNumber">(.*)</Data>', data).group(1).split()
                    try:
                        serialNum = serialNumTemp[0]
                    except:
                        serialNum = serialNumTemp
                    bootDevice = re.search('<Data Name="BootDevice">(.*)</Data>', data).group(1)
                    if(serialNum not in listOfInternalStorage):
                        listOfInternalStorage.append(serialNum)
                        listOfPotentiallyInternal["Disk ID"].append(re.search('<Data Name="ClassDeviceGuid">(.*)</Data>', data).group(1))
                        listOfPotentiallyInternal["Prod ID"].append(re.search('<Data Name="ProductId">(.*)</Data>', data).group(1))
                        listOfPotentiallyInternal["Serial Number"].append(serialNum)
                        if(bootDevice == "True"):
                            listOfBootDevice.append(serialNum)
                            listOfPotentiallyBoot["Disk ID"].append(re.search('<Data Name="ClassDeviceGuid">(.*)</Data>', data).group(1))
                            listOfPotentiallyBoot["Prod ID"].append(re.search('<Data Name="ProductId">(.*)</Data>', data).group(1))
                    else:
                        if(bootDevice == "True" and serialNum not in listOfBootDevice):
                            listOfBootDevice.append(serialNum)
                            listOfPotentiallyBoot["Disk ID"].append(re.search('<Data Name="ClassDeviceGuid">(.*)</Data>', data).group(1))
                            listOfPotentiallyBoot["Prod ID"].append(re.search('<Data Name="ProductId">(.*)</Data>', data).group(1))
                except:
                    try:
                        serialNumTemp = re.search('<Data Name="SerialNumber">(.*)</Data>', data).group(1).split()
                        try:
                            serialNum = serialNumTemp[0]
                        except:
                            serialNum = serialNumTemp
                        listOfInternalStorage.append(serialNum)
                    except:
                        pass
            for index, storage in enumerate(tableStorage["Serial Number"]):
                if(storage in listOfBootDevice):
                    tableStorage["Boot Device"].append("True")
                else:
                    if(tableStorage["Disk ID"][index] in listOfPotentiallyBoot["Disk ID"]):
                        bootDeviceDiskIDAndProdIDIndex = listOfPotentiallyBoot["Disk ID"].index(tableStorage["Disk ID"][index])
                        if(tableStorage["Model Name"][index] == listOfPotentiallyBoot["Prod ID"][bootDeviceDiskIDAndProdIDIndex]):
                            tableStorage["Storage Type"].append("(Potentially) Boot Device")
                    tableStorage["Boot Device"].append("False")
                if(storage in listOfInternalStorage):
                    tableStorage["Storage Type"].append("Internal")
                else:
                    if(tableStorage["Disk ID"][index] in listOfPotentiallyInternal["Disk ID"]):
                        internalDeviceDiskIDAndProdIDIndex = listOfPotentiallyInternal["Disk ID"].index(tableStorage["Disk ID"][index])
                        if(tableStorage["Model Name"][index] == listOfPotentiallyInternal["Prod ID"][internalDeviceDiskIDAndProdIDIndex]):
                            tableStorage["Storage Type"].append("(Potentially) Internal")
                            tableStorage["Serial Number"][index] = f'{tableStorage["Serial Number"][index]} ({listOfPotentiallyInternal["Serial Number"][internalDeviceDiskIDAndProdIDIndex]})'
                        else:
                            tableStorage["Storage Type"].append("External")
                    else:
                        tableStorage["Storage Type"].append("External")

        with evtx.Evtx(pathStorsvcDiagnostic) as log3:
            storagePrimaryFileSystemList = {"Serial Number":[], "File System":[]}
            for record in log3.records():
                try:
                    data = record.xml()
                    serialNumTemp = re.search('<Data Name="SerialNumber">(.*)</Data>', data).group(1).split()
                    try:
                        serialNum = serialNumTemp[0]
                    except:
                        serialNum = serialNumTemp
                    fileSystem = re.search('<Data Name="FileSystem">(.*)</Data>', data).group(1)
                    if(fileSystem == ""):
                        fileSystem = "Unknown"
                    if(serialNum not in storagePrimaryFileSystemList["Serial Number"]):
                        storagePrimaryFileSystemList["Serial Number"].append(serialNum)
                        storagePrimaryFileSystemList["File System"].append(fileSystem)
                    else:
                        index = storagePrimaryFileSystemList["Serial Number"].index(serialNum)
                        if(storagePrimaryFileSystemList["File System"][index] != fileSystem):
                            storagePrimaryFileSystemList["File System"][index] = fileSystem
                except:
                    pass
            for tempStorage in tableStorage["Serial Number"]:
                try:
                    storage = ''.join(tempStorage).split()[0]
                except:
                    storage = tempStorage
                if(storage in storagePrimaryFileSystemList["Serial Number"]):
                    index = storagePrimaryFileSystemList["Serial Number"].index(storage)
                    tableStorage["File System"].append(storagePrimaryFileSystemList["File System"][index])
                else:
                    tableStorage["File System"].append("Unknown")

        for index in range(len(tableStorage["Model Name"])):
            tableStorage["No"].append(index+1)

        for index in range(len(tableConnectedDisconnected["Event Type"])):
            tableConnectedDisconnected["No"].append(index+1)

        print("\nList of storages:")
        dfStorages = pd.DataFrame(tableStorage)
        dfStorages.index = [''] * len(dfStorages)
        print(dfStorages)
        print("")

        print("\nList of connected and disconnected events of all the storages:")
        dfStorageConnectedDisconnected = pd.DataFrame(tableConnectedDisconnected)
        dfStorageConnectedDisconnected.index = [''] * len(dfStorageConnectedDisconnected)
        print(dfStorageConnectedDisconnected)
        print("")

        tempFlag = False
        while(tempFlag == False):
            option = input("\nChoose one of the storage indexes to view the connected and disconnected events (input anything other than listed index to quit)> ")
            if(option.isnumeric()):
                option = int(option)
                if(option > 0 and option <= len(tableStorage["Serial Number"])):
                    tableStorageConnectAndDisconnect = {"No":[], "Connected":[], "Disconnected":[]}
                    try:
                        tableSerialNum = ''.join(tableStorage["Serial Number"][option-1]).split()[0]
                    except:
                        tableSerialNum = tableStorage["Serial Number"][option-1]
                    conFlag = False
                    for index, serialNum in enumerate(tableConnectedDisconnected["Serial Number"]):
                        if(serialNum == tableSerialNum):
                            eventType = tableConnectedDisconnected["Event Type"][index]
                            time = tableConnectedDisconnected["Time"][index]
                            if(eventType == "Connected"):
                                if(conFlag == True):
                                    tableStorageConnectAndDisconnect["Disconnected"].append("")
                                tableStorageConnectAndDisconnect["Connected"].append(time)
                                conFlag = True
                            else:
                                if(conFlag == False):
                                    tableStorageConnectAndDisconnect["Connected"].append("")
                                tableStorageConnectAndDisconnect["Disconnected"].append(time)
                                conFlag = False
                    if(conFlag == True):
                        tableStorageConnectAndDisconnect["Disconnected"].append("")

                    for index in range(len(tableStorageConnectAndDisconnect["Connected"])):
                        tableStorageConnectAndDisconnect["No"].append(index+1)

                    print("List of connected and disconnected events for the storage:")
                    dfSpecificStorageConnectDisconnect = pd.DataFrame(tableStorageConnectAndDisconnect)
                    dfSpecificStorageConnectDisconnect.index = [''] * len(dfSpecificStorageConnectDisconnect)
                    print(dfSpecificStorageConnectDisconnect)

                else:
                    tempFlag = True
            else:
                tempFlag = True

        tempFlag = False
        while(tempFlag == False):
            option = input("\nChoose one of the storage indexes to view the MBR partition table (input anything other than listed index to quit)> ")
            if(option.isnumeric()):
                option = int(option)
                if(option > 0 and option <= len(tableStorage["Serial Number"])):
                    if(tableStorage["Partition Style"][option-1] == "MBR"):
                        serialNumList = tableStorage["Serial Number"][option-1]
                        try:
                            serialNum = ''.join(serialNumList).split()[0]
                        except:
                            serialNum = serialNumList
                        mbrValue = ""
                        fileSystemId = []
                        bootableFlag = []
                        partitionsSize = []
                        startingSectorStorages = []
                        for record in log.records():
                            data = record.xml()
                            serialNumTemp = re.search('<Data Name="SerialNumber">(.*)</Data>', data).group(1).split()
                            try:
                                serialNumCurr = serialNumTemp[0]
                            except:
                                serialNumCurr= serialNumTemp
                            mbrBytes = re.search('<Data Name="MbrBytes">(.*)</Data>', data).group(1)
                            if(serialNumCurr == serialNum and mbrBytes != "0"):
                                if(mbrValue == ""):
                                    mbrValue = re.search('<Data Name="Mbr">(.*)</Data>', data).group(1)
                                    decodedMbrText = base64.b64decode(mbrValue)
                                    hexMbrText = base64.b16encode(decodedMbrText)
                                    try:
                                        vbr0Bytes = re.search('<Data Name="Vbr0Bytes">(.*)</Data>', data).group(1)
                                        if(vbr0Bytes != "0"):
                                            if(hexMbrText[892:894] == b"80"):
                                                bootableFlag.append("True")
                                            else:
                                                bootableFlag.append("False")
                                            startingSector = int(b'0x'+hexMbrText[914:916]+hexMbrText[912:914]+hexMbrText[910:912]+hexMbrText[908:910], base=16)
                                            startingSectorStorages.append(startingSector)
                                            sizeOfPartition = int(b'0x'+hexMbrText[922:924]+hexMbrText[920:922]+hexMbrText[918:920]+hexMbrText[916:918], base=16)*int(tableStorage["Bytes Per Sector"][option-1])
                                            partitionsSize.append(sizeOfPartition)
                                            if(hexMbrText[900:902] == b"07" and base64.b64decode(re.search('<Data Name="Vbr0">(.*)</Data>', data).group(1))[3:7] != b"NTFS"):
                                                fileSystemId.append("exFAT")
                                            else:
                                                fileSystemId.append(hexMbrText[900:902])
                                    except:
                                        pass
                                    try:
                                        vbr1Bytes = re.search('<Data Name="Vbr1Bytes">(.*)</Data>', data).group(1)
                                        if(vbr1Bytes != "0"):
                                            if(hexMbrText[924:926] == b"80"):
                                                bootableFlag.append("True")
                                            else:
                                                bootableFlag.append("False")
                                            startingSector = int(b'0x'+hexMbrText[946:948]+hexMbrText[944:946]+hexMbrText[942:944]+hexMbrText[940:942], base=16)
                                            startingSectorStorages.append(startingSector)
                                            sizeOfPartition = int(b'0x'+hexMbrText[954:956]+hexMbrText[952:954]+hexMbrText[950:952]+hexMbrText[948:950], base=16)*int(tableStorage["Bytes Per Sector"][option-1])
                                            partitionsSize.append(sizeOfPartition)
                                            if(hexMbrText[932:934] == b"07" and base64.b64decode(re.search('<Data Name="Vbr1">(.*)</Data>', data).group(1))[3:7] != b"NTFS"):
                                                fileSystemId.append("exFAT")
                                            else:
                                                fileSystemId.append(hexMbrText[932:934])
                                    except:
                                        pass
                                    try:
                                        vbr2Bytes = re.search('<Data Name="Vbr2Bytes">(.*)</Data>', data).group(1)
                                        if(vbr2Bytes != "0"):
                                            if(hexMbrText[956:958] == b"80"):
                                                bootableFlag.append("True")
                                            else:
                                                bootableFlag.append("False")
                                            startingSector = int(b'0x'+hexMbrText[978:980]+hexMbrText[976:978]+hexMbrText[974:976]+hexMbrText[972:974], base=16)
                                            startingSectorStorages.append(startingSector)
                                            sizeOfPartition = int(b'0x'+hexMbrText[986:988]+hexMbrText[984:986]+hexMbrText[982:984]+hexMbrText[980:982], base=16)*int(tableStorage["Bytes Per Sector"][option-1])
                                            partitionsSize.append(sizeOfPartition)
                                            if(hexMbrText[964:966] == b"07" and base64.b64decode(re.search('<Data Name="Vbr2">(.*)</Data>', data).group(1))[3:7] != b"NTFS"):
                                                fileSystemId.append("exFAT")
                                            else:
                                                fileSystemId.append(hexMbrText[964:966])
                                    except:
                                        pass
                                    try:
                                        vbr3Bytes = re.search('<Data Name="Vbr3Size">(.*)</Data>', data).group(1)
                                        if(vbr3Bytes != "0"):
                                            if(hexMbrText[988:990] == b"80"):
                                                bootableFlag.append("True")
                                            else:
                                                bootableFlag.append("False")
                                            startingSector = int(b'0x'+hexMbrText[1010:1012]+hexMbrText[1008:1010]+hexMbrText[1006:1008]+hexMbrText[1004:1006], base=16)
                                            startingSectorStorages.append(startingSector)
                                            sizeOfPartition = int(b'0x'+hexMbrText[1018:1020]+hexMbrText[1016:1018]+hexMbrText[1014:1016]+hexMbrText[1012:1014], base=16)*int(tableStorage["Bytes Per Sector"][option-1])
                                            partitionsSize.append(sizeOfPartition)
                                            if(hexMbrText[996:998] == b"07" and base64.b64decode(re.search('<Data Name="Vbr3">(.*)</Data>', data).group(1))[3:7] != b"NTFS"):
                                                fileSystemId.append("exFAT")
                                            else:
                                                fileSystemId.append(hexMbrText[996:998])
                                    except:
                                        pass
                                else:
                                    mbrValueTemp = re.search('<Data Name="Mbr">(.*)</Data>', data).group(1)
                                    if(mbrValue != mbrValueTemp):
                                        mbrValue = mbrValueTemp
                                        fileSystemId.clear()
                                        startingSectorStorages.clear()
                                        partitionsSize.clear()
                                        bootableFlag.clear()
                                        decodedMbrText = base64.b64decode(mbrValue)
                                        hexMbrText = base64.b16encode(decodedMbrText)
                                        try:
                                            vbr0Bytes = re.search('<Data Name="Vbr0Bytes">(.*)</Data>', data).group(1)
                                            if(vbr0Bytes != "0"):
                                                if(hexMbrText[892:894] == b"80"):
                                                    bootableFlag.append("True")
                                                else:
                                                    bootableFlag.append("False")
                                                startingSector = int(b'0x'+hexMbrText[914:916]+hexMbrText[912:914]+hexMbrText[910:912]+hexMbrText[908:910], base=16)
                                                startingSectorStorages.append(startingSector)
                                                sizeOfPartition = int(b'0x'+hexMbrText[922:924]+hexMbrText[920:922]+hexMbrText[918:920]+hexMbrText[916:918], base=16)*int(tableStorage["Bytes Per Sector"][option-1])
                                                partitionsSize.append(sizeOfPartition)
                                                if(hexMbrText[900:902] == b"07" and base64.b64decode(re.search('<Data Name="Vbr0">(.*)</Data>', data).group(1))[3:7] != b"NTFS"):
                                                    fileSystemId.append("exFAT")
                                                else:
                                                    fileSystemId.append(hexMbrText[900:902])
                                        except:
                                            pass
                                        try:
                                            vbr1Bytes = re.search('<Data Name="Vbr1Bytes">(.*)</Data>', data).group(1)
                                            if(vbr1Bytes != "0"):
                                                if(hexMbrText[924:926] == b"80"):
                                                    bootableFlag.append("True")
                                                else:
                                                    bootableFlag.append("False")
                                                startingSector = int(b'0x'+hexMbrText[946:948]+hexMbrText[944:946]+hexMbrText[942:944]+hexMbrText[940:942], base=16)
                                                startingSectorStorages.append(startingSector)
                                                sizeOfPartition = int(b'0x'+hexMbrText[954:956]+hexMbrText[952:954]+hexMbrText[950:952]+hexMbrText[948:950], base=16)*int(tableStorage["Bytes Per Sector"][option-1])
                                                partitionsSize.append(sizeOfPartition)
                                                if(hexMbrText[932:934] == b"07" and base64.b64decode(re.search('<Data Name="Vbr1">(.*)</Data>', data).group(1))[3:7] != b"NTFS"):
                                                    fileSystemId.append("exFAT")
                                                else:
                                                    fileSystemId.append(hexMbrText[932:934])
                                        except:
                                            pass
                                        try:
                                            vbr2Bytes = re.search('<Data Name="Vbr2Bytes">(.*)</Data>', data).group(1)
                                            if(vbr2Bytes != "0"):
                                                if(hexMbrText[956:958] == b"80"):
                                                    bootableFlag.append("True")
                                                else:
                                                    bootableFlag.append("False")
                                                startingSector = int(b'0x'+hexMbrText[978:980]+hexMbrText[976:978]+hexMbrText[974:976]+hexMbrText[972:974], base=16)
                                                startingSectorStorages.append(startingSector)
                                                sizeOfPartition = int(b'0x'+hexMbrText[986:988]+hexMbrText[984:986]+hexMbrText[982:984]+hexMbrText[980:982], base=16)*int(tableStorage["Bytes Per Sector"][option-1])
                                                partitionsSize.append(sizeOfPartition)
                                                if(hexMbrText[964:966] == b"07" and base64.b64decode(re.search('<Data Name="Vbr2">(.*)</Data>', data).group(1))[3:7] != b"NTFS"):
                                                    fileSystemId.append("exFAT")
                                                else:
                                                    fileSystemId.append(hexMbrText[964:966])
                                        except:
                                            pass
                                        try:
                                            vbr3Bytes = re.search('<Data Name="Vbr3Size">(.*)</Data>', data).group(1)
                                            if(vbr3Bytes != "0"):
                                                if(hexMbrText[988:990] == b"80"):
                                                    bootableFlag.append("True")
                                                else:
                                                    bootableFlag.append("False")
                                                startingSector = int(b'0x'+hexMbrText[1010:1012]+hexMbrText[1008:1010]+hexMbrText[1006:1008]+hexMbrText[1004:1006], base=16)
                                                startingSectorStorages.append(startingSector)
                                                sizeOfPartition = int(b'0x'+hexMbrText[1018:1020]+hexMbrText[1016:1018]+hexMbrText[1014:1016]+hexMbrText[1012:1014], base=16)*int(tableStorage["Bytes Per Sector"][option-1])
                                                partitionsSize.append(sizeOfPartition)
                                                if(hexMbrText[996:998] == b"07" and base64.b64decode(re.search('<Data Name="Vbr3">(.*)</Data>', data).group(1))[3:7] != b"NTFS"):
                                                    fileSystemId.append("exFAT")
                                                else:
                                                    fileSystemId.append(hexMbrText[996:998])
                                        except:
                                            pass
                        
                        print(f"\nThere are {len(fileSystemId)} partition(s) found on the selected storage.")
                        tablePartition = {"No":[], "Partition":[], "Bootable Flag":[], "File System":[], "Starting Sectors":[], "Size (bytes)":[]}
                        partitionCounter = 0
                        for eachBootableFlag in bootableFlag:
                            tablePartition["Bootable Flag"].append(eachBootableFlag)
                        for partitionSize in partitionsSize:
                            tablePartition["Size (bytes)"].append(partitionSize)
                        for startingSectorStorage in startingSectorStorages:
                            tablePartition["Starting Sectors"].append(startingSectorStorage)
                        for fileSystem in fileSystemId:
                            partitionCounter += 1
                            tablePartition["Partition"].append(partitionCounter)
                            if(fileSystem == b"00"):
                                tablePartition["File System"].append("Empty")
                            elif(fileSystem == b"01"):
                                tablePartition["File System"].append("FAT12, CHS")
                            elif(fileSystem == b"04"):
                                tablePartition["File System"].append("FAT16, 16-32MB, CHS")
                            elif(fileSystem == b"05"):
                                tablePartition["File System"].append("Microsoft Extended, CHS")
                            elif(fileSystem == b"06"):
                                tablePartition["File System"].append("FAT16, 32MB-2GB, CHS")
                            elif(fileSystem == b"07"):
                                tablePartition["File System"].append("NTFS")
                            elif(fileSystem == b"0B"):
                                tablePartition["File System"].append("FAT32, CHS")
                            elif(fileSystem == b"0C"):
                                tablePartition["File System"].append("FAT32, LBA")
                            elif(fileSystem == b"0E"):
                                tablePartition["File System"].append("FAT16, 32MB-2GB, LBA")
                            elif(fileSystem == b"0F"):
                                tablePartition["File System"].append("Microsoft Extended, LBA")
                            elif(fileSystem == b"11"):
                                tablePartition["File System"].append("Hidden FAT12, CHS")
                            elif(fileSystem == b"14"):
                                tablePartition["File System"].append("Hidden FAT16, 16-32MB, CHS")
                            elif(fileSystem == b"16"):
                                tablePartition["File System"].append("Hidden FAT16, 32MB-2GB, CHS")
                            elif(fileSystem == b"1B"):
                                tablePartition["File System"].append("Hidden FAT32, CHS")
                            elif(fileSystem == b"1C"):
                                tablePartition["File System"].append("Hidden FAT32, LBA")
                            elif(fileSystem == b"1E"):
                                tablePartition["File System"].append("Hidden FAT16, 32MB-2GB, LBA")
                            elif(fileSystem == b"42"):
                                tablePartition["File System"].append("Microsoft MBR. Dynamic Disk")
                            elif(fileSystem == b"82"):
                                tablePartition["File System"].append("Solaris x86 / Linux Swap")
                            elif(fileSystem == b"83"):
                                tablePartition["File System"].append("Linux")
                            elif(fileSystem == b"84"):
                                tablePartition["File System"].append("Hibernation")
                            elif(fileSystem == b"85"):
                                tablePartition["File System"].append("Linux Extended")
                            elif(fileSystem == b"86"):
                                tablePartition["File System"].append("NTFS Volume Set")
                            elif(fileSystem == b"87"):
                                tablePartition["File System"].append("NTFS Volume Set")
                            elif(fileSystem == b"A0"):
                                tablePartition["File System"].append("Hibernation")
                            elif(fileSystem == b"A1"):
                                tablePartition["File System"].append("Hibernation")
                            elif(fileSystem == b"A5"):
                                tablePartition["File System"].append("FreeBSD")
                            elif(fileSystem == b"A6"):
                                tablePartition["File System"].append("OpenBSD")
                            elif(fileSystem == b"A8"):
                                tablePartition["File System"].append("Mac OSX")
                            elif(fileSystem == b"A9"):
                                tablePartition["File System"].append("NetBSD")
                            elif(fileSystem == b"AB"):
                                tablePartition["File System"].append("Mac OSX Boot")
                            elif(fileSystem == b"B7"):
                                tablePartition["File System"].append("BSDI")
                            elif(fileSystem == b"B8"):
                                tablePartition["File System"].append("BSDI Swap")
                            elif(fileSystem == b"EE"):
                                tablePartition["File System"].append("EFI GPT Disk")
                            elif(fileSystem == b"EF"):
                                tablePartition["File System"].append("EFI System Partition")
                            elif(fileSystem == b"FB"):
                                tablePartition["File System"].append("Vmware File System")
                            elif(fileSystem == b"FC"):
                                tablePartition["File System"].append("Vmware Swap")
                            elif(fileSystem == "exFAT"):
                                tablePartition["File System"].append("exFAT")
                            else:
                                tablePartition["File System"].append("Unknown")

                        for index in range(len(tablePartition["File System"])):
                            tablePartition["No"].append(index+1)
                        dfSpecificStoragePartitions = pd.DataFrame(tablePartition)
                        dfSpecificStoragePartitions.index = [''] * len(dfSpecificStoragePartitions)
                        print(dfSpecificStoragePartitions)
                    else:
                        print(f"Partition table on storage {option} cannot be listed since the partition style is not MBR")
                else:
                    tempFlag = True
            else:
                tempFlag = True

    if(export == "y"):
        print("\nWhich table you want to export? (Please choose one or more tables)")
        print("1. List of storages")
        print("2. List of connected and disconnected events of the storages")
        print("3. List of connected and disconnected events of the specific storage")
        print("4. List of partitions of the specific storage")
        exportChoice = input("> ")
        if(exportChoice.lower() == "all"):
            exportChoice = "1, 2, 3, 4"
        exportChoice = ''.join(exportChoice.split())
        listOfExportChoice = exportChoice.split(',')
        if("1" in listOfExportChoice):
            dfStorages.to_csv(outputPath+'/listOfStorages.csv', index=False)
        if("2" in listOfExportChoice):
            dfStorageConnectedDisconnected.to_csv(outputPath+'/listOfStorageConnectedDisconnected.csv', index=False)
        if("3" in listOfExportChoice):
            choice3 = input("\nWhich connected and disconnected events of the storages you want to export? (Please choose one or more storages)> ")
            listOfChoice3 = []
            if(choice3 == "all"):
                for index in range(len(tableStorage["Serial Number"])):
                    listOfChoice3.append(index+1)
            else:
                choice3 = ''.join(choice3.split())
                listOfChoice3 = choice3.split(',')
            for option in listOfChoice3:
                option = int(option)
                tableStorageConnectAndDisconnect = {"No":[], "Connected":[], "Disconnected":[]}
                try:
                    tableSerialNum = ''.join(tableStorage["Serial Number"][option-1]).split()[0]
                except:
                    tableSerialNum = tableStorage["Serial Number"][option-1]
                conFlag = False
                for index, serialNum in enumerate(tableConnectedDisconnected["Serial Number"]):
                    if(serialNum == tableSerialNum):
                        eventType = tableConnectedDisconnected["Event Type"][index]
                        time = tableConnectedDisconnected["Time"][index]
                        if(eventType == "Connected"):
                            if(conFlag == True):
                                tableStorageConnectAndDisconnect["Disconnected"].append("")
                            tableStorageConnectAndDisconnect["Connected"].append(time)
                            conFlag = True
                        else:
                            if(conFlag == False):
                                tableStorageConnectAndDisconnect["Connected"].append("")
                            tableStorageConnectAndDisconnect["Disconnected"].append(time)
                            conFlag = False
                if(conFlag == True):
                    tableStorageConnectAndDisconnect["Disconnected"].append("")

                for index in range(len(tableStorageConnectAndDisconnect["Connected"])):
                    tableStorageConnectAndDisconnect["No"].append(index+1)

                dfSpecificStorageConnectDisconnect = pd.DataFrame(tableStorageConnectAndDisconnect)
                dfSpecificStorageConnectDisconnect.index = [''] * len(dfSpecificStorageConnectDisconnect)
                dfSpecificStorageConnectDisconnect.to_csv(outputPath+f'/listOfSpecificStorageConnectDisconnect{option}.csv', index=False)
        if("4" in listOfExportChoice):
            with evtx.Evtx(pathPartitionDiagnostic) as log:
                choice4 = input("\nWhich partition table of the storages you want to export? (Please choose one or more storages)> ")
                listOfChoice4 = []
                if(choice4 == "all"):
                    for index in range(len(tableStorage["Serial Number"])):
                        listOfChoice4.append(index+1)
                else:
                    choice4 = ''.join(choice4.split())
                    listOfChoice4 = choice4.split(',')
                for option in listOfChoice4:
                    tablePartition = {"No":[], "Partition":[], "File System":[]}
                    option = int(option)
                    if(option > 0 and option <= len(tableStorage["Serial Number"])):
                        if(tableStorage["Partition Style"][option-1] == "MBR"):
                            serialNumList = tableStorage["Serial Number"][option-1]
                            try:
                                serialNum = ''.join(serialNumList).split()[0]
                            except:
                                serialNum = serialNumList
                            mbrValue = ""
                            fileSystemId = []
                            for record in log.records():
                                data = record.xml()
                                serialNumTemp = re.search('<Data Name="SerialNumber">(.*)</Data>', data).group(1).split()
                                try:
                                    serialNumCurr = serialNumTemp[0]
                                except:
                                    serialNumCurr= serialNumTemp
                                mbrBytes = re.search('<Data Name="MbrBytes">(.*)</Data>', data).group(1)
                                if(serialNumCurr == serialNum and mbrBytes != "0"):
                                    if(mbrValue == ""):
                                        mbrValue = re.search('<Data Name="Mbr">(.*)</Data>', data).group(1)
                                        decodedMbrText = base64.b64decode(mbrValue)
                                        hexMbrText = base64.b16encode(decodedMbrText)
                                        try:
                                            vbr0Bytes = re.search('<Data Name="Vbr0Bytes">(.*)</Data>', data).group(1)
                                            if(vbr0Bytes != "0"):
                                                if(hexMbrText[900:902] == b"07" and base64.b64decode(re.search('<Data Name="Vbr0">(.*)</Data>', data).group(1))[3:7] != b"NTFS"):
                                                    fileSystemId.append("exFAT")
                                                else:
                                                    fileSystemId.append(hexMbrText[900:902])
                                        except:
                                            pass
                                        try:
                                            vbr1Bytes = re.search('<Data Name="Vbr1Bytes">(.*)</Data>', data).group(1)
                                            if(vbr1Bytes != "0"):
                                                if(hexMbrText[932:934] == b"07" and base64.b64decode(re.search('<Data Name="Vbr1">(.*)</Data>', data).group(1))[3:7] != b"NTFS"):
                                                    fileSystemId.append("exFAT")
                                                else:
                                                    fileSystemId.append(hexMbrText[932:934])
                                        except:
                                            pass
                                        try:
                                            vbr2Bytes = re.search('<Data Name="Vbr2Bytes">(.*)</Data>', data).group(1)
                                            if(vbr2Bytes != "0"):
                                                if(hexMbrText[964:966] == b"07" and base64.b64decode(re.search('<Data Name="Vbr2">(.*)</Data>', data).group(1))[3:7] != b"NTFS"):
                                                    fileSystemId.append("exFAT")
                                                else:
                                                    fileSystemId.append(hexMbrText[964:966])
                                        except:
                                            pass
                                        try:
                                            vbr3Bytes = re.search('<Data Name="Vbr3Size">(.*)</Data>', data).group(1)
                                            if(vbr3Bytes != "0"):
                                                if(hexMbrText[996:998] == b"07" and base64.b64decode(re.search('<Data Name="Vbr3">(.*)</Data>', data).group(1))[3:7] != b"NTFS"):
                                                    fileSystemId.append("exFAT")
                                                else:
                                                    fileSystemId.append(hexMbrText[996:998])
                                        except:
                                            pass
                                    else:
                                        mbrValueTemp = re.search('<Data Name="Mbr">(.*)</Data>', data).group(1)
                                        if(mbrValue != mbrValueTemp):
                                            mbrValue = mbrValueTemp
                                            fileSystemId.clear()
                                            decodedMbrText = base64.b64decode(mbrValue)
                                            hexMbrText = base64.b16encode(decodedMbrText)
                                            try:
                                                vbr0Bytes = re.search('<Data Name="Vbr0Bytes">(.*)</Data>', data).group(1)
                                                if(vbr0Bytes != "0"):
                                                    if(hexMbrText[900:902] == b"07" and base64.b64decode(re.search('<Data Name="Vbr0">(.*)</Data>', data).group(1))[3:7] != b"NTFS"):
                                                        fileSystemId.append("exFAT")
                                                    else:
                                                        fileSystemId.append(hexMbrText[900:902])
                                            except:
                                                pass
                                            try:
                                                vbr1Bytes = re.search('<Data Name="Vbr1Bytes">(.*)</Data>', data).group(1)
                                                if(vbr1Bytes != "0"):
                                                    if(hexMbrText[932:934] == b"07" and base64.b64decode(re.search('<Data Name="Vbr1">(.*)</Data>', data).group(1))[3:7] != b"NTFS"):
                                                        fileSystemId.append("exFAT")
                                                    else:
                                                        fileSystemId.append(hexMbrText[932:934])
                                            except:
                                                pass
                                            try:
                                                vbr2Bytes = re.search('<Data Name="Vbr2Bytes">(.*)</Data>', data).group(1)
                                                if(vbr2Bytes != "0"):
                                                    if(hexMbrText[964:966] == b"07" and base64.b64decode(re.search('<Data Name="Vbr2">(.*)</Data>', data).group(1))[3:7] != b"NTFS"):
                                                        fileSystemId.append("exFAT")
                                                    else:
                                                        fileSystemId.append(hexMbrText[964:966])
                                            except:
                                                pass
                                            try:
                                                vbr3Bytes = re.search('<Data Name="Vbr3Size">(.*)</Data>', data).group(1)
                                                if(vbr3Bytes != "0"):
                                                    if(hexMbrText[996:998] == b"07" and base64.b64decode(re.search('<Data Name="Vbr3">(.*)</Data>', data).group(1))[3:7] != b"NTFS"):
                                                        fileSystemId.append("exFAT")
                                                    else:
                                                        fileSystemId.append(hexMbrText[996:998])
                                            except:
                                                pass
                            
                            partitionCounter = 0
                            for fileSystem in fileSystemId:
                                partitionCounter += 1
                                tablePartition["Partition"].append(partitionCounter)
                                if(fileSystem == b"00"):
                                    tablePartition["File System"].append("Empty")
                                elif(fileSystem == b"01"):
                                    tablePartition["File System"].append("FAT12, CHS")
                                elif(fileSystem == b"04"):
                                    tablePartition["File System"].append("FAT16, 16-32MB, CHS")
                                elif(fileSystem == b"05"):
                                    tablePartition["File System"].append("Microsoft Extended, CHS")
                                elif(fileSystem == b"06"):
                                    tablePartition["File System"].append("FAT16, 32MB-2GB, CHS")
                                elif(fileSystem == b"07"):
                                    tablePartition["File System"].append("NTFS")
                                elif(fileSystem == b"0B"):
                                    tablePartition["File System"].append("FAT32, CHS")
                                elif(fileSystem == b"0C"):
                                    tablePartition["File System"].append("FAT32, LBA")
                                elif(fileSystem == b"0E"):
                                    tablePartition["File System"].append("FAT16, 32MB-2GB, LBA")
                                elif(fileSystem == b"0F"):
                                    tablePartition["File System"].append("Microsoft Extended, LBA")
                                elif(fileSystem == b"11"):
                                    tablePartition["File System"].append("Hidden FAT12, CHS")
                                elif(fileSystem == b"14"):
                                    tablePartition["File System"].append("Hidden FAT16, 16-32MB, CHS")
                                elif(fileSystem == b"16"):
                                    tablePartition["File System"].append("Hidden FAT16, 32MB-2GB, CHS")
                                elif(fileSystem == b"1B"):
                                    tablePartition["File System"].append("Hidden FAT32, CHS")
                                elif(fileSystem == b"1C"):
                                    tablePartition["File System"].append("Hidden FAT32, LBA")
                                elif(fileSystem == b"1E"):
                                    tablePartition["File System"].append("Hidden FAT16, 32MB-2GB, LBA")
                                elif(fileSystem == b"42"):
                                    tablePartition["File System"].append("Microsoft MBR. Dynamic Disk")
                                elif(fileSystem == b"82"):
                                    tablePartition["File System"].append("Solaris x86 / Linux Swap")
                                elif(fileSystem == b"83"):
                                    tablePartition["File System"].append("Linux")
                                elif(fileSystem == b"84"):
                                    tablePartition["File System"].append("Hibernation")
                                elif(fileSystem == b"85"):
                                    tablePartition["File System"].append("Linux Extended")
                                elif(fileSystem == b"86"):
                                    tablePartition["File System"].append("NTFS Volume Set")
                                elif(fileSystem == b"87"):
                                    tablePartition["File System"].append("NTFS Volume Set")
                                elif(fileSystem == b"A0"):
                                    tablePartition["File System"].append("Hibernation")
                                elif(fileSystem == b"A1"):
                                    tablePartition["File System"].append("Hibernation")
                                elif(fileSystem == b"A5"):
                                    tablePartition["File System"].append("FreeBSD")
                                elif(fileSystem == b"A6"):
                                    tablePartition["File System"].append("OpenBSD")
                                elif(fileSystem == b"A8"):
                                    tablePartition["File System"].append("Mac OSX")
                                elif(fileSystem == b"A9"):
                                    tablePartition["File System"].append("NetBSD")
                                elif(fileSystem == b"AB"):
                                    tablePartition["File System"].append("Mac OSX Boot")
                                elif(fileSystem == b"B7"):
                                    tablePartition["File System"].append("BSDI")
                                elif(fileSystem == b"B8"):
                                    tablePartition["File System"].append("BSDI Swap")
                                elif(fileSystem == b"EE"):
                                    tablePartition["File System"].append("EFI GPT Disk")
                                elif(fileSystem == b"EF"):
                                    tablePartition["File System"].append("EFI System Partition")
                                elif(fileSystem == b"FB"):
                                    tablePartition["File System"].append("Vmware File System")
                                elif(fileSystem == b"FC"):
                                    tablePartition["File System"].append("Vmware Swap")
                                elif(fileSystem == "exFAT"):
                                    tablePartition["File System"].append("exFAT")
                                else:
                                    tablePartition["File System"].append("Unknown")

                            for index in range(len(tablePartition["File System"])):
                                tablePartition["No"].append(index+1)

                            dfSpecificStoragePartitions = pd.DataFrame(tablePartition)
                            dfSpecificStoragePartitions.index = [''] * len(dfSpecificStoragePartitions)
                            dfSpecificStoragePartitions.to_csv(outputPath+f'/listOfSpecificStoragePartitions{option}.csv', index=False)
                        else:
                            print(f"Partition table on storage {option} cannot be exported since the partition style is not MBR")

def boot(path, export, outputPath):
    with evtx.Evtx(path) as log:
        table = {"No":[], "Boot Time":[], "Last Sleep Time Detected":[], "Boot Type":[]}
        lastTimeSleepDetected = ""
        flagBootTypeOne = False
        flagBootTypeTwo = False
        sleepFlag = False
        sleepFlagCounter = 0
        for record in log.records():
            try:
                data = record.xml()
                if(re.search('<Level>(.*)</Level>', data).group(1) == "4"):
                    eventID = re.search('>(.*)</EventID>', data).group(1)
                    if(eventID == "27"):
                        bootType = re.search('<Data Name="BootType">(.*)</Data>', data).group(1)
                        if(sleepFlag == True):
                            sleepFlag = False
                            sleepFlagCounter = 0
                        if(bootType == "0"):
                            eventTime = re.search('<TimeCreated SystemTime="(.*)"></TimeCreated>', data).group(1)
                            table["Boot Time"].append(eventTime + " UTC")
                            table["Boot Type"].append("Started after full shutdown")
                            if(lastTimeSleepDetected == ""):
                                table["Last Sleep Time Detected"].append("")
                            else:
                                table["Last Sleep Time Detected"].append(lastTimeSleepDetected + " UTC")
                                lastTimeSleepDetected = ""
                                flagBootTypeOne = False
                                flagBootTypeTwo = False
                                sleepFlag = False
                                sleepFlagCounter = 0
                        elif(bootType == "1"):
                            table["Boot Type"].append("Started with Fast Startup")
                            flagBootTypeOne = True
                        elif(bootType == "2"):
                            table["Boot Type"].append("Resumed from hibernation")
                            flagBootTypeTwo = True
                    elif(eventID == "1" and re.search('<Version>(.*)</Version>', data).group(1) != "0"):
                        version = re.search('<Version>(.*)</Version>', data).group(1)
                        if(flagBootTypeOne == True):
                            try:
                                wakeTime = re.search('<Data Name="WakeTime">(.*)</Data>', data).group(1)
                                sleepTime = re.search('<Data Name="SleepTime">(.*)</Data>', data).group(1)
                            except:
                                wakeTime = re.search('<Data Name="NewTime">(.*)</Data>', data).group(1)
                                sleepTime = re.search('<Data Name="OldTime">(.*)</Data>', data).group(1)
                            table["Boot Time"].append(wakeTime + " UTC")
                            table["Last Sleep Time Detected"].append(sleepTime + " UTC")
                            flagBootTypeOne = False
                            lastTimeSleepDetected = ""
                            flagBootTypeTwo = False
                            sleepFlag = False
                            sleepFlagCounter = 0
                        elif(flagBootTypeTwo == True and version == "3"):
                            try:
                                wakeTime = re.search('<Data Name="WakeTime">(.*)</Data>', data).group(1)
                                sleepTime = re.search('<Data Name="SleepTime">(.*)</Data>', data).group(1)
                            except:
                                wakeTime = re.search('<Data Name="NewTime">(.*)</Data>', data).group(1)
                                sleepTime = re.search('<Data Name="OldTime">(.*)</Data>', data).group(1)
                            table["Boot Time"].append(wakeTime + " UTC")
                            table["Last Sleep Time Detected"].append(sleepTime + " UTC")
                            flagBootTypeTwo = False
                            lastTimeSleepDetected = ""
                            flagBootTypeOne = False
                            sleepFlag = False
                            sleepFlagCounter = 0
                        elif(sleepFlag == True):
                            sleepFlagCounter += 1
                            if(sleepFlagCounter == 2):
                                try:
                                    wakeTime = re.search('<Data Name="WakeTime">(.*)</Data>', data).group(1)
                                    sleepTime = re.search('<Data Name="SleepTime">(.*)</Data>', data).group(1)
                                except:
                                    wakeTime = re.search('<Data Name="NewTime">(.*)</Data>', data).group(1)
                                    sleepTime = re.search('<Data Name="OldTime">(.*)</Data>', data).group(1)
                                table["Boot Type"].append("Resumed after sleep (not a booting process)")
                                table["Boot Time"].append(wakeTime + " UTC")
                                table["Last Sleep Time Detected"].append(sleepTime + " UTC")
                                sleepFlag = False
                                sleepFlagCounter = 0
                                lastTimeSleepDetected = ""
                                flagBootTypeOne = False
                                flagBootTypeTwo = False
                    elif(eventID == "107"):
                        if(sleepFlag == False):
                            sleepFlag = True
                        elif(sleepFlag == True):
                            sleepFlag = False
                            sleepFlagCounter = 0
                    elif(eventID == "6006"):
                        eventTime = re.search('<TimeCreated SystemTime="(.*)"></TimeCreated>', data).group(1)
                        lastTimeSleepDetected = eventTime
            except:
                pass

    for index in range(len(table["Boot Time"])):
        table["No"].append(index+1)

    print("\nList of boot activity:")

    dfBoot = pd.DataFrame(table)
    dfBoot.index = [''] * len(dfBoot)
    print(dfBoot)

    if(export == "y"):
        dfBoot.to_csv(outputPath+'/listOfBootEvents.csv', index=False)

def wlan(path, export, outputPath):
    with evtx.Evtx(path) as log:
        table = {"No":[], "SSID":[], "Connection Time":[], "Disconnection Time":[], "PHY Type":[], "Authentication":[], "Encryption":[], "802.1x":[], "Hidden":[], "Connection Mode":[], "Disconnect Reason":[]}
        wlanList = {"No":[], "SSID":[]}
        wlanPublicList = {"No":[], "SSID":[]}
        flag = False
        firstEntryFlag = False
        for record in log.records():
            data = record.xml()
            eventID = re.search('>(.*)</EventID>', data).group(1)
            if(eventID == "8001"):
                firstEntryFlag = True
                time = re.search('<TimeCreated SystemTime="(.*)"></TimeCreated>', data).group(1)
                ssid = re.search('<Data Name="SSID">(.*)</Data>', data).group(1)
                phy = re.search('<Data Name="PHYType">(.*)</Data>', data).group(1)
                auth = re.search('<Data Name="AuthenticationAlgorithm">(.*)</Data>', data).group(1)
                enc = re.search('<Data Name="CipherAlgorithm">(.*)</Data>', data).group(1)
                onex = re.search('<Data Name="OnexEnabled">(.*)</Data>', data).group(1)
                hidden = re.search('<Data Name="NonBroadcast">(.*)</Data>', data).group(1)
                conMode = re.search('<Data Name="ConnectionMode">(.*)</Data>', data).group(1)
                if(onex == "0"):
                    onexStr = "Disabled"
                else:
                    onexStr = "Enabled"
                table['SSID'].append(ssid)
                table['Connection Time'].append(time + " UTC")
                table['PHY Type'].append(phy)
                table['Authentication'].append(auth)
                table['Encryption'].append(enc)
                table['802.1x'].append(onexStr)
                table['Hidden'].append(hidden)
                table['Connection Mode'].append(conMode)
                if(flag == False):
                    flag = True
                else:
                    table['Disconnection Time'].append("")
                    table['Disconnect Reason'].append("")
                if(auth == "Open" and ssid not in wlanPublicList['SSID']):
                    wlanPublicList['SSID'].append(ssid)
                if(ssid not in wlanList['SSID']):
                    wlanList['SSID'].append(ssid)
            elif(eventID == "8003"):
                if(firstEntryFlag == True):  
                    time = re.search('<TimeCreated SystemTime="(.*)"></TimeCreated>', data).group(1)
                    disReason = re.search('<Data Name="Reason">(.*)</Data>', data).group(1)
                    table['Disconnection Time'].append(time + " UTC")
                    table['Disconnect Reason'].append(disReason)
                    flag = False
                else:
                    firstEntryFlag = True
                    ssid = re.search('<Data Name="SSID">(.*)</Data>', data).group(1)
                    table['SSID'].append(ssid)
                    table['Connection Time'].append("")
                    table['PHY Type'].append("")
                    table['Authentication'].append("")
                    table['Encryption'].append("")
                    table['802.1x'].append("")
                    table['Hidden'].append("")
                    table['Connection Mode'].append("")
                    time = re.search('<TimeCreated SystemTime="(.*)"></TimeCreated>', data).group(1)
                    disReason = re.search('<Data Name="Reason">(.*)</Data>', data).group(1)
                    table['Disconnection Time'].append(time + " UTC")
                    table['Disconnect Reason'].append(disReason)
                    flag = False
        if(flag == True):
            table['Disconnection Time'].append("")
            table['Disconnect Reason'].append("")

    for index in range(len(wlanList["SSID"])):
        wlanList["No"].append(index+1)

    for index in range(len(wlanPublicList["SSID"])):
        wlanPublicList["No"].append(index+1)

    for index in range(len(table["SSID"])):
        table["No"].append(index+1)

    dfWlanList = pd.DataFrame(wlanList)
    dfWlanPublicList = pd.DataFrame(wlanPublicList)
    dfWlanFull = pd.DataFrame(table)
    print("\nWhich table you want to view? (Please choose one or more tables)")
    print("1. List of WLAN profile")
    print("2. List of WLAN profile (no authentication only)")
    print("3. List of connected and disconnected events")
    viewChoice = input("> ")
    if(viewChoice.lower() == "all"):
        viewChoice = "1, 2, 3"
    viewChoice = ''.join(viewChoice.split())
    listOfViewChoice = viewChoice.split(',')
    if("1" in listOfViewChoice):
        print("\nWLAN Profile List:")
        dfWlanList.index = [''] * len(dfWlanList)
        if(len(dfWlanList) == 0):
            print("There is no WLAN found")
        else:
            print(dfWlanList)
    if("2" in listOfViewChoice):
        dfWlanPublicList.index = [''] * len(dfWlanPublicList)
        print("\nWarning! These WLAN profile has no authentication:")
        if(len(dfWlanPublicList) == 0):
            print("There is no WLAN profile that has no authentication")
        else:
            print(dfWlanPublicList)
    if("3" in listOfViewChoice):
        print("\nList of connected and disconnected events:")
        dfWlanFull.index = [''] * len(dfWlanFull)
        if(len(dfWlanFull) == 0):
            print("There is no WLAN found")
        else:
            print(dfWlanFull)

    if(export == "y"):
        print("\nWhich table you want to export? (Please choose one or more tables)")
        print("1. List of WLAN profile")
        print("2. List of WLAN profile (no authentication only)")
        print("3. List of connected and disconnected events")
        exportChoice = input("> ")
        if(exportChoice.lower() == "all"):
            exportChoice = "1, 2, 3"
        exportChoice = ''.join(exportChoice.split())
        listOfExportChoice = exportChoice.split(',')
        if("1" in listOfExportChoice):
            if(len(dfWlanList) == 0):
                print("List of WLAN profile cannot be exported since no WLAN found")
            else:
                dfWlanList.to_csv(outputPath+'/listOfWlanProfile.csv', index=False)
        if("2" in listOfExportChoice):
            if(len(dfWlanPublicList) == 0):
                print("List of WLAN profile that has no authentication cannot be exported since there is no WLAN profile that has no authentication")
            else:
                dfWlanPublicList.to_csv(outputPath+'/listOfWlanProfileNoAuth.csv', index=False)
        if("3" in listOfExportChoice):
            if(len(dfWlanFull) == 0):
                print("List of coonected and disconnected cannot be exported since no WLAN found")
            else:
                dfWlanFull.to_csv(outputPath+'/listOfConAndDisconWlan.csv', index=False)

def systemTimeChange(path, export, outputPath):
    with evtx.Evtx(path) as log:
        table = {"No":[], "From":[], "To":[]}
        mode = False
        flag = False
        for record in log.records():
            try:
                data = record.xml()
                eventID = re.search('>(.*)</EventID>', data).group(1)
                if(eventID == "7040"):
                    service = re.search('<Data Name="param1">(.*)</Data>', data).group(1)
                    to = re.search('<Data Name="param3">(.*)</Data>', data).group(1)
                    if(service == "Windows Time"):
                        if(to == "disabled"):
                            mode = True
                        elif(to == "demand start"):
                            mode = False
                            flag = True
                elif(eventID == "1"):
                    if(mode == True):
                        task = re.search('<Task>(.*)</Task>', data).group(1)
                        if(task == "5"):
                            newTime = re.search('<Data Name="NewTime">(.*)</Data>', data).group(1)
                            oldTime = re.search('<Data Name="OldTime">(.*)</Data>', data).group(1)
                            process = re.search('<Data Name="ProcessName">(.*)</Data>', data).group(1).split("\\")[-1]
                            if(newTime != oldTime and process == "SystemSettingsAdminFlows.exe"):
                                table['From'].append(oldTime + " UTC")
                                table['To'].append(newTime + " UTC")
                    else:
                        if(flag == True):
                            task = re.search('<Task>(.*)</Task>', data).group(1)
                            if(task == "5"):
                                newTime = re.search('<Data Name="NewTime">(.*)</Data>', data).group(1)
                                oldTime = re.search('<Data Name="OldTime">(.*)</Data>', data).group(1)
                                table['From'].append(oldTime + " UTC")
                                table['To'].append(newTime + " UTC")
                                flag = False
            except:
                pass

    for index in range(len(table["From"])):
        table["No"].append(index+1)

    print("\nList of system time changes done by user manually:")
    dfSystemTimeChange = pd.DataFrame(table)
    dfSystemTimeChange.index = [''] * len(dfSystemTimeChange)
    if(len(dfSystemTimeChange) == 0):
        print("There is no system time changes done by user manually")
    else:
        print(dfSystemTimeChange)
        if(export == "y"):
            dfSystemTimeChange.to_csv(outputPath+'/listOfSystemTimeChangesManual.csv', index=False)

def windowsDefender(path, export, outputPath):
    with evtx.Evtx(path) as log:
        table = {"No":[], "Threat Name":[], "Severity":[], "Category":[], "Path":[], "Detection Origin":[], "Detection Type":[], "Detection Source":[], "User":[], "Process Name":[], "Protected by Microsoft Defender Antivirus":[]}
        for record in log.records():
            data = record.xml()
            eventID = re.search('<EventID Qualifiers="">(.*)</EventID>', data).group(1)
            if(eventID == "1116"):
                name = re.search('<Data Name="Threat Name">(.*)</Data>', data).group(1)
                severity = re.search('<Data Name="Severity Name">(.*)</Data>', data).group(1)
                category = re.search('<Data Name="Category Name">(.*)</Data>', data).group(1)
                path = re.search('<Data Name="Path">(.*)</Data>', data).group(1)
                detectionOrigin = re.search('<Data Name="Origin Name">(.*)</Data>', data).group(1)
                detectionType = re.search('<Data Name="Type Name">(.*)</Data>', data).group(1)
                detectionSource = re.search('<Data Name="Source Name">(.*)</Data>', data).group(1)
                user = re.search('<Data Name="Detection User">(.*)</Data>', data).group(1)
                processName = re.search('<Data Name="Process Name">(.*)</Data>', data).group(1)
                flag = 0
                for index, entry in enumerate(table["Threat Name"]):
                    if(name == entry):
                        if(severity == table["Severity"][index] and category == table["Category"][index] and detectionOrigin == table["Detection Origin"][index] and detectionType == table["Detection Type"][index] and detectionSource == table["Detection Source"][index] and user == table["User"][index] and processName == table["Process Name"][index]):
                            if(len(path)>len(table["Path"][index])):
                                table["Path"][index] = path
                            flag = 1
                            break
                if(flag == 0):
                    table["Threat Name"].append(name)
                    table["Severity"].append(severity)
                    table["Category"].append(category)
                    table["Path"].append(path)
                    table["Detection Origin"].append(detectionOrigin)
                    table["Detection Type"].append(detectionType)
                    table["Detection Source"].append(detectionSource)
                    table["User"].append(user)
                    table["Process Name"].append(processName)
                    table["Protected by Microsoft Defender Antivirus"].append("False")
            elif(eventID == "1117"):
                name = re.search('<Data Name="Threat Name">(.*)</Data>', data).group(1)
                severity = re.search('<Data Name="Severity Name">(.*)</Data>', data).group(1)
                category = re.search('<Data Name="Category Name">(.*)</Data>', data).group(1)
                path = re.search('<Data Name="Path">(.*)</Data>', data).group(1)
                detectionOrigin = re.search('<Data Name="Origin Name">(.*)</Data>', data).group(1)
                detectionType = re.search('<Data Name="Type Name">(.*)</Data>', data).group(1)
                detectionSource = re.search('<Data Name="Source Name">(.*)</Data>', data).group(1)
                user = re.search('<Data Name="Detection User">(.*)</Data>', data).group(1)
                processName = re.search('<Data Name="Process Name">(.*)</Data>', data).group(1)
                for index, entry in enumerate(table["Threat Name"]):
                    if(name == entry):
                        if(severity == table["Severity"][index] and category == table["Category"][index] and path == table["Path"][index] and detectionOrigin == table["Detection Origin"][index] and detectionType == table["Detection Type"][index] and detectionSource == table["Detection Source"][index] and user == table["User"][index] and processName == table["Process Name"][index]):
                            table["Protected by Microsoft Defender Antivirus"][index] = "True"

    tableWarning = {"No":[], "Threat Name":[], "Severity":[], "Category":[], "Path":[], "Detection Origin":[], "Detection Type":[], "Detection Source":[], "User":[], "Process Name":[], "Protected by Microsoft Defender Antivirus":[]}
    for protected in table["Protected by Microsoft Defender Antivirus"]:
        if(protected == "False"):
            index = table["Protected by Microsoft Defender Antivirus"].index(protected)
            tableWarning["Category"].append(table["Category"][index])
            tableWarning["Detection Origin"].append(table["Detection Origin"][index])
            tableWarning["Detection Source"].append(table["Detection Source"][index])
            tableWarning["Detection Type"].append(table["Detection Type"][index])
            tableWarning["Path"].append(table["Path"][index])
            tableWarning["Process Name"].append(table["Process Name"][index])
            tableWarning["Protected by Microsoft Defender Antivirus"].append(table["Protected by Microsoft Defender Antivirus"][index])
            tableWarning["Severity"].append(table["Severity"][index])
            tableWarning["Threat Name"].append(table["Threat Name"][index])
            tableWarning["User"].append(table["User"][index])

    for index in range(len(table["User"])):
        table["No"].append(index+1)
    
    for index in range(len(tableWarning["User"])):
        tableWarning["No"].append(index+1)

    dfMalwareNotProtected = pd.DataFrame(tableWarning)
    dfMalwareDetected = pd.DataFrame(table)
    print("\nWhich table you want to view? (Please choose one or more tables)")
    print("1. List of malware detected but not protected by Windows Defender")
    print("2. List of malware detected by Windows Defender")
    viewChoice = input("> ")
    if(viewChoice.lower() == "all"):
        viewChoice = "1, 2"
    viewChoice = ''.join(viewChoice.split())
    listOfViewChoice = viewChoice.split(',')
    if("1" in listOfViewChoice):
        print("\nList of malware detected but not protected by Windows Defender:")
        dfMalwareNotProtected.index = [''] * len(dfMalwareNotProtected)
        if(len(dfMalwareNotProtected) == 0):
            print("All detected malware are protected by Windows Defender")
        else:
            print(dfMalwareNotProtected)
    if("2" in listOfViewChoice):
        print("\nList of malware detected by Windows Defender:")
        dfMalwareDetected.index = [''] * len(dfMalwareDetected)
        if(len(dfMalwareDetected) == 0):
            print("There is no malware detected by Windows Defender")
        else:
            print(dfMalwareDetected)

    if(export == "y"):
        print("\nWhich table you want to export? (Please choose one or more tables)")
        print("1. List of malware detected but not protected by Windows Defender")
        print("2. List of malware detected by Windows Defender")
        exportChoice = input("> ")
        if(exportChoice.lower() == "all"):
            exportChoice = "1, 2"
        exportChoice = ''.join(exportChoice.split())
        listOfExportChoice = exportChoice.split(',')
        if("1" in listOfExportChoice):
            if(len(dfMalwareNotProtected) == 0):
                print("List of malware detected but not protected by Windows Defender cannot be exported since all detected malware are protected by Windows Defender")
            else:
                dfMalwareNotProtected.to_csv(outputPath+'/listOfMalwareNotProtectedByWinDefender.csv', index=False)
        if("2" in listOfExportChoice):
            if(len(dfMalwareDetected) == 0):
                print("List of malware detected by Windows Defender cannot be exported since there is no malware detected by Windows Defender")
            else:
                dfMalwareDetected.to_csv(outputPath+'/listOfMalwareDetectedByWinDefender.csv', index=False)

def userLogonoff(path, export, outputPath):
    with evtx.Evtx(path) as log:
        tableUserLog = {"No":[], "User Logon Time":[], "User Logoff Time":[]}
        onFlag = False
        for record in log.records():
            try:
                data = record.xml()
                eventID = re.search('>(.*)</EventID>', data).group(1)
                taskCat = re.search('>(.*)</Task>', data).group(1)
                if(eventID == "7001" and taskCat == "1101"):
                    time = re.search('<TimeCreated SystemTime="(.*)"></TimeCreated>', data).group(1)
                    tableUserLog['User Logon Time'].append(time + " UTC")
                    if(onFlag == False):
                        onFlag = True
                    else:
                        tableUserLog['User Logoff Time'].append("")
                elif(eventID == "7002" and taskCat == "1102"):
                    if(onFlag == False):
                        tableUserLog["User Logon Time"].append("")
                    time = re.search('<TimeCreated SystemTime="(.*)"></TimeCreated>', data).group(1)
                    tableUserLog['User Logoff Time'].append(time + " UTC")
                    onFlag = False
            except:
                pass
        if(onFlag == True):
            tableUserLog['User Logoff Time'].append("")
    
    for index in range(len(tableUserLog["User Logoff Time"])):
        tableUserLog["No"].append(index+1)

    print("\nList of user logon and logoff timestamps:")
    dfUserLog = pd.DataFrame(tableUserLog)
    dfUserLog.index = [''] * len(dfUserLog)
    print(dfUserLog)

    if(export == "y"):
        dfUserLog.to_csv(outputPath+'/listOfUserLogonLogoff.csv', index=False)

def printer(path, export, outputPath):
    with evtx.Evtx(path) as log:
        tablePrintedDoc = {"No":[], "Printer Name":[], "Port Used":[], "User":[], "Computer Name":[], "Total Page(s) of the File Printed":[], "Size of the File Printed (Bytes)":[], "Timestamp":[]}
        tablePrintedDocMicToPDF = {"No":[], "User":[], "Computer Name":[], "File":[],"Total Page(s) of the File Printed":[], "Size of the File Printed (Bytes)":[], "Timestamp":[]}
        tablePrinterList = {"No":[], "Printer Name":[]}
        for record in log.records():
            data = record.xml()
            eventID = re.search('<EventID Qualifiers="">(.*)</EventID>', data).group(1)
            taskID = re.search('<Task>(.*)</Task>', data).group(1)
            if(eventID == "306" and taskID == "17"):
                printerName = re.search('<Param1>(.*)</Param1>', data).group(1)
                tablePrinterList["Printer Name"].append(printerName)
            elif(eventID == "307" and taskID == "26"):
                time = re.search('<TimeCreated SystemTime="(.*)"></TimeCreated>', data).group(1)
                printerName = re.search('<Param5>(.*)</Param5>', data).group(1)
                user = re.search('<Param3>(.*)</Param3>', data).group(1)
                computer = re.search('<Param4>\\\\\\\\(.*)</Param4>', data).group(1)
                pages = re.search('<Param8>(.*)</Param8>', data).group(1)
                size = re.search('<Param7>(.*)</Param7>', data).group(1)
                if(printerName == "Microsoft Print to PDF"):
                    file = re.search('<Param6>(.*)</Param6>', data).group(1)
                    tablePrintedDocMicToPDF['User'].append(user)
                    tablePrintedDocMicToPDF['Computer Name'].append(computer)
                    tablePrintedDocMicToPDF['File'].append(file)
                    tablePrintedDocMicToPDF['Total Page(s) of the File Printed'].append(pages)
                    tablePrintedDocMicToPDF['Size of the File Printed (Bytes)'].append(size)
                    tablePrintedDocMicToPDF['Timestamp'].append(time + " UTC")
                else:
                    port = re.search('<Param6>(.*)</Param6>', data).group(1)
                    tablePrintedDoc['Printer Name'].append(printerName)
                    tablePrintedDoc['Port Used'].append(port)
                    tablePrintedDoc['User'].append(user)
                    tablePrintedDoc['Computer Name'].append(computer)
                    tablePrintedDoc['Total Page(s) of the File Printed'].append(pages)
                    tablePrintedDoc['Size of the File Printed (Bytes)'].append(size)
                    tablePrintedDoc['Timestamp'].append(time + " UTC")
        
        for index in range(len(tablePrintedDoc["Computer Name"])):
            tablePrintedDoc["No"].append(index+1)

        for index in range(len(tablePrintedDocMicToPDF["Computer Name"])):
            tablePrintedDocMicToPDF["No"].append(index+1)

        for index in range(len(tablePrinterList["Printer Name"])):
            tablePrinterList["No"].append(index+1)

        dfPrinterConfigured = pd.DataFrame(tablePrinterList)
        dfPrint = pd.DataFrame(tablePrintedDoc)
        dfPrinterDocMicToPDF = pd.DataFrame(tablePrintedDocMicToPDF)
        print("\nWhich table you want to view? (Please choose one or more tables)")
        print("1. List of printer configured")
        print("2. List of printing events")
        print("3. List of Microsoft Print to PDF events")
        viewChoice = input("> ")
        if(viewChoice.lower() == "all"):
            viewChoice = "1, 2, 3"
        viewChoice = ''.join(viewChoice.split())
        listOfViewChoice = viewChoice.split(',')
        if("1" in listOfViewChoice):
            print("\nList of printer configured:")
            dfPrinterConfigured.index = [''] * len(dfPrinterConfigured)
            if(len(dfPrinterConfigured) == 0):
                print("There is no printer configured")
            else:
                print(dfPrinterConfigured)
        if("2" in listOfViewChoice):
            print("\nList of printing events:")
            dfPrint.index = [''] * len(dfPrint)
            if(len(dfPrint) == 0):
                print("There is no printing events found")
            else:
                print(dfPrint)
        if("3" in listOfViewChoice):
            print("\nList of Microsoft Print to PDF events:")
            dfPrinterDocMicToPDF.index = [''] * len(dfPrinterDocMicToPDF)
            if(len(dfPrinterDocMicToPDF) == 0):
                print("There is no Microsoft Print to PDF events found")
            else:
                print(dfPrinterDocMicToPDF)

        if(export == "y"):
            print("\nWhich table you want to export? (Please choose one or more tables)")
            print("1. List of printer configured")
            print("2. List of printing events")
            print("3. List of Microsoft Print to PDF events")
            exportChoice = input("> ")
            if(exportChoice.lower() == "all"):
                exportChoice = "1, 2, 3"
            exportChoice = ''.join(exportChoice.split())
            listOfExportChoice = exportChoice.split(',')
            if("1" in listOfExportChoice):
                if(len(dfPrinterConfigured) == 0):
                    print("List of printer configured cannot be exported since there is no printer configured")
                else:
                    dfPrinterConfigured.to_csv(outputPath+'/listOfPrinterConfigured.csv', index=False)
            if("2" in listOfExportChoice):
                if(len(dfPrint) == 0):
                    print("List of printing events cannot be exported since there is no printing events found")
                else:
                    dfPrint.to_csv(outputPath+'/listOfPrintingEvents.csv', index=False)
            if("3" in listOfExportChoice):
                if(len(dfPrinterDocMicToPDF) == 0):
                    print("List of Microsoft Print to PDF events cannot be exported since there is no Microsoft Print to PDF events found")
                else:
                    dfPrinterDocMicToPDF.to_csv(outputPath+'/listOfMicrosoftPrinttoPDFEvents.csv', index=False)

def microsoftOffice(path, export, outputPath):
    officeExtList = ['.odt', '.pdf', '.rtf', '.txt', '.csv', '.doc', '.dot', '.wbk', '.docx', '.docm', '.dotx', '.dotm', '.docb', '.pdf', '.wll', '.wwl', '.xls', '.xlt', '.xlm', '.xll', '.xla', '.xlsx', '.xlsm', '.xltx', '.xltm', '.xlsb', '.xlam', '.xla', '.xll', '.xlw', '.ppt', '.pot', '.pps', '.ppam', '.ppa', '.pptx', '.pptm', '.potx', '.potm', '.ppam', '.ppsx', '.ppsm', '.sldx', '.sldm', '.pa', '.ACCDU', '.ACCDT', '.ACCDR', '.ACCDE', '.ACCDB', '.ACCDA', '.MDA', '.MDE', '.one', '.ecf', '.pub', '.xps']
    fileCount = 0
    with evtx.Evtx(path) as log:
        fileList = {'No':[], "Filename":[], "Counter":[]}
        warningFileList = {'No':[], "Filename":[], "Counter":[]}
        table = {"No":[], "Office Product":[], "Version":[], "Alert":[], "File":[], "Time":[]}
        dataList = []
        for record in log.records():
            data = record.xml()
            time = re.search('<TimeCreated SystemTime="(.*)"></TimeCreated>', data)
            level = re.search('<Level>(.*)</Level>', data).group(1)
            if(level == "4"):
                toBeAppend = re.findall("&lt;string&gt;(.*)", data)
                toBeAppend.append(time.group(1) + " UTC")
                dataList.append(toBeAppend)
        for entry in dataList:
            if(entry[0]!="Activated App" and entry[0]!="Remove Account"):
                try:
                    table["Version"].append(entry[3])
                    table["Office Product"].append(entry[0])
                    table["Alert"].append(entry[1])
                    table["Time"].append(entry[6])
                    filename = ''
                    if '.' in entry[1]:
                        flag = False
                        extIndexStart = 0
                        while(flag == False):
                            lastIndexStart = extIndexStart
                            extIndexStart = entry[1].find('.', extIndexStart+1)
                            if(extIndexStart == -1):
                                flag = True
                                break
                            extIndexEnd = entry[1].find(' ', extIndexStart)
                            if(extIndexStart+1 != len(entry[1])):
                                if(entry[1][extIndexStart+1].isalnum()):
                                    flag = True
                                    ext = entry[1][extIndexStart:extIndexEnd]
                                    while('.' in ext[1:]):
                                        extIdxTemp = ext.rfind('.')
                                        ext = ext[:extIdxTemp]
                                    idxLastFileName = entry[1].find('.', lastIndexStart+1)
                                    substr = entry[1][0:idxLastFileName]
                                    if(substr.rfind("\"")!=-1):
                                        idxStartFileName = substr.rfind("\"")
                                        filename = entry[1][idxStartFileName+1:idxLastFileName] + ext[:-1]
                                    elif(substr.rfind("\'")!=-1):
                                        idxStartFileName = substr.rfind('\'')
                                        filename = entry[1][idxStartFileName+1:idxLastFileName] + ext[:-1]
                                    elif(substr.rfind("\\")!=-1):
                                        idxStartFileName = substr.rfind('\\')
                                        filename = entry[1][idxStartFileName+1:idxLastFileName] + ext
                                    elif(substr.rfind("/")!=-1):
                                        idxStartFileName = substr.rfind('/')
                                        filename = entry[1][idxStartFileName+1:idxLastFileName] + ext
                                    elif("You already have a file named " in substr):
                                        filename = substr.lstrip("You already have a file named ") + ext
                                    else:
                                        idxStartFileName = substr.rfind(" ")
                                        filename = entry[1][idxStartFileName+1:idxLastFileName] + ext
                                    table["File"].append(filename)
                                    fileCount += 1
                                    if filename in fileList['Filename']:
                                        index = fileList['Filename'].index(filename)
                                        fileList['Counter'][index] += 1
                                    else:
                                        fileList['Filename'].append(filename)
                                        fileList['Counter'].append(1)
                    if(filename == ''):
                        if("Want to save your changes to " in entry[1]):
                            tempFilename = entry[1].lstrip("Want to save your changes to ")
                            filename = tempFilename.rstrip("?")
                            fileCount += 1
                            table['File'].append(filename)
                            if filename in fileList['Filename']:
                                index = fileList['Filename'].index(filename)
                                fileList['Counter'][index] += 1
                            else:
                                fileList['Filename'].append(filename)
                                fileList['Counter'].append(1)
                        else:
                            table["File"].append('')
                except:
                    continue

        for filename in fileList['Filename']:
            flag = False
            for ext in officeExtList:
                if(ext in filename.lower()):
                    flag = True
                    break
            if(flag == False):
                warningFileList['Filename'].append(filename)
                index = fileList['Filename'].index(filename)
                warningFileList['Counter'].append(fileList['Counter'][index])
        
        for index in range(len(warningFileList["Filename"])):
            warningFileList["No"].append(index+1)

        for index in range(len(fileList["Filename"])):
            fileList["No"].append(index+1)

        for index in range(len(table["Office Product"])):
            table["No"].append(index+1)

        dfWarning = pd.DataFrame(warningFileList)
        dfFileList=pd.DataFrame(fileList)
        dfAlert=pd.DataFrame(table)
        print("\nWhich table you want to view? (Please choose one or more tables)")
        print("1. List of suspicious files found")
        print("2. List of files found")
        print("3. List of alerts")
        viewChoice = input("> ")
        if(viewChoice.lower() == "all"):
            viewChoice = "1, 2, 3"
        viewChoice = ''.join(viewChoice.split())
        listOfViewChoice = viewChoice.split(',')
        if("1" in listOfViewChoice):
            print("\nList of suspicious files found:")
            dfWarning.index = [''] * len(dfWarning)
            if(len(dfWarning) == 0):
                print("No suspicious file found")
            else:
                print(dfWarning)
        if("2" in listOfViewChoice):
            print("\nList of files found:")
            dfFileList.index = [''] * len(dfFileList)
            if(len(dfFileList) == 0):
                print("No file found")
            else:
                print(dfFileList)
        if("3" in listOfViewChoice):
            print("\nList of alerts:")
            dfAlert.index = [''] * len(dfAlert)
            if(len(dfAlert) == 0):
                print("No alerts found")
            else:
                print(dfAlert)
        if(export == "y"):
            print("\nWhich table you want to export? (Please choose one or more tables)")
            print("1. List of suspicious files found")
            print("2. List of files found")
            print("3. List of alerts")
            exportChoice = input("> ")
            if(exportChoice.lower() == "all"):
                exportChoice = "1, 2, 3"
            exportChoice = ''.join(exportChoice.split())
            listOfExportChoice = exportChoice.split(',')
            if("1" in listOfExportChoice):
                if(len(dfWarning) == 0):
                    print("List of suspicious files cannot be exported since there is no suspicious file found")
                else:
                    dfWarning.to_csv(outputPath+'/listOfOfficeSuspiciousFilesFound.csv', index=False)
            if("2" in listOfExportChoice):
                if(len(dfFileList) == 0):
                    print("List of files cannot be exported since there in no file found")
                else:
                    dfFileList.to_csv(outputPath+'/listOfOfficeFilesFound.csv', index=False)
            if("3" in listOfExportChoice):
                if(len(dfAlert) == 0):
                    print("List of alerts cannot be exported since there is no alert found")
                else:
                    dfAlert.to_csv(outputPath+'/listOfOfficeAlertsFound.csv', index=False)

def powershell(path, export, outputPath):
    obfuscatedFlag = input("Would you like to do obfuscation detection with deep learning? (This process may take longer time)> ")
    if(obfuscatedFlag.lower() == "y" or obfuscatedFlag.lower() == "yes"):
        oc = od.ObfuscationClassifier(od.PlatformType.ALL)
        tableObfuscated = {"No":[], "Command":[], "Timestamp":[]}
    with evtx.Evtx(path) as log:
        table = {"No":[], "Command":[], "Timestamp":[]}
        tableObfuscatedBase64 = {"No":[], "Command":[], "DecryptedString":[], "Timestamp":[]}
        for record in log.records():
            data = record.xml()
            flag = False
            time = re.search('<TimeCreated SystemTime="(.*)"></TimeCreated>', data).group(1)
            command = re.search('\sHostApplication=(.*)\r\s', data).group(1)
            if(command != "powershell" and command.endswith("powershell.exe") == False):
                table['Command'].append(command)
                table['Timestamp'].append(time)
                if(" -e " in command):
                    flag = True
                    try:
                        encoded = re.search(' -e (.*)$', command).group(1)
                    except:
                        encoded = re.search(' -e (.*) ', command).group(1)
                    if(encoded != "cmd"):
                        decoded = base64.b64decode(encoded).decode('UTF-16LE')
                elif (" -E " in command):
                    flag = True
                    try:
                        encoded = re.search(' -E (.*)$', command).group(1)
                    except:
                        encoded = re.search(' -E (.*) ', command).group(1)
                    if(encoded != "cmd"):
                        decoded = base64.b64decode(encoded).decode('UTF-16LE')
                elif(" -ec " in command):
                    flag = True
                    try:
                        encoded = re.search(' -ec (.*)$', command).group(1)
                    except:
                        encoded = re.search(' -ec (.*) ', command).group(1)
                    decoded = base64.b64decode(encoded).decode('UTF-16LE')
                elif(" -enc " in command):
                    flag = True
                    try:
                        encoded = re.search(' -enc (.*)$', command).group(1)
                    except:
                        encoded = re.search(' -enc (.*) ', command).group(1)
                    decoded = base64.b64decode(encoded).decode('UTF-16LE')
                elif(" -EncodedCommand " in command):
                    flag = True
                    try:
                        encoded = re.search(' -EncodedCommand (.*)$', command).group(1)
                    except:
                        encoded = re.search(' -EncodedCommand (.*) ', command).group(1)
                    decoded = base64.b64decode(encoded).decode('UTF-16LE')
                elif("FromBase64String((('" in command):
                    flag = True
                    encoded = re.search("FromBase64String\(\(\('(.*)'\)(.*)\)\)\)\)", command).group(1)
                    try:
                        try:
                            decoded = base64.b64decode(encoded).decode('UTF-16LE')
                        except:
                            decoded = gzip.decompress(base64.b64decode(encoded)).decode()
                    except:
                        decoded = encoded
                if(flag == True):
                    tableObfuscatedBase64['DecryptedString'].append(decoded)
                    tableObfuscatedBase64['Command'].append(command)
                    tableObfuscatedBase64['Timestamp'].append(time)
            
            if(obfuscatedFlag.lower() == "y" or obfuscatedFlag.lower() == "yes"):
                classCommand = [command]
                classifications = oc(classCommand)
                if(classifications[0] == 1):
                    tableObfuscated["Command"].append(command)
                    tableObfuscated["Timestamp"].append(time)

    for index in range(len(table["Command"])):
        table["No"].append(index+1)

    if(obfuscatedFlag.lower() == "y" or obfuscatedFlag.lower() == "yes"):
        for index in range(len(tableObfuscated["Command"])):
            tableObfuscated["No"].append(index+1)
    
    for index in range(len(tableObfuscatedBase64["Command"])):
        tableObfuscatedBase64["No"].append(index+1)

    dfCommand = pd.DataFrame(table)
    dfObfuscatedBase64 = pd.DataFrame(tableObfuscatedBase64)
    print("\nWhich table you want to view? (Please choose one or more tables)")
    print("1. List of commands run on PowerShell")
    print("2. List of commands encoded by using base64 run on Powershell")
    if(obfuscatedFlag.lower() == "y" or obfuscatedFlag.lower() == "yes"):
        print("3. List of obfuscated commands run on Powershell")
        dfObfuscated = pd.DataFrame(tableObfuscated)
    viewChoice = input("> ")
    if(viewChoice.lower() == "all"):
        if(obfuscatedFlag.lower() == "y" or obfuscatedFlag.lower() == "yes"):
            viewChoice = "1, 2, 3"
        else:
            viewChoice = "1, 2"
    viewChoice = ''.join(viewChoice.split())
    listOfViewChoice = viewChoice.split(',')
    if("1" in listOfViewChoice):
        print("\nList of commands run on PowerShell:")
        dfCommand.index = [''] * len(dfCommand)
        if(len(dfCommand) == 0):
            print("There is no command run on PowerShell")
        else:
            print(dfCommand)
    if("2" in listOfViewChoice):
        print("\nList of commands encoded by using base64 run on Powershell:")
        dfObfuscatedBase64.index = [''] * len(dfObfuscatedBase64)
        if(len(dfObfuscatedBase64) == 0):
            print("There is no command encoded by using base64 run on PowerShell")
        else:
            print(dfObfuscatedBase64)
    if(obfuscatedFlag.lower() == "y" or obfuscatedFlag.lower() == "yes"):
        if("3" in listOfViewChoice):
            print("\nList of obfuscated commands run on Powershell:")
            dfObfuscated.index = [''] * len(dfObfuscated)
            if(len(dfObfuscated) == 0):
                print("There is no obfuscated command run on PowerShell")
            else:
                print(dfObfuscated)

    if(export == "y"):
        print("\nWhich table you want to export? (Please choose one or more tables)")
        print("1. List of commands run on Powershell")
        print("2. List of commands encoded by using base64 run on Powershell")
        if(obfuscatedFlag.lower() == "y" or obfuscatedFlag.lower() == "yes"):
            print("3. List of obfuscated commands run on Powershell")
        exportChoice = input("> ")
        if(exportChoice.lower() == "all"):
            if(obfuscatedFlag.lower() == "y" or obfuscatedFlag.lower() == "yes"):
                exportChoice = "1, 2, 3"
            else:
                exportChoice = "1, 2"
        exportChoice = ''.join(exportChoice.split())
        listOfExportChoice = exportChoice.split(',')
        if("1" in listOfExportChoice):
            if(len(dfCommand) == 0):
                print("List of commands run on PowerShell cannot be exported since there is no command run on PowerShell")
            else:
                dfCommand.to_csv(outputPath+'/listOfPowershellCommand.csv', index=False)
        if("2" in listOfExportChoice):
            if(len(dfObfuscatedBase64) == 0):
                print("List of commands encoded by using base64 run on PowerShell cannot be exported since there is no command encoded by using base64 run on PowerShell")
            else:
                dfObfuscatedBase64.to_csv(outputPath+'/listOfPowershellObfuscatedBase64Command.csv', index=False)
        if(obfuscatedFlag.lower() == "y" or obfuscatedFlag.lower() == "yes"):
            if("3" in listOfExportChoice):
                if(len(dfObfuscated) == 0):
                    print("List of obfuscated commands run on PowerShell cannot be exported since there is no obfuscated command run on PowerShell")
                else:
                    dfObfuscated.to_csv(outputPath+'/listOfPowershellObfuscatedCommand.csv', index=False)

def main():
    CONTINUEUSINGTOOL = True
    while(CONTINUEUSINGTOOL == True):
        FUNCTION1 = False
        FUNCTION2 = False
        FUNCTION3 = False
        FUNCTION4 = False
        FUNCTION5 = False
        FUNCTION6 = False
        FUNCTION7 = False
        FUNCTION8 = False
        FUNCTION9 = False
        print("============================================")
        print("Wielview version 0.1.0")
        print("Author: Williams Kosasi")
        print("https://github.com/williamskosasi")
        print("============================================")
        
        print("1. Run the function")
        print("2. Help")
        firstChoice = input("Choice> ")

        if(firstChoice == "1"):
            print("\nList of functions:")
            print("1. Storage")
            print("2. Boot")
            print("3. WLAN")
            print("4. System Time Change")
            print("5. Windows Defender")
            print("6. User Logon/Logoff")
            print("7. Printer")
            print("8. Microsoft Office")
            print("9. PowerShell")

            print("\nPlease choose one or more functions")
            print("Examples:")
            print("1")
            print("1, 2")
            print("1, 2, 3")
            print("all")

            functionChoice = input("\nChoice> ")

            if(functionChoice.lower() == "all"):
                functionChoice = "1, 2, 3, 4, 5, 6, 7, 8, 9"
            
            functionChoice = ''.join(functionChoice.split())
            listOfChosenFunction = functionChoice.split(',')
            
            if('1' in listOfChosenFunction):
                FUNCTION1 = True
            if('2' in listOfChosenFunction):
                FUNCTION2 = True
            if('3' in listOfChosenFunction):
                FUNCTION3 = True
            if('4' in listOfChosenFunction):
                FUNCTION4 = True
            if('5' in listOfChosenFunction):
                FUNCTION5 = True
            if('6' in listOfChosenFunction):
                FUNCTION6 = True
            if('7' in listOfChosenFunction):
                FUNCTION7 = True
            if('8' in listOfChosenFunction):
                FUNCTION8 = True
            if('9' in listOfChosenFunction):
                FUNCTION9 = True

            tempFlag = False
            while(tempFlag == False):
                folderOrFilesChoice = input("\nWhich one you want to specify? (d=folder, f=file)> ")
                if(folderOrFilesChoice.lower() == "d" or folderOrFilesChoice.lower() == "folder" or folderOrFilesChoice.lower() == "f" or folderOrFilesChoice.lower() == "file"):
                    tempFlag = True
            folderOrFilesChoice = folderOrFilesChoice.lower()
            if(folderOrFilesChoice == "folder"):
                folderOrFilesChoice == "d"
            elif(folderOrFilesChoice == "file"):
                folderOrFilesChoice == "f"

            if(folderOrFilesChoice == "d"):
                print("\nMake sure that you have admin privileges if you are doing live analysis")
                print("Please specify the path of the folder containing:")
                if(FUNCTION1):
                    print("- Microsoft-Windows-Partition%4Diagnostic.evtx")
                    print("- Microsoft-Windows-Storage-Storport%4Health.evtx")
                    print("- Microsoft-Windows-Storsvc%4Diagnostic.evtx")
                if(FUNCTION2 or FUNCTION4 or FUNCTION6):
                    print("- System.evtx")
                if(FUNCTION3):
                    print("- Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx")
                if(FUNCTION5):
                    print("- Microsoft-Windows-Windows Defender%4Operational.evtx")
                if(FUNCTION7):
                    print("- Microsoft-Windows-PrintService%4Operational.evtx")
                if(FUNCTION8):
                    print("- OAlerts.evtx")
                if(FUNCTION9):
                    print("- Windows PowerShell.evtx")
                print("\nDefault: %SystemRoot%/System32/winevt/Logs")
                folderPath = input("> ").replace("\"","").replace("'","")
            elif(folderOrFilesChoice == "f"):
                print("\nMake sure that you have admin privileges if you are doing live analysis")
                if(FUNCTION1):
                    f1aPath = input("Please specify the path of Microsoft-Windows-Partition%4Diagnostic.evtx> ").replace("\"","").replace("'","")
                    f1bPath = input("Please specify the path of Microsoft-Windows-Storage-Storport%4Health.evtx> ").replace("\"","").replace("'","")
                    f1cPath = input("Please specify the path of Microsoft-Windows-Storsvc%4Diagnostic.evtx> ").replace("\"","").replace("'","")
                if(FUNCTION2 or FUNCTION4 or FUNCTION6):
                    f246Path = input("Please specify the path of System.evtx> ").replace("\"","").replace("'","")
                if(FUNCTION3):
                    f3Path = input("Please specify the path of Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx> ").replace("\"","").replace("'","")
                if(FUNCTION5):
                    f5Path = input("Please specify the path of Microsoft-Windows-Windows Defender%4Operational.evtx> ").replace("\"","").replace("'","")
                if(FUNCTION7):
                    f7Path = input("Please specify the path of Microsoft-Windows-PrintService%4Operational.evtx> ").replace("\"","").replace("'","")
                if(FUNCTION8):
                    f8Path = input("Please specify the path of OAlerts.evtx> ").replace("\"","").replace("'","")
                if(FUNCTION9):
                    f9Path = input("Please specify the path of Windows PowerShell.evtx> ").replace("\"","").replace("'","")

            tempFlag = False
            while(tempFlag == False):
                exportToCsv = input("\nExport the output to csv? (Y/N)> ")
                if(exportToCsv.lower() == "y" or exportToCsv.lower() == "n"):
                    tempFlag = True
            if(exportToCsv == "y"):
                outputCsv = input("Please specify the path of the output> ").replace("\"","").replace("'","")
                if(folderOrFilesChoice == "d"):
                    if(FUNCTION1):
                        storage(folderPath+'/Microsoft-Windows-Partition%4Diagnostic.evtx', folderPath+'/Microsoft-Windows-Storage-Storport%4Health.evtx', folderPath+'/Microsoft-Windows-Storsvc%4Diagnostic.evtx', "y", outputCsv)
                    if(FUNCTION2):
                        boot(folderPath+'/System.evtx', "y", outputCsv)
                    if(FUNCTION3):
                        wlan(folderPath+'/Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx', "y", outputCsv)
                    if(FUNCTION4):
                        systemTimeChange(folderPath+'/System.evtx', "y", outputCsv)
                    if(FUNCTION5):
                        windowsDefender(folderPath+'/Microsoft-Windows-Windows Defender%4Operational.evtx', "y", outputCsv)
                    if(FUNCTION6):
                        userLogonoff(folderPath+'/System.evtx', "y", outputCsv)
                    if(FUNCTION7):
                        printer(folderPath+'/Microsoft-Windows-PrintService%4Operational.evtx', "y", outputCsv)
                    if(FUNCTION8):
                        microsoftOffice(folderPath+'/OAlerts.evtx', "y", outputCsv)
                    if(FUNCTION9):
                        powershell(folderPath+'/Windows PowerShell.evtx', "y", outputCsv)
                elif(folderOrFilesChoice == "f"):
                    if(FUNCTION1):
                        storage(f1aPath, f1bPath, f1cPath, "y", outputCsv)
                    if(FUNCTION2):
                        boot(f246Path, "y", outputCsv)
                    if(FUNCTION3):
                        wlan(f3Path, "y", outputCsv)
                    if(FUNCTION4):
                        systemTimeChange(f246Path, "y", outputCsv)
                    if(FUNCTION5):
                        windowsDefender(f5Path, "y", outputCsv)
                    if(FUNCTION6):
                        userLogonoff(f246Path, "y", outputCsv)
                    if(FUNCTION7):
                        printer(f7Path, "y", outputCsv)
                    if(FUNCTION8):
                        microsoftOffice(f8Path, "y", outputCsv)
                    if(FUNCTION9):
                        powershell(f9Path, "y", outputCsv)
            elif(exportToCsv == "n"):
                if(folderOrFilesChoice == "d"):
                    if(FUNCTION1):
                        storage(folderPath+'/Microsoft-Windows-Partition%4Diagnostic.evtx', folderPath+'/Microsoft-Windows-Storage-Storport%4Health.evtx', folderPath+'/Microsoft-Windows-Storsvc%4Diagnostic.evtx', "n", "")
                    if(FUNCTION2):
                        boot(folderPath+'/System.evtx', "n", "")
                    if(FUNCTION3):
                        wlan(folderPath+'/Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx', "n", "")
                    if(FUNCTION4):
                        systemTimeChange(folderPath+'/System.evtx', "n", "")
                    if(FUNCTION5):
                        windowsDefender(folderPath+'/Microsoft-Windows-Windows Defender%4Operational.evtx', "n", "")
                    if(FUNCTION6):
                        userLogonoff(folderPath+'/System.evtx', "n", "")
                    if(FUNCTION7):
                        printer(folderPath+'/Microsoft-Windows-PrintService%4Operational.evtx', "n", "")
                    if(FUNCTION8):
                        microsoftOffice(folderPath+'/OAlerts.evtx', "n", "")
                    if(FUNCTION9):
                        powershell(folderPath+'/Windows PowerShell.evtx', "n", "")
                elif(folderOrFilesChoice == "f"):
                    if(FUNCTION1):
                        storage(f1aPath, f1bPath, f1cPath, "n", "")
                    if(FUNCTION2):
                        boot(f246Path, "n", "")
                    if(FUNCTION3):
                        wlan(f3Path, "n", "")
                    if(FUNCTION4):
                        systemTimeChange(f246Path, "n", "")
                    if(FUNCTION5):
                        windowsDefender(f5Path, "n", "")
                    if(FUNCTION6):
                        userLogonoff(f246Path, "n", "")
                    if(FUNCTION7):
                        printer(f7Path, "n", "")
                    if(FUNCTION8):
                        microsoftOffice(f8Path, "n", "")
                    if(FUNCTION9):
                        powershell(f9Path, "n", "")
        elif(firstChoice == "2"):
            help()

        tempFlag = False
        while(tempFlag == False):
            continueUsingToolFlag = input("\nContinue using this tool? (Y/N)> ")
            if(continueUsingToolFlag.lower() == "y" or continueUsingToolFlag.lower() == "n"):
                tempFlag = True
        if(continueUsingToolFlag.lower() == "n"):
            CONTINUEUSINGTOOL = False
            print("Thanks for using Wielview")

if __name__ == "__main__":
    main()