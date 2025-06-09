![{2721AB32-2441-4E06-81C8-2C3F569E447F}](https://github.com/user-attachments/assets/e86db88c-eb2b-449a-8fa2-041c6a1cf4af)## Scenario

John Grunewald was deleting some old accounting documents when he accidentally deleted an important document he had been working on. He panicked and downloaded software to recover the document, but after installing it, his PC started behaving strangely. Feeling even more demoralised and depressed, he alerted the IT department, who immediately locked down the workstation and recovered some forensic evidence. Now it is up to you to analyze the evidence to understand what happened on John's workstation.

## Tools used

- Volatility 3
- FTK Imager
- DB Browser for SQLite

## Questions

### Task 1. What is the build version of the operating system?

The build version of the OS is located in the SOFTWARE Registry hive.

To extract this information, we can use the `windows.registry.hivelist` plugin in Volatility 3 to identify the virtual address of the SOFTWARE hive.

Then, we utilize the `windows.registry.printkey` plugin to navigate to the appropriate Registry key containing the build version.

List all registry hives to identify SOFTWARE hive's virtual offset: `volatility3 -f memory.vmem windows.registry.hivelist`

Access the CurrentVersion key to read build information: `volatility3 -f memory.vmem windows.registry.printkey --key "Microsoft\Windows NT\CurrentVersion"`

**Answer: 19041**


### Task 2. What is the computer hostname?

The computer hostname is located in the SYSTEM Registry hive, specifically under the ComputerName key path.

Access the hostname key and check the value named **ComputerName**:

`volatility3 -f memory.vmem windows.registry.printkey --key "ControlSet001\Control\ComputerName\ComputerName"`

**Answer: DESKTOP-38NVPD0**


### Task 3. What is the name of the downloaded ZIP file?

Load disk artifact into FTK Imager and navigate to `/Users/John/Downloads/` directory:

![{2721AB32-2441-4E06-81C8-2C3F569E447F}](https://github.com/user-attachments/assets/0d78a4a8-7947-4e90-93eb-1afa435cb101)

**Answer: Data_Recovery.zip**


### Task 4. What is the domain of the website (including the third-level domain) from which the file was downloaded?

Let check the history of Browser. In this case, user John use Microsoft Edge to download that zip file.

Export `History` file in `/User/John/AppData/Local/Microsoft/Edge/User Data/Default/` directory and load that file in `DB Browser for SQLite` and show the `downloads` table

![{6BB6356A-CB09-430C-9C76-182B4707045C}](https://github.com/user-attachments/assets/f4e6237c-4454-4b88-96ca-7ca733ded75b)


**Answer: praetorial-gears.000webhostapp.com**


### Task 5. The user then executed the suspicious application found in the ZIP archive. What is the process PID?

Using `pslist` or `pstree` Volatility 3 plugin to know what is the pid of executed suspicious application.

![{A053D29D-9B12-49A9-A759-7DF73DF9E0C5}](https://github.com/user-attachments/assets/3d04b9e6-9841-4286-a650-f1102afa6371)

**Answer: 484**


### Task 6. What is the full path of the suspicious process?

See Task 5.

**Answer: C:\Users\John\Downloads\Data_Recovery\Recovery_Setup.exe**


### Task 7. What is the SHA-256 hash of the suspicious executable?

In FTK Imager, export executable file and SHA-256 calculate.

**Answer: C34601c5da3501f6ee0efce18de7e6145153ecfac2ce2019ec52e1535a4b3193**


### Task 8. When was the malicious program first executed?

Windows creates a prefetch file when an application is run from a particular location for the very first time. This is used to help speed up the loading of applications. [1]

In FTK Imager, export `/Windows/Prefetch/RECOVERY_SETUP.EXE-A808CDA8` file. Then, using tool named `PEcmd` (Prefetch Explorer Command line), to parse and extract detailed metadata from the Prefetch file.

![{69D39570-C5BA-4338-B160-5597C1B02C95}](https://github.com/user-attachments/assets/284d3291-6472-457c-a7b5-a8458a92fa5a)

**Answer: 2023-05-30 02:06:29**


### Task 9. How many times in total has the malicious application been executed?

**Answer: 2**


### Task 10. The malicious application references two .TMP files, one is IS-NJBAT.TMP, which is the other?

In the result of metadata that extracted by using PEcmd, go to File references and we can see the other of .TMP file that malicious application references.

![{9D6C1916-003D-4C95-95AF-CDE2658E6777}](https://github.com/user-attachments/assets/41420d20-94cf-4af3-ba92-f33e06149519)


**Answer: IS-R7RFP.TMP**


### Task 11. How many of the URLs contacted by the malicious application were detected as malicious by VirusTotal?

In VirusTotal, go to Relations tab. There are 4 URLs contacted by malicious application were detected.

![{AFACBC90-D004-4111-BF4D-3DC9309C5E9F}](https://github.com/user-attachments/assets/3a38be6b-c7de-4732-87b5-1072632c9a80)

**Answer: 4**


### Task 12. The malicious application downloaded a binary file from one of the C2 URLs, what is the name of the file?

In Wireshark, filter HTTP protocol and victim IP address - we can find it by using Network Miner, find the host matching with computer name `DESKTOP-38NVPD0`, and C2.

Filter: `_ws.col.protocol == "HTTP" && ip.src == 192.168.116.133 && (ip.dst == 45.12.253.72 || ip.dst == 45.12.253.75)`

![{C8C4D533-A733-40B7-8730-BA14BAC64548}](https://github.com/user-attachments/assets/ea152155-7802-4ac8-a2f6-9239f5e6d507)


Updating...

**Answer: puk.php**


### Task 13. Can you find any indication of the actual name and version of the program that the malware is pretending to be?

![{E0BDC771-7455-439D-9E5C-AF7F97445CEE}](https://github.com/user-attachments/assets/7f181953-6761-4f50-a8a1-a1f36c5c86de)

Updating...

**Answer: FinalRecovery v3.0.7.0325**


## References

- [1] Windows Prefetch file: https://www.magnetforensics.com/blog/forensic-analysis-of-prefetch-files-in-windows/
- [2] AnyRun: https://app.any.run/tasks/c7e41dc7-a11e-4061-9eb0-400362c2bb9b
- [2] VirusTotal: https://www.virustotal.com/gui/file/c34601c5da3501f6ee0efce18de7e6145153ecfac2ce2019ec52e1535a4b3193/detection
