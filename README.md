# SysAudit
A script written in PowerShell for auditing Windows configurations and security settings.  
Its main purpose is for local computer security audits on standalone, siloed or air gapped systems. 
The tool will output information that can be later analyzed.
The tool can be run from a USB stick or from a network share.  
The resulting output will be stored in the OUTPUT directory.  

## Usage
1. Place the SysAudit directory and all subfolders, files on a USB stick or a network share.
	Note that you may need to go to the file properties and select "Unblock" if you get a Smartscreen warning.
2. On the computer to be audited, run the SysAudit.ps1 file. (Requires Administrator rights to run.)
   	- Run Powershell as Administrator
   	- Navigate to the directory containing the script, and type the command .\SysAudit.ps1
   	- The SysAudit script will run	
4. The results will be available in the OUTPUT folder.

Note: Defender or Smartscreen warnings may appear, or require a scan, accept those to continue - the script is non malicious using Microsoft utilities and PowerShell cmdlets.

### Results
The results will be available at the locations below:

- OUTPUT\
  - HOSTNAME\
    - HOSTNAME-DATETIME-arp.txt <- ARP export
    - HOSTNAME-DATETIME-Inventory.html <- Main SysAudit inventory report
    - HOSTNAME-DATETIME-ScheduledTasks.csv <- Export of Scheduled Tasks configuration  
    - EVENTLOGS\
      - Application.evtx  
      - Security.evtx  
      - System.evtx  
      - WindowsDefender.evtx  
    - POLICIES\ 
      - {GUID} <- Local GPO Backup
      - HOSTNAME-DATETIME-GroupPolicy.PolicyRules <- Export of Local Group Policy Configuration for use with Policy Analyzer
      - HOSTNAME-DATETIME-SecurityPolicy.inf <- Export of Local Security Policy for use with Policy Analyzer
      - HOSTNAME-DATETIME-GPResult.html <- Local GPO Policy HTML report
