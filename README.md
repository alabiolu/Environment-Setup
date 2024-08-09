# Environment Setup, LimaCharlie Configuration, and Sliver (C2) Implementation

## Objective

To establish a secure and functional testing environment by configuring a Linux system with LimaCharlie for threat detection and Sliver for adversary emulation, enabling the analysis and development of effective security counter measures.

### Skills Learned

- Linux system administration: Proficiency in setting up and configuring Linux environments for specific use cases.
- Security tool configuration: Ability to install, configure, and operate security tools like LimaCharlie and Sliver.
- Scripting and automation: Knowledge of scripting languages for automating tasks.
- Cybersecurity fundamentals: Understanding of threat actor tactics, techniques, and procedures.
- Troubleshooting: Ability to diagnose and resolve technical issues related to environment setup and tool configuration.
- Attention to detail: Ensuring accurate configuration and data handling.

### Tools Used

- LimaCharlie: Proficiency in configuring agent settings, data collection, and alert management.
- Sliver C2 framework: Understanding of command-and-control infrastructure, agent deployment, and communication protocols.


## Steps
Set up a Linux based system using VirtualBox.

I did install this with the Kali Server ISO file obtained from the official website, I created a new VM in virtualBox. Using the downloaded ISO file as the installer image


Set up a Window based system using VirtualBox

After downloading the Windows virtual machine image from Microsoft 's official source, I imported the VM into VirtualBox.

I began by starting up the VM, with disabling Microsoft Defender. Although this action is typically discouraged in production environments, it was necessary for the purpose of this home lab setup to prevent any interference with subsequent activities.

![Screenshot 2024-08-09 184055](https://github.com/user-attachments/assets/e1132bfb-f1c6-4e09-861c-e854814d5c4b)

*Ref 1: WIndows Diagram*

## Install Sysmon in Windows VM
I proceeded to install Sysmon on the Windows VM. Sysmon serves as a valuable analyst tool, providing detailed telemetry on various activities within the Windows endpoint.

To set up Sysmon on the Windows VM, I followed these steps in an administrative PowerShell session:

Downloaded Sysmon using the following command: Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Windows\Temp\Sysmon.zip        

Unzipped the Sysmon.zip file: Expand-Archive -LiteralPath C:\Windows\Temp\Sysmon.zip -DestinationPath C:\Windows\Temp\Sysmon        

I downloaded the Sysmon configuration provided by SwiftOnSecurity. Utilizing a custom rule set from SwiftOnSecurity enhances logging on a Windows endpoint, providing optimal results when combined with Sysmon.

Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Windows\Temp\Sysmon\sysmonconfig.xml        

Installed Sysmon with Swift’s configuration using the following command: C:\Windows\Temp\Sysmon\Sysmon64.exe -accepteula -i C:\Windows\Temp\Sysmon\sysmonconfig.xml        


![Screenshot 2024-08-09 184802](https://github.com/user-attachments/assets/5124887e-9415-40b5-bfcf-490b22646782)

*Ref 2: Windows Diagram* 

## Install LimaCharlie EDR on Windows Virtual Machine:

LimaCharlie serves as a robust SecOps Cloud Platform, providing an extensive suite of features to bolster your cybersecurity defense. It offers a cross-platform EDR agent, robust log management capabilities, and an intelligent threat detection engine. Its comprehensive approach to security makes it akin to having a dedicated security team safeguarding your digital assets around the clock. Additionally, LimaCharlie's provision of a free tier for up to two systems enhances its accessibility for users.

Begin by creating a free LimaCharlie account.

After logging into LimaCharlie, proceed to create an organization

![Screenshot 2024-08-09 185132](https://github.com/user-attachments/assets/12452a8a-c254-4868-9846-2bb8bed675b1)

*Ref 3: LimaCharlie Diagram*

After creating the organization, navigate to the "Add Sensor" option.

![Screenshot 2024-08-09 185333](https://github.com/user-attachments/assets/df28d85b-52c3-4ffb-b930-927d4e4fbc9b)

*Ref 4: LimaCharlie Diagram*

After creating the organization, I proceeded to "Add Sensor," selected "Windows" as the sensor type, provided a description like "Windows VM - Lab," and chose the Installation Key generated earlier.

![Screenshot 2024-08-09 185542](https://github.com/user-attachments/assets/5ee32093-8a15-4f76-8cc3-27dda7597bd7)

*Ref 5: LimaCharlieDiagram*

Specify the x86-64 (.exe) sensor during the installation process.

![Screenshot 2024-08-09 185701](https://github.com/user-attachments/assets/cb0ae253-0040-49ac-b81b-3b2810c7d845)

*Ref 6: LimaCharlie Diagram*

In the Windows VM, I opened an Administrative command line prompt and executed the following commands.

cd C:\Users\MySOC\Downloads

cd C:\Users\MySOC\Downloads

Invoke-WebRequest -Uri https://downloads.limacharlie.io/sensor/windows/64 -Outfile C:\Users\User\Downloads\lc_sensor.exe

Then, I executed the following command, which contains the installation key.

lc_senser.exe -i [instalation key copied from LimaChalie]

![Screenshot 2024-08-09 190247](https://github.com/user-attachments/assets/4b78eda9-93f9-42e6-bb96-247bfdef3d3a)

*Ref 7: Windows Diagram*

I observed that the LimaCharlie web UI showed the sensor reporting in.

![Screenshot 2024-08-09 190436](https://github.com/user-attachments/assets/ed2fd65b-41af-42a1-af32-b9d87176f83c)

*Ref 8: LimaCharlie Diagram*

Next, I configured LimaCharlie to also send the Sysmon event logs along with its own EDR telemetry.
Navigate to the left-side menu and select "Artifact Collection."

![Screenshot 2024-08-09 190625](https://github.com/user-attachments/assets/a080da68-c096-4c05-ab1c-adda307bb61a)

*Ref 9: LimaCharlie Diagram*

Create a new Rule

![Screenshot 2024-08-09 190758](https://github.com/user-attachments/assets/7623be02-bfa9-45d4-b8a3-c36af0b7b749)

*Ref 10: LimaCharlie Diagram*

Once configured, LimaCharlie will start sending Sysmon logs, offering a wealth of EDR-like telemetry.

## Configuring the Kali Attack VM
I configure our attacker C2 server. To gain root privileges, I executed the following command.

sudo su

Next, I proceeded to download Sliver, a Command & Control (C2) framework developed by BishopFox. Sliver serves as an open-source post-exploitation C2 framework, providing an alternative to other C2 frameworks like Cobalt Strike and Merlin, or complementing them when used together.

curl https://sliver.sh/install|sudo bash

I check that the server service is running using "systemctl status sliver"

I Install mingw-w64 to enhance functionality

apt install -y mingw-w64  

I created a directory where I'll perform our subsequent tasks.

mkdir -p /opt/sliver 

## Exploring LimaCharlie Web Interface:
Let's take a closer look at the LimaCharlie web interface. I navigated to the "Sensors List" and clicked on the hostname of the sensor I was interested in exploring.

## Timeline:
The timeline on Limacharlie EDR provides a chronological view of security events and activities on monitored endpoints, including alerts, endpoint events, incident response actions, and the progression of detected threats. It helps security analysts quickly identify and respond to potential threats.

I conducted an experiment by attempting to ping google.com from the Windows VM where LimaCharlie EDR is installed. Now, I'll check the LimaCharlie web interface's timeline to see if the event has been registered and is available for analysis.

As observed, the ping event was successfully logged and is visible on the timeline in the LimaCharlie web interface. Furthermore, it's noted that the event was captured through the Sysmon channel, affirming that both LimaCharlie and Sysmon are functioning as expected in the setup.

![Screenshot 2024-08-08 231123](https://github.com/user-attachments/assets/86b7c42e-a1e9-4c60-a265-d336ae446c72)

![Screenshot 2024-08-08 231159](https://github.com/user-attachments/assets/3ffbd6db-a6ac-455f-b40d-93e40183ea9a)

*Ref 11: LimaCharlie Diagram*

## Processes:
In Limacharlie EDR, the "Processes" section provides a concise overview of the processes running on monitored endpoints, including their names, paths, IDs, parent processes, command line arguments, user context, and execution timestamps.

![Screenshot 2024-08-08 231239](https://github.com/user-attachments/assets/cbf8fd67-02af-4557-9b62-51b01d37bf79)

*Ref 12: LimaCharlie Diagram*

The three dots menu for each process in Limacharlie EDR provides the following options:

These options provide various capabilities to investigate and respond to potential security threats associated with specific processes.

![Screenshot 2024-08-08 231314](https://github.com/user-attachments/assets/d4e681c1-b066-4b32-bc19-1d525e91780d)

*Ref 12: LimaCharlie Diagram*

## File System:
In Limacharlie EDR, the "File System" section provides a view of the files and directories present on the monitored endpoints.

![Screenshot 2024-08-08 231347](https://github.com/user-attachments/assets/b98476e4-989d-452b-8cc2-d5388b45f165)

*Ref 13: LimaCharlie Diagram*

In Limacharlie, a standout feature is the ability to search file hash values directly with VirusTotal. This handy tool quickly checks the potential threat of files against VirusTotal's database, making it easier to assess and handle suspicious files. Integrating VirusTotal into the file explorer streamlines the analysis process, helping security analysts make better decisions and strengthen endpoint security.

![Screenshot 2024-08-08 231433](https://github.com/user-attachments/assets/383da1a8-d88c-4635-9ab5-338fd1aeeabf)

*Ref 14: LimaCharlie Diagram*

In conclusion, setting up this virtual lab was both interesting and exciting. By installing tools like VirtualBox, Kali Server, Windows VMs, Sysmon, LimaCharlie EDR, and Sliver C2, I've laid a solid foundation for hands-on learning.

Exploring LimaCharlie's web interface has uncovered the power of monitoring and analyzing security events. Engaging with processes and file systems has provided me with valuable insights into threat detection and response.
