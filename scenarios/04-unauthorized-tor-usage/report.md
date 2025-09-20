Threat Hunt Report (Unauthorized TOR Usage)

Detection of Unauthorized TOR Browser Installation and Use on Workstation: th--dp--win11

Example Scenario:
Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

High-Level TOR related IoC Discovery Plan:
Check DeviceFileEvents for any tor(.exe) or firefox(.exe) file events
Check DeviceProcessEvents for any signs of installation or usage
Check DeviceNetworkEvents for any signs of outgoing connections over known TOR ports

Steps Taken
Searched the DeviceFileEvents table to for ANY file that containes string "tor".
Discovered an employee test-th-v1 downloaded a tor installer.
Perofmd an actioned where tor related file was copied to the deskrtop.
Found creation of file called "tor-shopping-list.txt" on the desktop.
...
...

Chronological Events
...
...
...

Summary


Response Taken
TOR usage was confirmed on endpoint ______________. The device was isolated and the user's direct manager was notified.
