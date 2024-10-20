# Gerapy_RCE_0.9.7
Exploit credited to Jeremiasz Pluta, added some error handling.

# Readme
Copied from LongWayHomie's Github

Gerapy prior to version 0.9.8 is vulnerable to remote code execution. This issue is patched in version 0.9.8. CVE-2021-43857 is a vulnerability marked as Critical priority (CVSS 9.8) leading to remote code execution.
This vulnerability works on all versions prior to 0.9.8.
Tested only on 0.9.6. Needs correct credentials.
Exploit works by logging in to application, then getting the list of created projects (it will fail if there's none), then use the project setting to run the vulnerable spider mechanism by sending reverse shell payload.
