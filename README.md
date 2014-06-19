kill-miner
==========

To look for a miner process that is running in a compromised account. The script finds the process and verifies that it is indeed suspect kills the process and removes the files, as well as sending an email to an account informing them of the action so that the user account can be suspended if necessary.

**Script name** kill-miner.sh

*Created* 2014-05-20

*Original Author* Andrew Fore [afore@web.com](mailto:afore@web.com)

**File List**

* kill-miner.sh - this file handles removing the processes and reporting as well as sending an email to/from the addresses defined in the variables at the top of the script.
* kill-miner-nomail.sh - this file does the same processes as kill-miner.sh but as the name suggests it doesn't send an email.
