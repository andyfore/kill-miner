#!/bin/bash

#
# Created 2014-05-20
# Script name: kill-miner-nomail.sh
# Original Author: Andrew Fore, afore@web.com
# Purpose: To look for a miner process that is running in a compromised account.
#          The script finds the process and verifies that it is indeed suspect
#          kills the process and removes the files, as well as sending an email
#          to atlitops@web.com informing them of the action so that the account
#          can be suspended.
#
# Changelog
#
# Version 1.0
# - original version
# Version 1.0.1
# - adapted to check for multiple mining process under a single user
# Version 1.1
# - re-wrote script to handle multiple mining binary names instead of a single binary name
# - also takes into account the chance that a single user id could be running
#   multiple instances of different binary names
# Version 1.2
# - commented out all debug lines
# - added echo after e-mail to send UID back as result of the loop
# Version 1.3
# - added a new variable to hold the search pattern of binary names
# - updated the egrep calls to use the new search pattern variable
# Version 1.3.1
# - removed section that sends email message
# Version 1.4
# - added new variable to hold the bad urls used by the new attack vector
# - added new loop structure to handle new attack vector

# Variable definitions
#
# user_id - string to hold the UID(s) of the suspect process(es)
# arr_user_id - string array to handle occurrence of multiple UIDs
# user_id_single - string variable to hold the current UID being processed
# miner_pid - string to hold the PID(s) of the suspect process(es)
# arr_miner_pid - string array to handle the occurrence of multiple PIDs
# miner_pid_single - string variable to hold the current PID being processed
# pid_binary_path - string to hold the absolute path of the executable tied to miner_pid_single
# pid_directory_path - string to hold the directory path containing the executable tied to miner_pid_single
# binary_names - string to hold the search pattern to use
# bad_sites - string to hold the domains known to be bad

# binary names to hunt for
# add additional binary names to this string as they are found
binary_names="(kernelupdates)|(kernelcfg)|(kernelorg)|(kernelupgrade)"

# look for all UID running miner processes
user_id=`ps -ef | egrep $binary_names | grep -v grep | awk '{print $1}'`

# put UIDs in an array to account for multiple broken accounts
arr_user_id=($user_id)

# check to see if the array of user id's is empty
if [ ${#arr_user_id[@]} = 0 ]; then
    echo "no miner process found"
else
    echo "Notice: Suspect process found, investigating..."
    # process each UID found
    for user_id_single in "${arr_user_id[@]}"
    do
        # get the PID of the process in this iteration of the loop
        miner_pid=`ps -ef | grep ${user_id_single} | egrep $binary_names | awk '{print $2}'`
        arr_miner_pid=($miner_pid)
        if [ ! ${#arr_miner_pid[@]} = 0 ]; then
            for miner_pid_single in "${arr_miner_pid[@]}"
            do
                # look up and populate the path to the process binary
                pid_binary_path=`ls -l /proc/${miner_pid_single}/exe | awk '{print $11}'`
                pid_directory_path=`ls -l /proc/${miner_pid_single}/exe | awk '{print $11}' | sed "s/\/[^\/]*$//"`

                # try to kill the process
                if kill -9 $miner_pid_single; then
                    echo "Notice: Mining process ${miner_pid_single} killed."
                else
                    echo "Error: Attempt to kill process ${miner_pid_single} failed."
                fi

                # try to remove the binary of the PID
                if rm -rf ${pid_binary_path}; then
                    echo "Notice: Mining binary ${pid_binary_path} removed."
                else
                    echo "Error: Attempt to remove mining binary ${pid_binary_path} failed."
                fi

                # look for existence of mining tarball
                # if found attempt removal
                if [ -f ${pid_directory_path}/32.tar.gz ]; then
                    echo "Notice: Tarball found"
                    if rm -rf ${pid_directory_path}/32.tar.gz; then
                        echo "Notice: Tarball ${pid_directory_path}/32.tar.gz removed."
                    else
                        echo "Error: Attempt to remove tarball ${pid_directory_path}/32.tar.gz failed."
                    fi
                else
                    echo "Notice: Tarball not found."
                fi
            done
        fi

        echo ${user_id_single}
    done
fi

# sites determined as bad
bad_sites="(updates.dyndn-web)||(updates.dyndn-web.com)"

# look for all UID running wget to the established suspect site(s) processes
user_id=`ps -ef | grep -i wget | egrep -i $bad_sites  | grep -v grep | awk '{print $1}' | sort -u`

# put UIDs in an array to account for multiple broken accounts
arr_user_id=($user_id)

# check to see if the array of user id's is empty
if [ ${#arr_user_id[@]} = 0 ]; then
  echo "no miner process found"
  exit 0
else
  echo "Notice: Suspect process found, investigating..."

  # kill each of the wget processes
  ps -ef | grep wget | grep updates.dyndn-web | grep -v grep | awk '{print $2}' | xargs kill -9

  # sanitize the user crontab
  echo "Sanitizing user crontabs"
  for user_id_single in "${arr_user_id[@]}"
  do
    sed -i '/updates.dyndn-web/d' /var/spool/cron/${user_id_single}

    # return the user id for account suspension
    echo ${user_id_single}
  done
fi
