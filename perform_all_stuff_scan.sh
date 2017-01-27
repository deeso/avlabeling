#!/bin/bash
# My command:
# sh perform_all_stuff_scan.sh /srv/result_data/virus_share/ VirusShare_00000 \
#     /research_data/virus_share_malware_labels/ /research_data/malware_scan \
#     /research_data/code/git/avlabeling/ /srv/nfs/malware_scan/ \
#     /home/fprotect/avlabeling fprotect fprotect

FP_USERNAME=fprotect
FP_PASSWORD=fprotect
FP_HOST_LIST="fprotect-workx32-00 fprotect-workx32-01 fprotect-workx32-02 fprotect-workx32-03"
FP_HOST_LIST="${FP_HOST_LIST} fprotect-workx32-04 fprotect-workx32-05 fprotect-workx32-10 fprotect-workx32-11"
FP_HOST_LIST="${FP_HOST_LIST} fprotect-workx32-12 fprotect-workx32-13 fprotect-workx32-14"
CLAMAV_DB_POST="_clamav_hash_labels.db"
FP_DB_POST="_fpscan_hash_labels.db"
UTIL="util.py"


CLAMAV_AVLABELING="clamscan_avlabeling_local.py"
FP_AVLABELING="fpscan_avlabeling_remote.py"


if [ $# -le 6 ]; then
    echo "${0}: usage: perform_all_stuff.sh <VirusShare_Path> <VirusShare_ArchiveName> <Sqlite_Locations> <MalwareDirectory> <LocalAvlableing> <RemoteMalwareDirectory> <RemoteAvLabeling>  <username> <password>"
    echo "perform_all_stuff.sh /virus_share_archives/ VirusShare_000000 /vs_dbs/ /malware_files /git/avlabeling /home/fprotect/avlabeling /srv/nfs/malware_files username password"
    echo "Parameters: set in the script are vms running fpscan and the files executed for running the scan"
    echo "\tVirusShare_Path: path where the ZIP archive can be found"
    echo "\tVirusShare_ArchiveName: name of the archive (without the ZIP extension"
    echo "\tSqlite_Locations: place to puth the resulting sqlite archives"
    echo "\tMalwareDirectory: local directory to clean, and unzip malware too.  Note, I use this as an NFS mount "
    echo "\tLocalAvlabeling: directory containing the avlabeling scripts for local scans"
    echo "\tRemoteMalwareDirectory: remote directory containing the extracted malware.  Note, this is an NFS mount in the remote VM"
    echo "\tRemoteAvlabeling: directory containing the avlabeling scripts on the remove VM"
    echo "\tusername: username to ssh into the VM with"
    echo "\tpassword: password to ssh into the VM with"
    exit 1
fi
#Arg 1 Paths to VirusShare Archive name
VIRUS_SHARE_PATH=$1

#Arg 2 VirusShare Archive name
VIRUS_SHARE_NAME=$2

#Arg 3 Database locations for sqlite
DB_DIRECTORY=$3

#Arg 4 Malware directory
MALWARE_DIRECTORY=$4

#Arg 5 Local AV Labeling code
LOCAL_AVLABELING=$5

#Arg 6 Remote Malware location
REMOTE_MALWARE_LOCATION=$6

#Arg 7 Remote AV labeling code
REMOTE_AVLABELING=$7

if [ $# -ge 8 ]; then
    FP_USERNAME=$8
fi

if [ $# -ge 9 ]; then
    FP_PASSWORD=$9
fi

#echo $1
#echo $2
#echo $3
#echo $4
#echo $5
#echo $6
#echo $7
#echo $FP_USERNAME
#echo $FP_PASSWORD


VIRUS_SHARE_PATH_NAME=${VIRUS_SHARE_PATH}/${VIRUS_SHARE_NAME}".zip"



CLAMSCANAV_AVLABELING_DIRECTORY=${LOCAL_AVLABELING}
FP_AVLABELING_DIRECTORY=$REMOTE_AVLABELING
CLAMAV_SCAN_DB_LOCATION=${DB_DIRECTORY}/${VIRUS_SHARE_NAME}${CLAMAV_DB_POST}
FP_SCAN_DB_LOCATION=${DB_DIRECTORY}/${VIRUS_SHARE_NAME}${FP_DB_POST}

FP_MALWARE_LOCATION=$REMOTE_MALWARE_LOCATION
UTIL_AVLABELING=${LOCAL_AVLABELING}/${UTIL}

# clean-up current malware (move to new directory and delete)
# otherwise it stomps the NFS mount and makes it stale to remote hosts
RM_FILES_COMMAND="${UTIL_AVLABELING} -cmd mt_rm -args ${MALWARE_DIRECTORY}"
echo "Performing malware clean up on: ${MALWARE_DIRECTORY}"
echo "Performing malware clean up: python ${RM_FILES_COMMAND}"
cd $LOCAL_AVLABELING

python $RM_FILES_COMMAND

# unzip the malware in the directory
echo "Performing unzipping ${VIRUS_SHARE_PATH_NAME} to ${MALWARE_DIRECTORY}"
cd $MALWARE_DIRECTORY
echo "Executing: unzip -q -P infected ${VIRUS_SHARE_PATH_NAME}"
unzip -q -P infected $VIRUS_SHARE_PATH_NAME

# move to the local avlabeling code and run the scans
cd $LOCAL_AVLABELING
CLAMAV_COMMAND="${CLAMAV_AVLABELING} -num_procs 22 -scan_location ${MALWARE_DIRECTORY} -malware_location ${MALWARE_DIRECTORY}"
CLAMAV_COMMAND="${CLAMAV_COMMAND} -avlabel_location ${CLAMSCANAV_AVLABELING_DIRECTORY} -sqlite_location ${CLAMAV_SCAN_DB_LOCATION}"

FPSCAN_COMMAND="$FP_AVLABELING -user $FP_USERNAME -password $FP_PASSWORD -hosts $FP_HOST_LIST -scan_location ${MALWARE_DIRECTORY}"
FPSCAN_COMMAND="${FPSCAN_COMMAND} -malware_location ${FP_MALWARE_LOCATION} -avlabel_location ${FP_AVLABELING_DIRECTORY} -sqlite_location $FP_SCAN_DB_LOCATION" 

# run the clamav labeling script
echo "Performing clamav scan: python ${CLAMAV_COMMAND}"
python ${CLAMAV_COMMAND} &

echo "Performing FP scan: python ${FPSCAN_COMMAND}"
python ${FPSCAN_COMMAND}
