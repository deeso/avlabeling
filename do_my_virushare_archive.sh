START=$(date +"%Y-%m-%d_%H:%M:%S")
echo "Starting: ${START}"




if [ $# -ne 6 ]; then
    echo "${0}: usage: do_my_virushare_archives.sh <VirusShare_Path>"
    echo "\tVirusShare_Path: path where the ZIP archive can be found"
    exit 1
fi

$VS_ARCHIVE_PATH=$1

sh perform_all_stuff_scan.sh $VS_ARCHIVE_PATH VirusShare_00000 \
        /research_data/virus_share_malware_labels/ /research_data/malware_scan \
            /research_data/code/git/avlabeling/ /srv/nfs/malware_scan/ \
                /home/fprotect/avlabeling fprotect fprotect


sh perform_all_stuff_scan.sh $VS_ARCHIVE_PATH VirusShare_00042 \
        /research_data/virus_share_malware_labels/ /research_data/malware_scan \
            /research_data/code/git/avlabeling/ /srv/nfs/malware_scan/ \
                /home/fprotect/avlabeling fprotect fprotect


sh perform_all_stuff_scan.sh $VS_ARCHIVE_PATH VirusShare_00045 \
        /research_data/virus_share_malware_labels/ /research_data/malware_scan \
            /research_data/code/git/avlabeling/ /srv/nfs/malware_scan/ \
                /home/fprotect/avlabeling fprotect fprotect

sh perform_all_stuff_scan.sh $VS_ARCHIVE_PATH VirusShare_00051 \
        /research_data/virus_share_malware_labels/ /research_data/malware_scan \
            /research_data/code/git/avlabeling/ /srv/nfs/malware_scan/ \
                /home/fprotect/avlabeling fprotect fprotect

sh perform_all_stuff_scan.sh $VS_ARCHIVE_PATH VirusShare_00054 \
        /research_data/virus_share_malware_labels/ /research_data/malware_scan \
            /research_data/code/git/avlabeling/ /srv/nfs/malware_scan/ \
                /home/fprotect/avlabeling fprotect fprotect

sh perform_all_stuff_scan.sh $VS_ARCHIVE_PATH VirusShare_00057 \
        /research_data/virus_share_malware_labels/ /research_data/malware_scan \
            /research_data/code/git/avlabeling/ /srv/nfs/malware_scan/ \
                /home/fprotect/avlabeling fprotect fprotect

sh perform_all_stuff_scan.sh $VS_ARCHIVE_PATH VirusShare_00058 \
        /research_data/virus_share_malware_labels/ /research_data/malware_scan \
            /research_data/code/git/avlabeling/ /srv/nfs/malware_scan/ \
                /home/fprotect/avlabeling fprotect fprotect

sh perform_all_stuff_scan.sh $VS_ARCHIVE_PATH VirusShare_00059 \
        /research_data/virus_share_malware_labels/ /research_data/malware_scan \
            /research_data/code/git/avlabeling/ /srv/nfs/malware_scan/ \
                /home/fprotect/avlabeling fprotect fprotect


END=$(date +"%Y-%m-%d_%H:%M:%S")
echo "Started: ${START}"
echo "Completed: ${END}"
