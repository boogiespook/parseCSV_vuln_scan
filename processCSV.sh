#!/bin/bash 
##########################################################################################
##
##  processPrisma
##  Author: Chris Jenkins
##  This script takes the raw (csv) output and performs the following:
##  - Deduplicate CVEs
##  - Filters by cluster name
##  - Filters where CVE id starts with "CVE-"
##  - Get critical or high severity as scored by Prisma Cloud
##  - Checks CVE in Red Hat database and gets Severity
##  - Creates a new csv file with the additional data
##
## This script is NOT officially supported by Red Hat. 
##
## The input CSV file should have the following standard column headers:
## Cluster,Namespace,Deployment,Image,Component,CVE,Fixable,Component Upgrade,Severity,Discovered At,Reference
##
##########################################################################################

lines_in_file () {
   lines=$(wc -l $1 | awk '{print $1}')
   echo " - Lines after $2 filter: $lines"
}

apply_filter () {
   in=$1
   filter=$2
   column=$3
   ext=$4
   awk -v filter=$filter -v col=$column -F"," '$col ~ filter {print $0}' $in > ${in}_${ext}
   lines_in_file ${in}_${ext} $filter
}

if=$1
cluster=$2
basefile=${if%.*}
tempFiles=""
echo
echo "Processing infile $if for cluster $cluster"
headers=$(head -1 $if)
head -1 $if > ${basefile}_headers
echo " - Lines in total: $(wc -l ${if}| awk '{print $1}')"

## Get all namespaces with ^open|^rhacs|^stack
awk -F"," '$2 ~ /^open|^rhacs|^stack/ {print}' ${if}> ${basefile}_ocp_namespaces

## De-duplicate CVEs
cveCol=$(awk -F"," '{ for (i=1; i<=NF; ++i) { if ($i ~ /CVE/) print i } }' ${basefile}_headers)
awk -F"," -vcol=$cveCol '!_[$col]++' ${basefile}_ocp_namespaces > ${basefile}_dedupe
lines_in_file ${basefile}_dedupe "de-duplicate"

cp ${basefile}_dedupe ${basefile}_dedupe_cluster

apply_filter ${basefile}_dedupe_cluster "^CVE-" "$cveCol" "cves"

## Get critical or high severity
# Find the Severity column
severityCol=$(awk -F"," '{ for (i=1; i<=NF; ++i) { if ($i ~ /^Severity/) print i } }' ${basefile}_headers)
apply_filter ${basefile}_dedupe_cluster_cves "CRITICAL|IMPORTANT" "$severityCol" "crit_high"

## Add RH Severity to the headers
newHeaders="Red Hat Severity,CVE Link,Affected,$headers"

## Run through all the CVE and look for entries in the Red Hat DB
# Create empty files so we don't append
> ${basefile}_dedupe_cluster_cves_crit_high_rh_severity
> ${basefile}_output.csv
cvesFound=0
totalLines=$(wc -l ${basefile}_dedupe_cluster_cves_crit_high | awk '{print $1}')
allCVEs=$(wc -l ${basefile}_dedupe_cluster_cves_crit_high | awk '{print $1}')
affectedTotal=0
echo "Checking $totalLines CVEs in the Red Hat CVE Database"
echo $newHeaders > ${basefile}_output.csv
while read line
do 
   cve=$(echo $line | awk -v col=$cveCol -F"," '{print $col}')
   affected=""
   newSeverity=""
   severity=$(curl -s https://access.redhat.com/hydra/rest/securitydata/cve/${cve}.json | jq '.threat_severity' 2> /dev/null | tr -d '"')
   if [ -z "$severity" ]
    then
      link="Not Found"
      severity="Not Found"
      printf "${cve}\t\t \33[01;31m Not Found \033[0m\n"
    else
      ((cvesFound=cvesFound+1))
      lcCve=$(echo $cve | tr '[A-Z]' '[a-z]')
      link="https://access.redhat.com/security/cve/$lcCve"
      printf "${cve}\t\t \33[01;32m Found \033[0m \t $severity "
      ## Get Affected state based on the repository name
      repoCol=$(awk -F"," '{ for (i=1; i<=NF; ++i) { if ($i ~ /Image/) print i } }' ${basefile}_headers)
      reponame=$(echo $line | awk -v col=$repoCol -F"," '{print $col}' | awk -F"/" '{print $2"/"$3}' | awk -F"@" '{print $1}')      
      affected=$(curl -s https://access.redhat.com/hydra/rest/securitydata/cve/${cve}.json | jq '.package_state' | grep -B1 $reponame | awk -F":" '/fix_state/ {print $2}' | tr -d '",')
      if [ -n "$affected" ]
      then
      printf "\t $affected"
         ## Check if there is an updated severity levelfor the specific repo
         newSeverity=$(curl -s https://access.redhat.com/hydra/rest/securitydata/cve/${cve}.json | jq '.package_state' | grep -A3 $reponame | awk -F":" '/impact/ {print $2}' | tr -d '", ')
         if [[ $newSeverity != "" ]]
         then
            severity=${newSeverity^}
            printf "\t \033[1;33m(Severity changed to $severity)\033[0m"
         fi
      fi
      printf "\n"
   fi
   echo "${severity^},$link,$affected,$line" >> ${basefile}_dedupe_cluster_cves_crit_high_rh_severity
   ((totalLines=totalLines-1))
done < ${basefile}_dedupe_cluster_cves_crit_high 
sort ${basefile}_dedupe_cluster_cves_crit_high_rh_severity >> ${basefile}_output.csv
## Tidy up all the temporary files
rm ${basefile}_dedupe* ${basefile}_headers
echo
echo " - $cvesFound out of $allCVEs CVEs found in the Red Hat database"
echo " Red Hat Severity Levels:"
awk -F"," '{print $1}' ${basefile}_output.csv | grep -v "Red Hat Severity" | sort | uniq -c | sort -nr
echo "Output file: ${basefile}_output.csv"
echo


