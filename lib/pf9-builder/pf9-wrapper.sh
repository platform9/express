#!/bin/bash

main="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
conf=${main}/conf
input=${main}/input
mkdir -p $input

if [ ! -f "${main}/../../pf9-express.conf" ]
then
	echo "Plese run \"pf9-express -s\" to setup your MGMT plane"
	exit
fi

if grep --quiet "<CHANGEME>" "${conf}/lab.rc"
then
	echo "Plese update your credentials in the ${conf}/lab.rc config file"
	exit
fi

#source to make openstack work
source ${conf}/lab.rc

if [[ ! $(env | grep "^OS") ]] 
then
	echo "Missing Openstack Authorization File, cannot proceed."
	exit
fi

echo
echo "Starting Wrapper script..."
echo

#return 2 networks
echo "Networks identified and selected"
net=$(nova network-list 2> /dev/null | awk -F"|" '{print $3 ":" $2}'| awk '{$1=$1};1' | egrep "^1-|^2-" |  sort | awk -F":" '{print $2}' | awk '{$1=$1};1' | awk '{key=$0; getline; print key "," $0;}')
echo "Network is $net"
echo

#get images
allimages=$(openstack image list | grep [0-9])
imcount=$(echo "$allimages" | wc -l)
if [[ $imcount -gt 1 ]] 
then
	PS3='Multiple images found. Please enter your choice: '
	images=$(echo "$allimages" | awk -F"|" '{print $3}' | awk '{$1=$1};1' | tr '\n' ' ')
	options=($images)
	select opt in "${options[@]}"
	do
		echo "You have chosen the $opt image. Moving forward with this selection"
		myimage=$opt
		break
	done
else
	single=$(echo "$allimages" | awk -F"|" '{print $3 ":" $2}' | awk '{$1=$1};1')
	myimage=$single
	echo "You have chosen the $single image. Moving forward with this selection"
fi

if [[ $myimage == *"centos"* ]]
then
	user=centos
	int="ens192"
else
	user=ubuntu
	int="ens224"
fi

image="${myimage}:${user}"
echo "Default OS user will be $user used"
echo

#get security keys
allkeys=$(openstack keypair list | grep ":")
keycount=$(echo "$allkeys" | wc -l)
if [[ $keycount -gt 1 ]] 
then
	PS3='Multiple keys found. Please enter your choice: '
	keys=$(echo "$allkeys" | awk -F"|" '{print $2}' | awk '{$1=$1};1' | tr '\n' ' ')
	options=($keys)
	select keyopt in "${options[@]}"
	do
		echo "You have chosen the $keyopt key. Moving forward with this selection"
		mykey=$keyopt
		break
	done
else
	mykey=$(echo "$allkeys" | awk -F"|" '{print $2}' | awk '{$1=$1};1')
fi
echo "Key is $mykey that you have chosen"
echo

#get security groups
allsecs=$(nova secgroup-list 2> /dev/null | grep [0-9])
secscount=$(echo "$allsecs" | wc -l)
if [[ $secscount -gt 1 ]] 
then
	PS3='Multiple security groups found. Please enter your choice: '
	secs=$(echo "$allsecs" | awk -F"|" '{print $3}' | awk '{$1=$1};1' | tr '\n' ' ')
	options=($secs)
	select secsopt in "${options[@]}"
	do
		echo "You have chosen the $keyopt security group. Moving forward with this selection"
		mysec=$secopt
		break
	done
else
	mysec=$(echo "$allsecs" | awk -F"|" '{print $3}' | awk '{$1=$1};1')
fi
echo "Security Group is $mysec that you have chosen"
echo

> ${input}/hosts.csv

#get flavors
echo "Downloading image flavor selections now..."
allflavors=$(openstack flavor list | grep [0-9] |  awk -F"|" '{print $3}' | awk '{$1=$1};1')
echo

echo "Is this for PMO or PMK?"
read solution
pm=$(echo "$solution" | tr '[:upper:]' '[:lower:]')
if [[ pmo == "$pm" ]]
then

        echo "$pm chosen"
	echo "How many hypervisors to create?"
	read varname

	if ! [[ "$varname" =~ ^[0-9]+$ ]]
    	then
        	echo "Sorry integers only"
		exit
	fi

	echo "Please provide a hostname to your hypervisor(s)"
	read hostname
	echo

	PS3='Please select your flavor for your hypervisor: '
	flavs=$(echo "$allflavors" | tr '\n' ' ')
	options=($flavs)
	select flavopt in "${options[@]}"
	do
		echo "You have chosen the $flavopt security group. Moving forward with this selection"
		myflavor=$flavopt
		break
	done
	echo "Hypervisor flavor chosen is $myflavor"
	echo

	for number in $(seq 1 $varname) 
	do
		echo "$hostname${number}|$image|$myflavor|$net|bond_members='[\"${int}\"]'|$mykey|$mysec|" >> ${input}/hosts.csv
	done


elif [[ pmk == "$pm" ]]
then

	echo "## kubernetes" > ${input}/hosts.csv

	echo "How many masters?"
	read varname

	if ! [[ "$varname" =~ ^[0-9]+$ ]]
    	then
        	echo "Sorry integers only"
		exit
	fi	

	echo "Please provide a hostname to your master(s)"
	read hostname
	echo

	#get flavors
	PS3='Please select your flavor for your master: '
	flavs=$(echo "$allflavors" | tr '\n' ' ')
	options=($flavs)
	select flavopt in "${options[@]}"
	do
		echo "You have chosen the $flavopt flavor. Moving forward with this selection"
		myflavor=$flavopt
		break
	done
	echo "Master flavor chosen is $myflavor"
	echo

	if [[ "$varname" -gt 0 ]]
	then

		for number in $(seq 1 $varname) 
		do
			echo "$hostname${number}|$image|$myflavor|$net||$mykey|$mysec|master|" >> ${input}/hosts.csv
		done

	fi

	echo "How many workers?"
	read varname

	if ! [[ "$varname" =~ ^[0-9]+$ ]]
    	then
        	echo "Sorry integers only"
		exit
	fi	

	echo "Please provide a hostname to your worker(s)"
	read hostname
	echo

	#get flavors
	PS3='Please select your flavor for worker: '
	flavs=$(echo "$allflavors" | tr '\n' ' ')
	options=($flavs)
	select flavopt in "${options[@]}"
	do
		echo "You have chosen the $flavopt flavor. Moving forward with this selection"
		myflavor=$flavopt
		break
	done
	echo "Worker flavor chosen is $myflavor"
	echo

	if [[ "$varname" -gt 0 ]]
	then

		for number in $(seq 1 $varname) 
		do
			echo "$hostname${number}|$image|$myflavor|$net||$mykey|$mysec|worker|" >> ${input}/hosts.csv
		done

	fi

fi

echo "Completed generating template file at hosts.csv. Contents are below:"
echo
cat ${input}/hosts.csv
echo

#execute builder now
${main}/pf9-builder --nova ${input}/hosts.csv ${conf}/lab.rc
