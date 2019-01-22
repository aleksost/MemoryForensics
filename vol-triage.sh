#!/bin/bash
# Example usage: ./vol-triage.sh -p Win7SP0x64 -d `pwd`/output -f `pwd`/memory.bin -y `pwd`/yara_rules_dir
# Example with timing and logging: time ./vol-triage.sh -p Win7SP0x64 -d `pwd`/output -f `pwd`/memory.bin -y yara_rules_dir | tee logfile.txt

vol_path='vol.py'

while getopts "hp:d:f:ry:" opt; do
	case $opt in
		h)
			echo "Volatility triage script - Runs Volatility with the most frequently used plugins and some other tools. 
Recommended to run on a SIFT Workstation. 

Usage: # ./vol_triage.sh -p Win7SP1x86 -d output_dir -f memdump.raw -y yara_rules_dir -r
	-h 			Displays this help message.
	-p <profile>		Set the desired Volatility profile, else kdbgscan is used to find it. (Optional)
	-d <output_directory> 	Set the output folder.
	-f <memory_dump>	Specify the memory dump to be processed.
	-r 			This option enables the timeliner-plugin to parse registry events (Optional, very time consuming)
	-y <yara-rules-path>	Set the yara-rules folder to scan the dumped processes, DLLs, injected code and drivers. (Optional)"
			exit 1
			;;
		p)
			echo "PROFILE set to: $OPTARG"
			profile=$OPTARG #Sets the profile
			;;
		d)
			echo "output directory set to: $OPTARG"
			output_dir=$OPTARG
			;;
		f)
			echo "Memdump set to: $OPTARG"
			memdump=$OPTARG
			;;
		r)
			echo "Running timeliner with registry events."
			reg="1"
			echo $reg
			;; 
		y)
			echo "Yara folder set to: $OPTARG" 
			yararules=$OPTARG
			;;
		\?)
			echo "Invalid option: -$OPTARG" >&2
			echo "Usage example: ./vol_triage.sh -p Win7SP1x86 -d output_dir -f memdump.raw -y yara_rules_dir -r"
			exit 1
			;;

		:)
			echo "Option -$OPTARG reqires an argument." >&2
			exit 1
			;;
		esac
	done

#Checks if directories exists, then creates them if they do not
function createDir {
	echo -e "Creating folder $output_dir/$1\n"
	if [ ! -d $output_dir/$1 ]; then
		mkdir -p $output_dir/$1;
	fi
}

#Creating volatilityrc file
volrc=$output_dir/volatilityrc
vol_command="$vol_path --conf-file=$volrc"

#Put relevant data in the volatilityrc file to make analysis faster
function volatilityrc {
	echo -e "Creating $volrc\n"
	touch $volrc
	echo "[DEFAULT]" > $volrc
	echo "LOCATION=file://$memdump" >> $volrc
	echo "PROFILE=$profile" >> $volrc
	
	#Code to make kdbg for Windows 8
	if [[ $profile == "Win8"*"x64"* ]] || [[ $profile == "Win10"*"x64"* ]] || [[ $profile == "Win2016"*"x64"* ]] || [[ $profile == "Win2012"*"x64"* ]]; then
		kdbg=`$vol_command kdbgscan 2>/dev/null | tee $output_dir/kdbgscan.txt | grep "KdCopyDataBlock (V)" | awk -F: '{print $2}' | tr -d ' ' | uniq`	
	else
		kdbg=`$vol_command kdbgscan 2>/dev/null | tee $output_dir/kdbgscan.txt | grep "Offset (V)" | awk -F: '{print $2}' | tr -d ' ' | uniq`
	fi	
	dtb=`$vol_command psscan 2>/dev/null | tee $output_dir/psscan.txt | awk '$2 ~ /System/' | awk '$3 ~ /4/' | awk '{print $5}' | uniq`
	
	echo "KDBG=$kdbg" >> $volrc
	echo "DTB=$dtb" >> $volrc
	echo "Volatilityrc-file finished"
}


#Handles the basic plugin array, runs volatility and stores output in text files with plugin-names in appropriate folders
function plugins {
	local -n plugins 
	plugins=$2
	echo -e "----------- Running $1 plugins -----------\n"
	for plugin in ${plugins[@]}; do
		if [ ! -f $3/$plugin.txt ]; then
        		echo -e "Running $plugin\n"
			$vol_command $plugin 2>/dev/null > $3/"$plugin.txt"
        		echo -e "finished $plugin\n" 
		else 
			echo -e "$plugin.txt already exists, skipping plugin...\n"
		fi & done
	
	wait
}

#Parses the timeline plugin array, runs volatility and converts to a mactime timeline
function timelinePlugins {
        local -n plugins
        plugins=$2
	touch $3/temp.body
        echo -e "----------- Running $1 plugins -----------\n"
        for plugin in ${plugins[@]}; do
                if [ ! -f $3/$plugin.txt ]; then
			if [[ $plugin = timeliner && $reg = 1 ]]; then
				echo -e "Running $plugin\n"
				$vol_command $plugin 2>/dev/null --output=body --type=EvtLog,IEHistory,ImageDate,LoadTime,Process,Shimcache,Socket,Symlink,Thread,TimeDateStamp,Timer,Userassist,_CMHIVE,_CM_KEY_BODY,_HBASE_BLOCK,Registry >> $3/temp.body
				echo -e "finished $plugin\n"
			else
				echo -e "Running $plugin\n"
				$vol_command $plugin 2>/dev/null --output=body >> $3/temp.body
				echo -e "finished $plugin\n"
			fi
		else
			echo -e "$plugin.txt already exists, skipping plugin...\n" 
		fi & done
	wait
	mactime -b $3/temp.body -d > $3/timeliner.txt
	rm temp.body
}


#Parses the triage plugin array, runs volatility and dumps files to a directory that is later scanned by ClamAV
function triagePlugins {
        local -n plugins
        plugins=$2
        echo -e "----------- Running $1 plugins -----------\n"
        for plugin in ${plugins[@]}; do
		echo -e "Running $plugin\n"
               	$vol_command $plugin 2>/dev/null -D $3
               	echo -e "finished $plugin\n" & done
	wait
	}

#Arrays of all plugins sorted into categories
declare -a basic_plugins=(pslist pstree malfind autoruns netscan psxview usbstor amcache svcscan sockets connscan connections clipboard cmdline mimikatz imageinfo shimcachemem hollowfind systeminfo shutdowntime cmdscan consoles apihooks prefetchparser dlllist ldrmodules schtasks filescan getsids mutantscan usnparser)
declare -a kernel_plugins=(modules ssdt drivermodule timers driverirp)
declare -a timeline_plugins=(timeliner mftparser shellbags)
declare -a triage_plugins=(procdump malfind moddump dlldump)

# ----- MAIN CODE ------

#Array of all subfolders and for-loop for creating them using the createDir function 
declare -a folders=(triage timeline kernel bulk_net) 
for folder in ${folders[@]}; do         
	createDir $folder 
done

# Error handling 
if ! [ -w $output_dir ] ;then
	echo "ERROR: Directory "$output_dir" is not writable"
	exit 1
elif ! test -r $memdump;then
	echo "ERROR: Image file "$memdump" is not readable" 	
	exit 2
elif test -z "$profile";then
	echo "No profile supplied. Running kdbgscan..."
	$vol_path -f $memdump kdbgscan > $output_dir/kdbgscan.txt
	profile=$( grep "Profile suggestion" $output_dir/kdbgscan.txt| head -1 | awk -F: '{print $2}' | tr -d ' ' )
	echo "Profile set to: "$profile	
fi

#Creating volatilityrc if it does not already exist
if [ ! -s $output_dir/volatilityrc ]; then
	volatilityrc;
fi

plugins basic basic_plugins $output_dir
plugins kernel kernel_plugins $output_dir/kernel
bulk_extractor -E net -o $output_dir/bulk_net $memdump
triagePlugins triage triage_plugins $output_dir/triage


#Checking if clamscan output file exists, if not clamscan is run. Else it skips clamscan.
if [ ! -s $output_dir/clamscan-infected.txt ]; then
        echo -e "----------- Running ClamAV -----------\n"
	clamscan -i -r $output_dir/triage > $output_dir/clamscan-infected.txt
else
	echo -e "Skipping Clamscan... Triage-folder has most likely already been scanned"
fi

#Checking if yarascan output file exists, if not run yarascan on triage folder. Else it skips yara.
if [ ! -s $output_dir/yara-rules-hits.txt ]; then
	echo -e "----------- Scanning triage-folder with yara rules -----------\n"
	find $yararules -iname '*.yar*' -exec yara -r -s {} $output_dir/triage \; > $output_dir/yara-triage-results.txt
else
	echo -e "Skipping yara on triage folder... Triage-folder has most likely already been scanned"
fi

#Running strings on the memory dump followed by volatility strings to translate physical to virtual offsets
echo -e "----------- Running strings -----------\n"
strings -td -a $memdump > $output_dir/strings.txt
strings -td -el -a $memdump >> $output_dir/strings.txt
$vol_command strings -s $output_dir/strings.txt > $output_dir/vol-strings.txt

timelinePlugins timeline timeline_plugins $output_dir/timeline

#Cleans up files with no output
find $output_dir -size  0 -print0 | xargs -0 rm
