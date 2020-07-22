#!/usr/bin/env bash
# TODO:
# * Add support for networks, not just hosts.
printUsage() {
	echo "Usage:"
	echo "$0 [-d] [-h] [-p port] [-J file] [-j file] [-c file] [-O] <list>"
	echo "Default output is pretty-print JSON to STDOUT, suitable for output redirection."
	echo -e "\t-d\tIncrease debug level, up to twice."
	echo -e "\t-h\tPrint this usage information."
	echo -e "\t-p port\tSpecify the port to use for API connections. Default is 443."
	echo -e "\t-J file\tWrite pretty-print JSON output to <file>."
	echo -e "\t-j file\tWrite compact JSON output to <file>. One line per rule."
	echo -e "\t-c file\tWrite quote-delimited CSV output to <file>."
	echo -e "\t-O\tWrite pretty-print JSON output to STDOUT."
	echo -e "\tlist\tList of IPs to search for, separated by spaces."
	echo ""
	echo "Example:"
	echo "$0 -J myAppPretty.json -j myApp.json -c myApp.csv 10.64.32.16 10.20.30.40"
	}

jqRuleRepresentation="{domainUID:.domain.uid,
layerUID:.layer,
ruleUID:.uid,
enabled:.enabled,
name:.name,
comments:.comments,
source:[.source[].uid],
sourceNegate:.[\"source-negate\"],
destination:[.destination[].uid],
destinationNegate:.[\"destination-negate\"],
service:[.service[].uid],
serviceNegate:.[\"service-negate\"],
action:.action.name}"

csvRuleRepresentation="{domainUID:.domainUID,
layerUID:.layerUID,
ruleUID:.ruleUID,
enabled:.enabled,
name:.name,
comments:.comments,
source:[.source[].name],
sourceNegate:.sourceNegate,
destination:[.destination[].name],
destinationNegate:.destinationNegate,
service:[.service[].name],
serviceNegate:.serviceNegate,
action:.action}"

# For jq 1.5, replace the above with this:
# # This gives you tab-separated values within a field, comma-separated
# # fields within a row. Later, I use 'tr' to translate tabs to newlines.
# csvRuleRepresentation="[([.domainUID,
# .layerUID,
# .ruleUID]|@tsv),
# .enabled,
# .name,
# .comments,
# ([.source[]|.name]|@tsv),
# .sourceNegate,
# ([.destination[].name]|@tsv),
# .destinationNegate,
# ([.service[].name]|@tsv),
# .serviceNegate,
# .action]|@csv"

unitSeparator=$(awk 'BEGIN {print "\037"}')



debug1() {
	if [ "${ipsToRulesDebug}" -ge 1 ]; then
		printf "DEBUG1: %s\n" "$*" >&2
		fi
	}

debug2() {
	if [ "${ipsToRulesDebug}" -ge 2 ]; then
		printf "DEBUG2: %s\n" "$*" >&2
		fi
	}

getRuleUsingUID() {
	## This function expects a single argument in this form:
	## {"layerUID":"<UUID>","ruleUID":"<UUID>"}
	## 
	## It then looks up that rule and carves it down to just the relevant
	## information.
	layerUID=$(echo "$1" | jq ".layerUID")
	ruleUID=$(echo "$1" | jq ".ruleUID")
	mgmt_cli --port "${apiPort}" \
		-s sessionFile_$CMA.txt \
		--format json \
		show access-rule \
		layer "$layerUID" \
		uid "$ruleUID" \
		details-level full \
		| jq "$jqRuleRepresentation"
	}

getRuleUIDsUsingObjectUID() {
	## This function expects an object UUID as an argument. It returns the rules
	## which use that object in this form:
	## {"layerUID":"<UUID>","ruleUID":"<UUID>"}
	## 
	## You need both the rule UUID and the layer UUID to look up a rule. This
	## returns them as one line to avoid needing to deal with list member
	## interleaving or other nonsense. Each rule reference is one list item.
	mgmt_cli --port "${apiPort}" \
		-s sessionFile_$CMA.txt \
		--format json \
		where-used \
		uid $1 \
		indirect true \
		| jq -c ".[\"used-directly\"].\"access-control-rules\"[],
			.[\"used-indirectly\"].\"access-control-rules\"[]
			| {layerUID:.layer.uid,ruleUID:.rule.uid}"
	}

getHostUIDsUsingIP() {
	## This function expects an IP address in string form as an argument. It
	## returns all UIDs for host objects which contain that IP, one per line.
	mgmt_cli --port "${apiPort}" \
		-s sessionFile_$CMA.txt \
		--format json \
		show objects \
		ip-only true \
		type host \
		filter $1 \
		details-level uid \
		| jq -c ".objects[]"
	}

dereferenceObjectUID() {
	objectUIDToFind=$1
	debug1 "dereferenceObjectUID: Dereferencing ${objectUIDToFind}."
	foundObject="$(mgmt_cli --port "${apiPort}" \
		-s sessionFile_$CMA.txt \
		--format json \
		show object \
		uid "${objectUIDToFind}" \
		details-level full)"

	type="$(echo "${foundObject}" | jq -c '.object.type' | sed 's#"##g')"
	case "${type}" in
	address-range)
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object|{name:.name,comments:.comments,type:.type,ipv4AddressFirst:.\"ipv4-address-first\",ipv4AddressLast:.\"ipv4-address-last\"}")${unitSeparator}\n"
		;;
	application-site)
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object|{name:.name,comments:.comments,type:.type}")${unitSeparator}\n"
		;;
	application-site-category)
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object|{name:.name,comments:.comments,type:.type}")${unitSeparator}\n"
		;;
	application-site-group)
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object|{name:.name,comments:.comments,type:.type,members:[.members[]|.uid]}")${unitSeparator}\n"
		;;
	CpmiAnyObject)
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object|{name:.name,comments:.comments}")${unitSeparator}\n"
		;;
	CpmiClusterMember)
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object|{name:.name,comments:.comments,type:.type,ipv4Address:.\"ipv4-address\"}")${unitSeparator}\n"
		;;
	CpmiGatewayCluster)
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object|{name:.name,comments:.comments,type:.type,ipv4Address:.\"ipv4-address\"}")${unitSeparator}\n"
		;;
	CpmiGatewayPlain)
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object|{name:.name,comments:.comments,type:.type,ipv4Address:.\"ipv4-address\"}")${unitSeparator}\n"
		;;
	CpmiHostCkp)
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object|{name:.name,comments:.comments,type:.type,ipv4Address:.\"ipv4-address\"}")${unitSeparator}\n"
		;;
	dns-domain)
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object|{name:.name,comments:.comments,type:.type,isSubdomain:.\"is-sub-domain\"}")${unitSeparator}\n"
		;;
	group)
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object|{name:.name,comments:.comments,type:.type,members:[.members[]|.uid]}")${unitSeparator}\n"
		;;
	group-with-exclusion)
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object|{name:.name,comments:.comments,type:.type,include:[.include.uid],except:[.except.uid]}")${unitSeparator}\n"
		;;
	host)
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object|{name:.name,comments:.comments,type:.type,ipv4Address:.\"ipv4-address\"}")${unitSeparator}\n"
		;;
	Internet)
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object|{name:.name,comments:.comments}")${unitSeparator}\n"
		;;
	network)
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object|{name:.name,comments:.comments,type:.type,subnet4:.subnet4,subnetMask:.\"subnet-mask\"}")${unitSeparator}\n"
		;;
	RulebaseAction)
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object.name")${unitSeparator}\n"
		;;
	service-dce-rpc)
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object|{name:.name,comments:.comments,type:.type}")${unitSeparator}\n"
		;;
	service-group)
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object|{name:.name,comments:.comments,type:.type,members:[.members[]|.uid]}")${unitSeparator}\n"
		;;
	service-icmp)
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object|{name:.name,comments:.comments,type:.type}")${unitSeparator}\n"
		;;
	service-other)
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object|{name:.name,comments:.comments,type:.type,ipProtocol:.\"ip-protocol\"}")${unitSeparator}\n"
		;;
	service-tcp)
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object|{name:.name,comments:.comments,type:.type,port:.port}")${unitSeparator}\n"
		;;
	service-udp)
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object|{name:.name,comments:.comments,type:.type,port:.port}")${unitSeparator}\n"
		;;
	*)
		echo "ERROR: Unhandled type: ${type} for object ${objectUIDToFind}" >&2
		printf "s${unitSeparator}${objectUIDToFind}${unitSeparator}$(echo -n "${foundObject}" \
			| jq -c ".object|{name:.name,comments:.comments,type:.type}")${unitSeparator}\n"
		;;
	esac
	}

dereferenceAllObjectsInRules() {
	ruleSet=$(echo "${1}" | jq .)

	while [ "$(echo "${ruleSet}" | egrep '^\s+.[-0-9a-fA-F]{36}.')" != "" ]; do
		debug1 "dereferenceAllObjectsInRules: Running dereference loop."
		objectUIDsToLookup=( $(echo "${ruleSet}" | egrep '^\s+.[-0-9a-fA-F]{36}.' | sed 's#,##g') )

		for objectToFind in "${objectUIDsToLookup[@]}"; do
			dereferenceObjectUID "${objectToFind}" >> objects.sed
			done

		ruleSet=$(echo "${ruleSet}" | jq . | sed -f objects.sed | jq .)
		done

	echo "${ruleSet}"
	}

findRulesUsingIPs() {
	debug1 "Entering findRulesUsingIPs."
	objectUIDs=()
	for ipToFind in "${ipList[@]}"; do
		## Here, we iterate through the list of IPs given above. We search for
		## each one, then record all the UUIDs of host objects which have
		## exactly that IP.
		debug1 "Looking for $ipToFind."
		ipToFindUIDs=( $(getHostUIDsUsingIP "$ipToFind") )
		debug2 "Found ${!ipToFindUIDs[@]} UIDs: ${ipToFindUIDs[@]}"
		objectUIDs=( "${objectUIDs[@]}" "${ipToFindUIDs[@]}" )
		done
	objectUIDs=( $(echo "${objectUIDs[@]}" | tr " " "\n" | sort -u) )
	if [ "${ipsToRulesDebug}" -ge 2 ]; then
		debug2 "objectUIDs now contains ${#objectUIDs[@]} items:"
		for element in "${objectUIDs[@]}"; do echo "$element" >&2; done
		echo "" >&2
		fi
	ruleUIDs=()
	for object in "${objectUIDs[@]}"; do
		## Here, we go through all the object UIDs we just found and find all
		## the rules referencing those objects.
		debug1 "Finding where $object is used."
		objectRuleUIDs=( $(getRuleUIDsUsingObjectUID "$object") )
		debug2 "Found ${!objectRuleUIDs[@]} UIDs: ${objectRuleUIDs[@]}"
		ruleUIDs=( "${ruleUIDs[@]}" "${objectRuleUIDs[@]}" )
		done
	ruleUIDs=( $(echo "${ruleUIDs[@]}" | tr " " "\n" | sort -u) )
	if [ "${ipsToRulesDebug}" -ge 2 ]; then
		debug2 "ruleUIDs now contains ${#ruleUIDs[@]} items:"
		for element in "${ruleUIDs[@]}"; do echo "$element" >&2; done
		echo "" >&2
		fi

	for rule in "${ruleUIDs[@]}"; do
		## Finally, it's time to get and print the rules.
		echo "$(getRuleUsingUID $rule)"
		done
	}

masterOutput() {
	## This function expects a string containing JSON. Each output format is a
	## separate if statement, so multiple formats can be emitted with one call.
	ruleJSON=$1
	if [ "${outFilePrettyJSON}" != "" ]; then
		debug1 "Emitting pretty JSON."
		echo "${ruleJSON}" \
		| jq . \
		>> "${outFilePrettyJSON}"
		fi
	if [ "${outFileCompactJSON}" != "" ]; then
		debug1 "Emitting compact JSON."
		echo "${ruleJSON}" \
		| jq -c . \
		>> "${outFileCompactJSON}"
		fi
	if [ "${outFileQDCSV}" != "" ]; then
		debug1 "Emitting quote-delimited CSV."
		echo "${ruleJSON}" \
		| jq -c "$csvRuleRepresentation" \
		| sed "s${unitSeparator}\"${unitSeparator}${unitSeparator}g" \
		| sed "s${unitSeparator}^{${unitSeparator}\"${unitSeparator}" \
		| sed -E "s${unitSeparator},enabled:(true|false),name:${unitSeparator}\",\"\1\",\"${unitSeparator}" \
		| sed "s${unitSeparator},comments:${unitSeparator}\",\"${unitSeparator}" \
		| sed "s${unitSeparator},source:\[${unitSeparator}\",\"${unitSeparator}" \
		| sed "s${unitSeparator}\],sourceNegate:${unitSeparator}\",\"${unitSeparator}" \
		| sed "s${unitSeparator},destination:\[${unitSeparator}\",\"${unitSeparator}" \
		| sed "s${unitSeparator}\],destinationNegate:${unitSeparator}\",\"${unitSeparator}" \
		| sed "s${unitSeparator},service:\[${unitSeparator}\",\"${unitSeparator}" \
		| sed "s${unitSeparator}\],serviceNegate:${unitSeparator}\",\"${unitSeparator}" \
		| sed "s${unitSeparator},action:${unitSeparator}\",\"${unitSeparator}" \
		| sed "s${unitSeparator}}\$${unitSeparator}\"${unitSeparator}" \
		| sed "s${unitSeparator}\\n${unitSeparator}~${unitSeparator}g" \
		| sed -E "s${unitSeparator}([^\"]),([^\"])${unitSeparator}\1~\2${unitSeparator}g" \
		| tr '~' '\n' \
		>> "${outFileQDCSV}"
# For jq 1.5, replace the above with this:
# 		echo "${ruleJSON}" \
# 		| jq -r "$csvRuleRepresentation" \
# 		| tr '\t' '\n' \
# 		>> "${outFileQDCSV}"
		fi
	if [ "${stdoutPrettyJSON}" -eq 1 ]; then
		debug1 "Emitting pretty-print JSON to STDOUT."
		echo "${ruleJSON}" \
		| jq .
		fi
	}

scanMDS() {
	debug1 "Entering scanMDS."
	mgmt_cli --port "${apiPort}" \
		login \
		read-only true \
		-r true > sessionFile.txt
	MDSDomains=( $(mgmt_cli --port "${apiPort}" \
		-s sessionFile.txt \
		--format json \
		show domains \
		| jq -c ".objects[].uid" \
		| sed 's/"//g') )
	for CMA in "${MDSDomains[@]}"; do
		debug1 "Scanning CMA $CMA."
		mgmt_cli --port "${apiPort}" \
			login \
			read-only true \
			domain $CMA \
			-r true > sessionFile_$CMA.txt
		foundRules=$(findRulesUsingIPs)
		foundRules=$(dereferenceAllObjectsInRules "${foundRules}")
		masterOutput "${foundRules}"
		done
	cleanupMDS
	}

scanSmartCenter() {
	## Here, I'm treating a SmartCenter as a special case. Effectively as a CMA
	## with no MDS. That way, all the subsequent calls can work with either a
	## CMA or a SmartCenter with no modification and no further conditionals.
	debug1 "Entering scanSmartCenter."
	CMA="SmartCenter"
	mgmt_cli --port "${apiPort}" \
		login \
		read-only true \
		-r true > sessionFile_$CMA.txt
	foundRules=$(findRulesUsingIPs)
	foundRules=$(dereferenceAllObjectsInRules "${foundRules}")
	masterOutput "${foundRules}"
	cleanupSmartCenter
	}

cleanupMDS() {
	debug1 "Entering cleanupMDS."
	for CMA in "${MDSDomains[@]}"; do
		debug1 "Cleaning up CMA: $CMA"
		mgmt_cli --port "${apiPort}" \
			-s sessionFile_$CMA.txt \
			logout>/dev/null
		/bin/rm sessionFile_$CMA.txt
		done
	debug1 "Cleaning up MDS."
	mgmt_cli --port "${apiPort}" \
		-s sessionFile.txt \
		logout>/dev/null
	/bin/rm sessionFile.txt
	/bin/rm objects.sed
	}

cleanupSmartCenter() {
	debug1 "Entering cleanupSmartCenter."
	mgmt_cli --port "${apiPort}" \
		-s sessionFile_$CMA.txt \
		logout>/dev/null
	/bin/rm sessionFile_$CMA.txt
	/bin/rm objects.sed
	}

if [ $# -eq 0 ]; then
	printUsage
	exit 1
	fi

declare -i ipsToRulesDebug=0
declare -i apiPort=443
ipList=()
outFilePrettyJSON=""
outFileCompactJSON=""
outFileQDCSV=""
declare -i stdoutPrettyJSON=0

while getopts ":dhp:J:j:c:" options; do
	case "$options" in
	d) # Increase debug level, up to twice.
		ipsToRulesDebug+=1
		;;
	h) # Print usage information.
		printUsage
		exit 0
		;;
	p) # Specify the port to use for API connections. Default is 443.
		apiPort="${OPTARG}"
		;;
	J) # Write pretty-print JSON output to <file>.
		outFilePrettyJSON="${OPTARG}"
		;;
	j) # Write compact JSON output to <file>.
		outFileCompactJSON="${OPTARG}"
		;;
	c) # Write quote-delimited CSV output to <file>.
		outFileQDCSV="${OPTARG}"
		;;
	O) # Write pretty-print JSON output to STDOUT.
		stdoutPrettyJSON=1
		;;
	\?) # Handle invalid options.
		echo "ERROR: Invalid option: -$OPTARG" >&2
		echo ""
		printUsage
		exit 1
		;;
	:)
		echo "ERROR: Option -$OPTARG requires an argument." >&2
		echo ""
		printUsage
		exit 1
		;;
	esac
	done

# Output prep work
if [ "${outFileCompactJSON}" = "" ] &&
	[ "${outFilePrettyJSON}" = "" ] &&
	[ "${outFileQDCSV}" = "" ]; then
	# If no output files are specified, default to pretty-print on STDOUT.
	stdoutPrettyJSON=1
	fi
if [ "${outFileQDCSV}" != "" ]; then
	echo "Rule ID,Rule enabled?,Rule Name,Comments,Source,Source negated?,Destination,Dest. negated?,Service,Service negated?,Action" > "${outFileQDCSV}"
	fi

shift "$((OPTIND-1))" # Remove all the options getopts has handled.

debug1 "Debug level set to ${ipsToRulesDebug}."
debug1 "Using port ${apiPort} to connect to API."

ipList=( $(echo "${@}" | sort -u) )
if [ "${#ipList[@]}" -eq 0 ]; then
	echo "ERROR: No IPs provided." >&2
	printUsage
	exit 1
	fi
debug1 "IPs we are about to search for: ${ipList[@]}"

if [ ! $(cpprod_util FwIsFirewallMgmt) ]; then
	echo "ERROR: This script must be run on a SmartCenter, but cpprod_util says this is not one." >&2
	exit 1
	fi

mdsstat >/dev/null 2>/dev/null
isMDS=$?
if [ $isMDS -eq 0 ]; then
	scanMDS
	else
	scanSmartCenter
	fi
