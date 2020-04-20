# ipsToRulesCP
I recently had the need to build a table out of all of the rules referencing any IP address in a list of addresses. Basically a rule audit for all the rules involved in a given application. Rather than spend days taking and arranging screenshots, I spent them building this tool.

# USAGE
The script should be run as root (in expert mode, and with elevated privileges if you use low-privilege users) on the SmartCenter or MDS. Doesn't need any credentials. It does everything via the API in read-only mode.

Usage is given right at the top of the script. It also prints the usage if you run the script with no switches or if you run it with the -h switch:

```[Bob_Zimmerman@MySmartCenter]# ./ipsToRules.sh -h
Usage:
./ipsToRules.sh [-d] [-h] [-J file] [-j file] [-c file] [-O] <list>
Default output is pretty-print JSON to STDOUT, suitable for output redirection.
	-d	Increase debug level, up to twice.
	-h	Print this usage information.
	-J file	Write pretty-print JSON output to <file>.
	-j file	Write compact JSON output to <file>. One line per rule.
	-c file	Write quote-delimited CSV output to <file>.
	-O	Write pretty-print JSON output to STDOUT.
	list	List of IPs to search for, separated by spaces.

Example:
./ipsToRules.sh -J myAppPretty.json -j myApp.json -c myApp.csv 10.64.32.16 10.20.30.40
```
As you can see, it currently has options for compact JSON output, pretty JSON output, and quote-delimited CSV output. It should be pretty clear from the code how to write a new output formatter. Just needs a new variable for the name, a new switch in the getopts case statement, a little output prep work, and a new item in the "masterOutput" function.

The only privileged commands it uses right now are 'cpprod_util FwIsFirewallMgmt' (to detect if it is run on a firewall instead of a management) and 'mdsstat' (to detect if it is a SmartCenter or MDS), within a few lines of each other at the bottom. You can make a version which will work only on a SmartCenter or only on an MDS, and it would work as an unprivileged user.

# KNOWN LIMITATIONS
It currently accepts only IP addresses. Haven't yet gotten around to writing logic for spotting CIDR notation, or for looking up networks once I've found them in the input.

There's a big case statement in the middle for dereferencing objects. It includes all the object types I personally needed, but I'm sure there are plenty which are not included.

I'm pretty sure there are error cases I don't handle properly, such as if none of the IP addresses are found.
