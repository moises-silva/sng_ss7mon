#!/bin/bash
span=$1
chanrange=`seq $2 $3`
for i in $chanrange
do
	sng_ss7mon -dev s${span}c${i} -pcap s${span}c${i}.pcap -pcap_mtp2_hdr -hexdump s${span}c${i}.hex -syslog -log info &> /dev/null &
done

