#!/bin/bash
UNISTD="/usr/include/asm/unistd_64.h"

IFS="
"
function gn() { echo -n "#ifndef "; echo "$*"|cut -d ' ' -f 2;   echo "$*";   echo "#endif"; }
for i in $(cat $UNISTD); do gn $i;done 
