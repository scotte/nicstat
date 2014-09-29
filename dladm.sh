#!/bin/sh
# dladm.sh -	Build glue for libdladm:dladm_walk_datalink_id

LIBDLADM=/lib/libdladm.so.1

CPP_DEFINES="-DUSE_DLADM"

if [ -f "$LIBDLADM" ]; then
    match=`nm -hgp $LIBDLADM | grep ' T dladm_walk_datalink_id'`
    if [ -n "$match" ]; then
	case $1 in
	'def'* | -[dD] )
	    if [ -f /usr/include/libnetcfg.h ]; then
		CPP_DEFINES="$CPP_DEFINES -DHAVE_LIBNETCFG"
	    fi
	    echo $CPP_DEFINES
	    ;;
	'lib'* | -l )
	    echo "-zlazyload -ldladm" ;;
	esac
    fi
fi
