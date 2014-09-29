#!/bin/sh
# nicstat.sh -	Wrapper for multi-architecture nicstat install
#
# Tim Cook, 27 Aug 2012

# Let us see if we can figure out the OS & CPU architecture cheaply

ostype=unknown
osrel=unknown
cputype=unknown

OSTYPE_PATH=/proc/sys/kernel/ostype

if [ -f "/etc/release" ]; then
    # Might be Solaris
    read f1 f2 f3 rest < /etc/release
    case " $f1 $f2 $f3 $rest" in
    ' Solaris '[0-9]*' '*' X86' )
	ostype=Solaris ; osrel=$f2 ; cputype=i386 ;;
    ' Solaris '[0-9]*' '*' SPARC' )
	ostype=Solaris ; osrel=$f2 ; cputype=sparc ;;
    ' '[A-Z]*' Solaris '[0-9]*' '*' X86' )
	ostype=Solaris ; osrel=$f3 ; cputype=i386 ;;
    ' '[A-Z]*' Solaris '[0-9]*' '*' SPARC' )
	ostype=Solaris ; osrel=$f3 ; cputype=sparc ;;
    ' '[A-Z]*' Solaris '[0-9]*.[0-9]*' X86' )
	ostype=Solaris ; rel=$f3 ; cputype=i386 ;;
    ' '[A-Z]*' Solaris '[0-9]*.[0-9]*' SPARC' )
	ostype=Solaris ; rel=$f3 ; cputype=sparc ;;
    *' Solaris '* )
	ostype=Solaris
	cpu=`uname -p`
	case "$cpu" in
	'i386' | 'sparc' )	cputype=$cpu ;;
	esac
	rel=`uname -r`
	;;
    esac
    case "$rel" in
    5.8 )			osrel=8 ;;
    5.9 )			osrel=9 ;;
    5.10 )			osrel=10 ;;
    # NOTE: Treat Solaris releases > 11 as if they were 11
    5.1[1-9] | 1[1-9].* )	osrel=11 ;;
    esac
elif [ -f "$OSTYPE_PATH" -a ! -s "$OSTYPE_PATH" ]; then
    read f1 rest < "$OSTYPE_PATH"
    case " $f1 " in
    ' Linux ' )			ostype=Linux ; osclass=Linux ;;
    esac
    # Let's see if we can refine that
    # NOTE: I would want to bunch popular variants that are similar together
    # (e.g. Ubuntu and Debian; RHEL & CentOS & OEL)
    if [ -f /etc/redhat-release ]; then
	ostype=RedHat
	read f1 f2 f3 f4 f5 f6 f7 f8 f9 rest < /etc/redhat-release
	if [ "$f6" = 'release' ]; then
	    osrel=$f7
	elif [ "$f5" = 'release' ]; then
	    osrel=$f6
	elif [ "$f7" = 'release' ]; then
	    osrel=$f7
	elif [ -f /proc/sys/kernel/osrelease ]; then
	    read osrel < /proc/sys/kernel/osrelease
	fi
	case "$osrel" in
	*'.'* )
		osrel=${osrel%%.*} ;;
	esac
    elif [ -f /etc/SuSE-release ]; then
	ostype=SuSE
	while read f1 f2 f3 rest
	do
	    if [ "$f1 $f2" = 'VERSION =' ]; then
		osrel=$f3
	    fi
	done < /etc/SuSE-release
    elif [ -f /etc/lsb-release ]; then
	save_IFS=$IFS
	IFS='= '
	while read name value
	do
	    case "$name" in
	    'DISTRIB_ID' )	ostype=$value ;;
	    'DISTRIB_RELEASE' )	osrel=${value%%.*} ;;
	    esac
	done < /etc/lsb-release
	IFS=$save_IFS
    fi
    if [ -z "$ostype" -a -f "/etc/issue" ]; then
	read f1 f2 f3 f4 f5 f6 rest < /etc/issue
	case "$f1 $f2 $f3 $f4 $f5 $f6 $rest " in
	'Ubuntu [1-9].'* )		ostype=Ubuntu ; osrel=${f2%%.*} ;;
	'Ubuntu [1-9][0-9].'* )		ostype=Ubuntu ; osrel=${f2%%.*} ;;
	'Red Hat Enterprise Server release '[1-9]* )
					ostype=RedHat ; osrel=${f6%%.*} ;;
	'Fedora release '[0-9]* )	ostype=Fedora ; osrel=${f3%%.*} ;;
	'Fedora Core release '[0-9]* )	ostype=Fedora ; osrel=${f4%%.*} ;;
	esac
    fi
fi

if [ "X$ostype" = "Xunknown" ]; then
    os=`uname -sr`
    case "$os" in
    'SunOS 5.'* )		ostype=Solaris ;;
    'Linux '* )			ostype=Linux ; osclass=Linux ;;
    esac
fi

if [ "X$cputype" = "Xunknown" ]; then
    cpu=`uname -mp`
    case "$cpu" in
    'i'[3456]'86 '* )		cputype=i386 ;;
    'i86pc '* )			cputype=i386 ;;
    *' sparc' )			cputype=sparc ;;
    'x86_64 '* )		cputype=i386 ;;
    esac
fi

if [ "$ostype,$osrel,$kernrel" = "Linux,," ]; then
    # Would be useful to at least get the Linux kernel release
    rel=`uname -r`
    case "$rel" in
    2.4.* )			kernrel=2.4 ;;
    2.6.* )			kernrel=2.6 ;;
    esac
fi


#------------------------------------------------------------------------
#	MAIN

# echo "os = [$ostype]"
# echo "cpu = [$cputype]"
# echo "release = [$osrel]"
# exit 0

SCRIPT_DIR=`dirname "$0"`
BIN_DIR=$SCRIPT_DIR
BIN_NAME=.nicstat

case "$#,$1" in
'1,--bin-name' )
	echo "${BIN_NAME}.${ostype}_${osrel}_${cputype}"
	exit 0
	;;
esac

for s in "${ostype}_${osrel}_${cputype}" \
	 "${osclass}_${kernrel}_${cputype}" \
	 "${ostype}_${cputype}" \
	 "${osclass}_${cputype}"
do
    if [ -x "$BIN_DIR/$BIN_NAME.$s" ]; then
	BIN="$BIN_DIR/$BIN_NAME.$s"
	break
    fi
done
if [ "X$BIN" = "X" ]; then
    echo "$0: can not find platform executable" >& 2
    exit 1
fi

exec "$BIN" "$@"
