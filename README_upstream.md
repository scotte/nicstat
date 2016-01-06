nicstat is a Solaris and Linux command-line that prints out network
statistics for all network interface cards (NICs), including packets,
kilobytes per second, average packet sizes and more.

It was developed by Tim Cook and Brendan Gregg, both formerly of Sun
Microsystems.

Changes for Version 1.95, January 2014
--------------------------------------

## Common

- Added "-U" option, to display separate read and write
  utilization.

- Simplified display code regarding "-M" option.

## Solaris

- Fixed fetch64() to check type of kstats

- Fixed memory leak in update_nicdata_list()

Changes for Version 1.92, October 2012
--------------------------------------

## Common

- Added "-M" option to change throughput statistics to Mbps
  (Megabits per second).  Suggestion from Darren Todd.

- Fixed bugs with printing extended parseable format (-xp)

- Fixed man page's description of extended parseable output.

## Solaris

- Fixed memory leak associated with g_getif_list

- Add 2nd argument to dladm_open() for Solaris 11.1

- Modify nicstat.sh to handle Solaris 11.1

## Linux

- Modify nicstat.sh to see "x86_64" cputype as "i386".  All Linux
  binaries are built as 32-bit, so we do not need to differentiate
  these two cpu types.

Changes for Version 1.90, April 2011
------------------------------------

## Common

- nicstat.sh script, to provide for automated multi-platform
  deployment.  See the Makefile's for details.

- Added "-x" flag, to display extended statistics for each
  interface.

- Added "-t" and "-u" flags, to include TCP and UDP
  (respectively) statistics.  These come from tcp:0:tcpstat
  and udp:0:udpstat on Solaris, or from /proc/net/snmp and
  /proc/net/netstat on Linux.

- Added "-a" flag, which equates to "-tux".

- Added "-l" flag, which lists interfaces and their
  configuration.

- Added "-v" flag, which displays nicstat version.

## Solaris

- Added use of libdladm.so:dladm_walk_datalink_id() to get list of
  interfaces.  This is better than SIOCGLIFCONF, as it includes
  interfaces given exclusively to a zone.  
  NOTE: this library/routine can be linked in to nicstat in "lazy"
  mode, meaning that a Solaris 11 binary built with knowledge of the
  routine will also run on Solaris 10 without failing when the routine
  or library is not found - in this case nicstat will fall back to the
  SIOGLIFCONF method.

- Added search of kstat "link_state" statistics as a third
  method for finding active network interfaces.  See the man
  page for details.

##  Linux

- Added support for SIOCETHTOOL ioctl, so that nicstat can
  look up interface speed/duplex (i.e. "-S" flag not necessarily
  needed any longer).

- Removed need for LLONG_MAX, improving Linux portability.
