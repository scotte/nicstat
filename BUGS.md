Bugs
====

The following bugs are fixed in this fork of nicstat.

Bug #1 - Utilization with 10GbE nics on RHEL is incorrect
---------------------------------------------------------

This fixes http://sourceforge.net/p/nicstat/bugs/1/ by applying the
patch provided by Darren in that that bug report.

This bug occurs due to an integer overflow for 10Gb interfaces and
is not specific to RHEL.

Bug #3 - -S option ignored if SIOCETHTOOL succeeds
--------------------------------------------------

This fixes http://sourceforge.net/p/nicstat/bugs/3/ by applying the
patch I provided in that that bug report.

This patch may not be ideal, and should be revisited for completeness,
but does resolve the issue for me.

Bug #4 - Utilization always computed as half duplex
---------------------------------------------------

This fixes http://sourceforge.net/p/nicstat/bugs/4/ by applying the
patch I provided in that that bug report.

When utilization is calculated, nicp->duplex checks for the value of
"2" for a full duplex link, but on Linux this value is "1" (see
/usr/include/linux/ethtool.h). Fix is to use DUPLEX_FULL #define.

Bug #5 - Remove unnecessary #ifdef block
----------------------------------------

This fixes http://sourceforge.net/p/nicstat/bugs/5/ by applying the
patch I provided in that that bug report.

An #ifdef for linux vs solaris is not needed as the DUPLEX_ #defines
can be used consistently instead.
