Bugs
====

The following bugs are fixed in this fork of nicstat.

Bug #1 - Utilization with 10GbE nics on RHEL is incorrect
---------------------------------------------------------

This fixes http://sourceforge.net/p/nicstat/bugs/1/ by applying
[the patch](https://github.com/scotte/nicstat/commit/3bd5866856ecf6a1312931851d4c5dcd0063d60a)
provided by Darren in that that bug report.

This bug occurs due to an integer overflow for 10Gb interfaces and
is not specific to RHEL.

Bug #3 - -S option ignored if SIOCETHTOOL succeeds
--------------------------------------------------

This fixes http://sourceforge.net/p/nicstat/bugs/3/ by applying
[the patch](https://github.com/scotte/nicstat/commit/23c7de0b7c39b9b6ec27ab34e479afb48bcc6711)
I provided in that that bug report.

This patch may not be ideal, and should be revisited for completeness,
but does resolve the issue for me.

Bug #4 - Utilization always computed as half duplex
---------------------------------------------------

This fixes http://sourceforge.net/p/nicstat/bugs/4/ by applying
[the patch](https://github.com/scotte/nicstat/commit/9ea8c81c55e4cf7487c1eebbb2976b60b016fa02)
I provided in that that bug report.

When utilization is calculated, nicp->duplex checks for the value of
"2" for a full duplex link, but on Linux this value is "1" (see
/usr/include/linux/ethtool.h). Fix is to use DUPLEX_FULL #define.

Bug #5 - Remove unnecessary #ifdef block
----------------------------------------

This fixes http://sourceforge.net/p/nicstat/bugs/5/ by applying
[the patch](https://github.com/scotte/nicstat/commit/303aea60db5b9ebc957b1bac368832b85ef88f94)
I provided in that that bug report.

An #ifdef for linux vs solaris is not needed as the DUPLEX_ #defines
can be used consistently instead.

Bug #6 - UDP stats scanf has too many arguments
-----------------------------------------------

This fixes http://sourceforge.net/p/nicstat/bugs/6/ by applying
[the patch](https://github.com/scotte/nicstat/commit/d536743abb23fb1174b0f801a4eed7d9ceac4763)
I provided in that that bug report.

There were too many arguments to fscanf(), resulting in the following warning
when compiling with -Wall:

nicstat.c: In function ‘load_snmp’:
nicstat.c:1569:8: warning: too many arguments for format [-Wformat-extra-args]

Bug #7 - Remove unused variables
--------------------------------

This fixes http://sourceforge.net/p/nicstat/bugs/7/ by applying
[the patch](https://github.com/scotte/nicstat/commit/f59393f19a4c7ca7c1dc8a873afe8cd6a1a4b036)
I provided in that that bug report.

There are two unused variables in Linux (one is used only for solaris,
the other used nowhere), found when compiling with -Wall.
