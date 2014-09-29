nicstat 1.95 README
===================

nicstat is licensed under the Artistic License 2.0.  You can find a
copy of this license as LICENSE.txt included with the nicstat
distribution, or at http://www.perlfoundation.org/artistic_license_2_0


AUTHORS
	timothy.cook@oracle.com (formerly tim.cook@sun.com), Brendan Gregg
	(formerly Brendan.Gregg@sun.com)

HOW TO BUILD ON SOLARIS
	mv Makefile.Solaris Makefile
	make

HOW TO BUILD ON LINUX
	mv Makefile.Linux Makefile
	make

HOW TO INSTALL
	make [BASEDIR=<dir>] install

	Default BASEDIR is /usr/local

HOW TO INSTALL A MULTI-PLATFORM SET OF BINARIES
        1. (Optional) Change BASEDIR, BINDIR and/or MP_DIR in Makefile
	2. make install_multi_platform
	3. (Optional) add links or binaries for your platform(s)

HOME PAGE
	https://blogs.oracle.com/timc/entry/nicstat_the_solaris_and_linux
