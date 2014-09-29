nicstat
=======

nicstat was written by Brendan Gregg and Tim Cook of Sun Microsystems - originally
for Solaris, ported to Linux.

The official, upstream repository for nicstat is at https://sourceforge.net/projects/nicstat/

This fork
=========

This fork exists primarily to address some bugs in the upstream code
(see https://sourceforge.net/p/nicstat/bugs/)

The original, imported source is on the
[upstream_1.95](https://github.com/scotte/nicstat/tree/upstream_1.95)
branch of this repository.

If any changes are made to the upstream source, I will merge them in in an
attempt to keep this tree in sync with upstream. Pull requests are welcome for
any additional bugs of features as well.

License
=======

nicstat is entirely the property of it's originators. All rights, restrictions,
limitations, warranties, etc remain per nicstat's owners and license.

nicstat is licensed under the Artistic License 2.0.  You can find a
copy of this license as [LICENSE.txt](LICENSE.txt) included with the nicstat
distribution, or at http://www.perlfoundation.org/artistic_license_2_0

README.txt
==========

Following is the full contents of [README.txt](README.txt):

```
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
```
