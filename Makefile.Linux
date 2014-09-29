# Makefile.Linux -	for nicstat, Linux platform edition

FILES =	nicstat

SOURCES =	nicstat.c

BINARY =	nicstat
BINARIES =	$(BINARY) enicstat

CC =		gcc
#-- This may be useful on RHEL versions where gcc is only version 4.1
#CC =		gcc43

#COPT =		-g
COPT =		-O3

# If you are building on (or for) a Linux distro that lacks support
# for ILP32, you can usually build an LP64 executable by changing
# CMODEL to -m64, or leaving it undefined (-m64 is the default on most
# Linux distros).

#CMODEL =
CMODEL =	-m32

CFLAGS =	$(COPT) $(CMODEL)

INSTALL =	sudo install -o bin -g bin
SETUINSTALL =	sudo install -o root -g root -m 4511

#-- Change this for your OS.  Look in nicstat.sh to see if you want
#-- to be more specific
OSTYPE =	RedHat
OSREL =		5
CPUTYPE =	i386

#--------------------------------

BASEDIR =	/usr/local
BINDIR =	$(BASEDIR)/bin
MANDIR =	$(BASEDIR)/share/man
MP_DIR =	$(BINDIR)

BINARY =	nicstat
#NATIVE_BINARY =	.$(BINARY).$(OSTYPE)_$(OSREL)_$(CPUTYPE)
NATIVE_BINARY =	`./nicstat.sh --bin-name`


all : $(FILES)
	mv $? $(NATIVE_BINARY)

$(NATIVE_BINARY) : $(BINARY)
	mv $? $@

#-- Choose one of these two install methods:
install : install_native install_man
#install : install_multi_platform install_man

install_native : $(BINARIES)
	$(SETUINSTALL) $(NATIVE_BINARY) $(BINDIR)/$(BINARY)
	$(INSTALL) -m 555 enicstat $(BINDIR)

#
# You may need to tweak the chown/chmod commands - all Linux
# binaries need setuid-root if they are to use the SIOCETHTOOL ioctl
# (which is optional, see the man page)
#
install_multi_platform : $(NATIVE_BINARY) enicstat
	$(INSTALL) -m 755 nicstat.sh $(BINDIR)/nicstat
	$(INSTALL) -m 555 enicstat $(BINDIR)
	sudo cp -p .nicstat.* $(MP_DIR)
	sudo chown root:bin $(MP_DIR)/.nicstat.Linux*
	sudo chmod 4711 $(MP_DIR)/.nicstat.Linux*

install_man: nicstat.1
	$(INSTALL) -m 444 nicstat.1 $(MANDIR)/man1/nicstat.1

lint :
	lint $(SOURCES) $(LDLIBS)

clean :
	rm -f $(FILES)
