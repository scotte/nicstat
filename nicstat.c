/*
 * nicstat - print network traffic, Kb/s read and written.
 *
 * Copyright (c) 2005-2014, Brendan.Gregg@sun.com and Tim.Cook@sun.com
 *
 * nicstat is licensed under the Artistic License 2.0.  You can find
 * a copy of this license as LICENSE.txt included with the nicstat
 * distribution, or at http://www.perlfoundation.org/artistic_license_2_0
 */

#define	NICSTAT_VERSION		"1.95"

/* Is this GNU/Linux? */
#if defined(__linux__) || defined(__linux) || defined(linux)
#define	OS_LINUX	1
#endif

/* Is this Solaris? */
#if defined(sun) || defined(__sun)
#if defined(__SVR4) || defined(__svr4__)
#define	OS_SOLARIS	1
#endif
#endif

#if ! defined(OS_SOLARIS) && ! defined(OS_LINUX)
#error	"nicstat is not supported on your OS yet"
#endif

#ifndef	DEBUG
#define	DEBUG	0
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>
#include <signal.h>

#ifdef OS_SOLARIS
#include <sys/sockio.h>
#include <kstat.h>
#include <libgen.h>
#ifdef USE_DLADM
#include <libdladm.h>
#include <libdllink.h>
#include <dlfcn.h>
#include <link.h>
#ifdef HAVE_LIBNETCFG
#include <libnetcfg.h>
#endif
#endif
#ifndef LIFC_ALLZONES	/* Comes from <net/if.h> in 5.10 & later */
#define	LIFC_ALLZONES	0x08
#endif
#ifndef LIFC_UNDER_IPMP	/* <net.if.h> in 5.11 */
#define	LIFC_UNDER_IPMP	0x0
#endif
#ifndef LIFC_ENABLED	/* <net.if.h> in 5.11 */
#define	LIFC_ENABLED	0x0
#endif
#ifndef MAXLINKNAMELEN	/* <net/if.h> in 5.11 */
#define	MAXLINKNAMELEN	LIFNAMSIZ
#endif
#define	LIFR_FLAGS_TYPE	uint64_t
#else /* OS_SOLARIS */
#include <poll.h>
#endif /* OS_SOLARIS */

#ifdef OS_LINUX
/* #include <linux/if.h> */
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <linux/types.h>
#include <linux/ethtool.h>
#define	PROC_NET_DEV_PATH	"/proc/net/dev"
#define	PROC_NET_SNMP_PATH	"/proc/net/snmp"
#define	PROC_NET_NETSTAT_PATH	"/proc/net/netstat"
#define	PROC_NET_BUFSIZ		(128 * 1024)
#define	PROC_UPTIME		"/proc/uptime"
/* Needs to be fixed if not built under ILP32 */
typedef unsigned long long	uint64_t;
typedef unsigned int		uint32_t;
extern char *optarg;
extern int optind, opterr, optopt;
#endif /* OS_LINUX */

#ifdef OS_LINUX
typedef __u8			duplex_t;
/* This may be defined by <linux/ethtool.h> */
#ifndef	DUPLEX_UNKNOWN
#define	DUPLEX_UNKNOWN		0xFF
#endif /* DUPLEX_UNKNOWN */
#else
typedef uint32_t		duplex_t;
#define	DUPLEX_UNKNOWN		0
#define	DUPLEX_HALF		1
#define	DUPLEX_FULL		2
#endif /* OS_LINUX */

#ifndef	B_TRUE
#define	B_TRUE		1
#define	B_FALSE		0
#endif

#ifndef	streql
#define	streql(a, b)	(strcmp((a), (b)) == 0)
#endif

#define	PAGE_SIZE 20
#define	INTERVAL 1
#define	LOOP_MAX 1

#ifdef OS_LINUX
#define	GETOPT_OPTIONS		"hi:sS:znplvxtuaMmU"
#else
#define	GETOPT_OPTIONS		"hi:sznpklvxtuaMmU"
#endif

/*
 * UDP stats
 */
typedef struct udp_stats {
	struct timeval tv;		/* tv_sec, tv_usec */
	uint64_t inDatagrams;
	uint64_t outDatagrams;
	uint64_t inErrors;
	uint64_t outErrors;
} udpstats_t;

static udpstats_t *g_udp_old, *g_udp_new;

typedef struct tcp_stats {
	struct timeval tv;		/* tv_sec, tv_usec */
	uint64_t inDataInorderSegs;
	uint64_t outDataSegs;
	uint64_t inDataInorderBytes;
	uint64_t inDataUnorderSegs;
	uint64_t inDataUnorderBytes;
	uint64_t outDataBytes;
	uint64_t estabResets;
	uint64_t outRsts;
	uint64_t attemptFails;
	uint64_t retransBytes;
	uint64_t passiveOpens;
	uint64_t activeOpens;
	uint64_t halfOpenDrop;
	uint64_t listenDrop;
	uint64_t listenDropQ0;
} tcpstats_t;

static tcpstats_t *g_tcp_old, *g_tcp_new;

#ifdef OS_SOLARIS
static kstat_t *g_tcp_ksp, *g_udp_ksp;
#endif

/*
 * Interface stats
 */
typedef struct nic_stats {
	struct timeval tv;		/* tv_sec, tv_usec */
	uint64_t rbytes;		/* total read bytes */
	uint64_t wbytes;		/* total written bytes */
	uint64_t rpackets;		/* total read packets */
	uint64_t wpackets;		/* total written packets */
	uint64_t ierr;			/* total input errors */
	uint64_t oerr;			/* total output errors */
	uint64_t coll;			/* total collisions */
	uint64_t nocp;			/* total nocanput */
	uint64_t defer;			/* total defers */
	uint64_t sat;			/* saturation value */
} nicstats_t;

typedef struct nicdata {
	struct nicdata *next;	/* pointer to next */
	char *name;		/* interface name (e.g. "lo0") */
	uint32_t flags;
#ifdef OS_LINUX
	int report;		/* non-zero means we intend to print */
#endif
#ifdef OS_SOLARIS
	kstat_t *ls_ksp;
	kstat_t *op_ksp;
	uint32_t ls_types;
	uint32_t op_types;
	LIFR_FLAGS_TYPE if_flags;
#endif
	uint64_t speed;			/* speed of interface */
	duplex_t duplex;
	struct nic_stats old;	/* stats from previous lookup */
	struct nic_stats new;	/* stats from current lookup */
} nicdata_t;

typedef struct if_list {
	struct if_list *next;
	char *name;
#ifdef OS_LINUX
	struct nicdata *nicp;
#endif
} if_list_t;

/*
 * kstat type flags
 *
 * These are in decreasing order of preference; i.e, the highest order
 * bit will be chosen as the preferred source.  These bits have been
 * chosen to allow addition above, below and in-between the existing
 * choices.
 */
#define	KS_LINK			0x40000		/* link:<n>:<if>:<stat> */
#define	KS_DRV_MAC		0x10000		/* <drv>:<n>:mac:<stat> */
#define	KS_DIN			0x04000		/* <drv>:<n>:<if>:<stat> */
#define	KS_DRV			0x01000		/* <drv>:<n>:*:<stat> */
#define	KS_NAME			0x00400		/* <if>:*:*:<stat> */

/*
 * Other interface flags - for nicdata_t.flags
 */
#define	NIC_LIF_UP		0x00000001	/* IFF_UP */
#define	NIC_KS_UP		0x00000002	/* kstat link_state = 1 */
#define	NIC_LOOPBACK		0x00000010	/* Is a IFF_LOOPBACK */
#define	NIC_NO_GLIFFLAGS	0x00000100	/* no ioctl(,SIOCGLIFFLAGS,) */
#define	NIC_NO_KSTATS		0x00000200	/* Can't even get packets */
#define	NIC_NO_LINKSTATE	0x00000400	/* No :::link_state */
#define	NIC_NO_GSET		0x00000800	/* ETHTOOL_GSET fails */
#define	NIC_NO_SFLAG		0x00000200	/* No -S for this i'face */
#define	NIC_UP		(NIC_KS_UP | NIC_LIF_UP)

#define	NIC_LK_IS_OK		0x00001000	/* ls_ksp == op_ksp */

#define	NIC_LK_UPDATED		0x00010000	/* ls_ksp up to date */
#define	NIC_OK_UPDATED		0x00020000	/* op_ksp up to date */
#define	NIC_KU_UPDATED		0x00040000	/* NIC_KS_UP up to date */
#define	NIC_LU_UPDATED		0x00080000	/* NIC_LIF_UP up to date */

/* These bits indicate we have updated some data */
#define	NIC_UPDATED_FLAGS	(NIC_LK_UPDATED | NIC_OK_UPDATED | \
				NIC_KU_UPDATED | NIC_LU_UPDATED)

/* These bits are capabilities - should be static */
#define	NIC_CAPAB	(NIC_CAN_GLIFFLAGS | NIC_HAVE_KSTATS | NIC_LOOPBACK)

#ifdef OS_LINUX
struct if_speed_list {
	struct if_speed_list *next;
	char *name;
	uint64_t speed;
	int duplex;
};
static struct if_speed_list *g_if_speed_list = NULL;
#endif /* OS_LINUX */

/*
 * This will contain everything we need to know about each interface, and
 * will be dynamically allocated.
 */
static struct nicdata *g_nicdatap = NULL;

/* Print style for NICs */
enum { STYLE_FULL = 0, STYLE_FULL_UTIL, STYLE_SUMMARY, STYLE_PARSEABLE,
	STYLE_EXTENDED, STYLE_EXTENDED_UTIL,
	STYLE_EXTENDED_PARSEABLE, STYLE_NONE };

static int g_nicdata_count = 0;		/* number of if's we are tracking */
static int g_style;			/* output style */
static int g_skipzero;			/* skip zero value lines */
static int g_nonlocal;			/* list only non-local (exclude lo0) */
static int g_someif;			/* trace some interfaces only */
static int g_list;
static int g_udp;			/* show UDP stats */
static int g_tcp;			/* show TCP stats */
static int g_opt_x;
static int g_opt_p;
static int g_verbose;
static int g_forever;			/* run forever */
static char **g_tracked;		/* tracked interfaces */
static int g_line;			/* output line counter */
static char *g_progname;			/* ptr to argv[0] */
static int g_caught_cont;		/* caught SIGCONT - were suspended */
static int g_opt_m;			/* show results in Mbps (megabits) */
static int g_opt_U;			/* show in and out %Util */

/* Used in display headers - default is when displaying KB/s */
static char *g_runit_1 = "rKB/s";
static char *g_wunit_1 = "wKB/s";
static char *g_runit_2 = "RdKB";
static char *g_wunit_2 = "WrKB";

static int g_sock;			/* Socket for interface ioctl's */

#ifdef OS_SOLARIS
static int g_opt_k;
static kstat_ctl_t *g_kc;		/* kstat chain pointer */
static int g_new_kstat_chain = B_TRUE;	/* kstat chain updated */
#ifdef USE_DLADM
/* This is set to TRUE if we can load the libdladm function we need */
static int g_use_dladm;
static dladm_handle_t g_handle = NULL;
#endif
#endif /* OS_SOLARIS */

#ifdef OS_LINUX
static unsigned long g_boot_time;	/* when we booted */
static FILE *g_snmp = NULL;
static FILE *g_netstat = NULL;
#endif /* OS_LINUX */

/*
 * diag - print stderr message.
 *
 * This subroutine prints an error message, possibly including the meaning
 * of errno.
 */
static void
diag(int use_errno, char *format, ...)
{
	va_list ap;
	char *error_str;

	(void) fprintf(stderr, "%s: ", g_progname);
	if (use_errno) {
		error_str = strerror(errno);
		if (! error_str)
			error_str = strerror(0);
	}
	va_start(ap, format);
	(void) vfprintf(stderr, format, ap);
	va_end(ap);
	if (use_errno)
		(void) fprintf(stderr, ": %s\n", error_str);
	else
		(void) fputc('\n', stderr);
}

#define	die(...) \
do { \
	diag(__VA_ARGS__);			\
	exit(2);				\
} while (0)

/*
 * usage - print a usage message and exit.
 */
static void
usage(void)
{
	(void) fprintf(stderr,
	    "USAGE: nicstat [-hvnsxpztualMU] [-i int[,int...]]\n   "
#ifdef OS_LINUX
	    "[-S int:mbps[,int:mbps...]] "
#endif
	    "[interval [count]]\n"
	    "\n"
	    "         -h                 # help\n"
	    "         -v                 # show version (" NICSTAT_VERSION ")\n"
	    "         -i interface       # track interface only\n"
	    "         -n                 # show non-local interfaces only"
					" (exclude lo0)\n"
	    "         -s                 # summary output\n"
	    "         -x                 # extended output\n"
	    "         -p                 # parseable output\n"
	    "         -z                 # skip zero value lines\n"
	    "         -t                 # show TCP statistics\n"
	    "         -u                 # show UDP statistics\n"
	    "         -a                 # equivalent to \"-x -u -t\"\n"
	    "         -l                 # list interface(s)\n"
	    "         -M                 # output in Mbits/sec\n"
	    "         -U                 # separate %%rUtil and %%wUtil\n"
#ifdef OS_LINUX
	    "         -S int:mbps[fd|hd] # tell nicstat the interface\n"
	    "                            # speed (Mbits/sec) and duplex\n"
#endif
	    "    eg,\n");
	(void) fprintf(stderr,
	    "       nicstat              # print summary since boot only\n"
	    "       nicstat 1            # print every 1 second\n"
	    "       nicstat 1 5          # print 5 times only\n"
	    "       nicstat -z 1         # print every 1 second, skip zero"
					" lines\n"
	    "       nicstat -i hme0 1    # print hme0 only every 1 second\n");
	exit(1);
}

/*
 * new_string - simply strdup(3), but terminate on failure
 */
static char *
new_string(char *s)
{
	char *new;

	new = strdup(s);
	if (! new)
		die(1, "strdup", g_progname);
	return (new);
}

/*
 * allocate() - calloc(3) - for zeroing, plus error handling
 */
static inline void *
allocate(size_t bytes)
{
	void *p;

	p = calloc(1, bytes);
	if (p == NULL)
		die(1, "calloc");
	return (p);
}

/*
 * Return floating difference in timevals
 */
static double
tv_diff(struct timeval *new, struct timeval *old)
{
	double new_d, old_d;

	new_d = (double)new->tv_sec;
	new_d += new->tv_usec / 1000000.0;
	old_d = (double)old->tv_sec;
	old_d += old->tv_usec / 1000000.0;
	return (new_d - old_d);
}

/*
 * if_is_ignored - return true if interface is to be ignored
 */
static int
if_is_ignored(char *if_name)
{
	char **p;

	if (! g_someif)
		return (B_FALSE);
	for (p = g_tracked; *p; p++)
		if (streql(if_name, *p))
			return (B_FALSE);
	return (B_TRUE);
}

#ifdef OS_SOLARIS
/*
 * Check interface list to see if an interface is in it
 */
static int
interface_in_list(char *interface, nicdata_t *nicp)
{
	while (nicp) {
		if (streql(interface, nicp->name))
			return (B_TRUE);
		nicp = nicp->next;
	}
	return (B_FALSE);
}
#endif /* OS_SOLARIS */

#ifdef OS_SOLARIS
/*
 * reclaim_nicdata - reclaim's a struct nicdata * from our global list
 *
 * Return a struct nicdata pointer; if it is found in the global list; and
 * also remove it from the list (we are in the process of re-building the
 * list).  Modifies g_nicdatap.
 */
static struct nicdata *
reclaim_nicdata(char *if_name)
{
	struct nicdata *matchp, *prevp;

	prevp = NULL;
	for (matchp = g_nicdatap; matchp; matchp = matchp->next) {
		if (streql(matchp->name, if_name)) {
			/* Got a match */
			if (prevp)
				/* Splice head of list to tail of list */
				prevp->next = matchp->next;
			else
				/* We are at the head */
				g_nicdatap = matchp->next;
			/* Disassociate match with the tail of the list */
			matchp->next = NULL;
			return (matchp);
		}
		prevp = matchp;
	}
	return (NULL);
}
#endif /* OS_SOLARIS */

#ifdef OS_SOLARIS
/*
 * fetch64 - return a uint64_t value from kstat.
 *
 * The arguments are a kstat pointer, the value name,
 * and a default value in case the lookup fails.
 */
static uint64_t
fetch64(kstat_t *ksp, char *value64, uint64_t def)
{
	kstat_named_t *knp;	/* Kstat named pointer */

	/* try a lookup and return */
	if ((knp = kstat_data_lookup(ksp, value64)) != NULL)
		/* Rely on C type conversion to promote smaller size values */
		switch (knp->data_type) {
		case KSTAT_DATA_INT32:
			return (knp->value.i32);
			/*NOTREACHED*/
		case KSTAT_DATA_UINT32:
			return (knp->value.ui32);
			/*NOTREACHED*/
		case KSTAT_DATA_INT64:
			return (knp->value.i64);
			/*NOTREACHED*/
		case KSTAT_DATA_UINT64:
			return (knp->value.ui64);
			/*NOTREACHED*/
		}
	return (def);
}
#endif /* OS_SOLARIS */

#ifdef OS_SOLARIS
/*
 * fetch32 - return a uint32_t value from kstat.
 *
 * The arguments are a kstat pointer, the value name,
 * and a default value in case the lookup fails.
 */
static uint32_t
fetch32(kstat_t *ksp, char *value, uint32_t def)
{
	kstat_named_t *knp;	/* Kstat named pointer */

	/* try a lookup and return */
	if ((knp = kstat_data_lookup(ksp, value)) != NULL)
		return (knp->value.ui32);
	return (def);
}
#endif /* OS_SOLARIS */

#ifdef OS_SOLARIS
/*
 * fetch6432 - return a uint64_t or a uint32_t value from kstat.
 *
 * The arguments are a kstat pointer, a potential ui64 value name,
 * a potential ui32 value name, and a default value in case both
 * lookup fails. The ui64 value is attempted first.
 */
static uint64_t
fetch6432(kstat_t *ksp, char *value64, char *value, uint64_t def)
{
	kstat_named_t *knp;	/* Kstat named pointer */

	/* try lookups and return */
	if ((knp = kstat_data_lookup(ksp, value64)) != NULL)
		return (knp->value.ui64);
	if ((knp = kstat_data_lookup(ksp, value)) != NULL)
		return (knp->value.ui32);
	return (def);
}
#endif /* OS_SOLARIS */

#ifdef OS_SOLARIS
/*
 * fetch_nocanput - return nocanput value, whose name(s) are driver-dependent.
 *
 * Most drivers have a kstat "nocanput", but the ce driver
 * at least has "rx_nocanput" and "tx_nocanput"
 */
static uint32_t
fetch_nocanput(kstat_t *ksp, uint32_t def)
{
	kstat_named_t *knp;	/* Kstat named pointer */
	uint32_t sum;

	/* These should go in order of decreasing prevalence */
	if ((knp = kstat_data_lookup(ksp, "norcvbuf")) != NULL)
		return (knp->value.ui32);
	if ((knp = kstat_data_lookup(ksp, "nocanput")) != NULL)
		return (knp->value.ui32);
	if ((knp = kstat_data_lookup(ksp, "rx_nocanput")) != NULL) {
		sum = knp->value.ui32;
		if ((knp = kstat_data_lookup(ksp, "tx_nocanput"))
		    != NULL) {
			sum += knp->value.ui32;
			return (sum);
		}
	}
	return (def);
}
#endif /* OS_SOLARIS */

#ifdef OS_SOLARIS
/*
 * fetch_boot_time - return the boot time in secs.
 *
 * This takes a kstat control pointer and looks up the boot time
 * from unix:0:system_misc:boot:time. If found, this is returned,
 * else 0.
 */
static time_t
fetch_boot_time()
{
	kstat_t *ksp;			/* Kstat struct pointer */
	kstat_named_t *knp;		/* Kstat named pointer */
	static time_t boot_time = 0;	/* Cache it if we can */

	if (boot_time != 0)
		return (boot_time);
	if ((ksp = kstat_lookup(g_kc, "unix", 0, "system_misc")) == NULL)
		die(1, "kstat_lookup: unix:0:system_misc");
	if ((kstat_read(g_kc, ksp, NULL) != -1) &&
	    ((knp = kstat_data_lookup(ksp, "boot_time")) != NULL))
		/* summary since boot */
		boot_time = knp->value.ui32;
	/* This will be zero if kstat_data_lookup() failed */
	return (boot_time);
}
#endif /* OS_SOLARIS */

#ifdef OS_LINUX
/*
 * fetch_boot_time - return the boot time in secs.
 *
 * Gets the boot time from /proc.
 */
static unsigned long
fetch_boot_time()
{
	char buf[64];
	int uptime_fd, bufsiz, scanned;
	unsigned long uptime;

	uptime_fd = open(PROC_UPTIME, O_RDONLY, 0);
	if (uptime_fd < 0)
		die(1, "error opening %s for read", PROC_UPTIME);
	bufsiz = read(uptime_fd, buf, sizeof (buf) - 1);
	if (bufsiz < 0)
		die(1, "read: %s", PROC_UPTIME);
	buf[bufsiz] = '\0';
	scanned = sscanf(buf, "%lu.", &uptime);
	if (scanned != 1)
		die(0, "cannot get uptime from %s", PROC_UPTIME);
	return (time(0) - uptime);
}
#endif /* OS_LINUX */

#ifdef OS_SOLARIS
static if_list_t *g_getif_list = NULL;	/* Used by the lifc & dladm routines */

static if_list_t *
get_if_list_lifc(if_list_t *p)
{
	if_list_t *newp, *headp;
	struct lifnum if_num;		/* Includes # of if's */
	struct lifconf if_conf;		/* Includes ptr to list of names */

	static struct ifreq *current_lif = (struct ifreq *)NULL;
	struct lifreq *if_reqp, req;
	int lif_size, lif_count, i;

	headp = p;

	/* Get number of interfaces on system */
	if_num.lifn_family = AF_UNSPEC;
	if_num.lifn_flags = LIFC_NOXMIT | LIFC_ALLZONES | LIFC_UNDER_IPMP
		| LIFC_ENABLED;
	if (ioctl(g_sock, SIOCGLIFNUM, &if_num) < 0)
		die(1, "ioctl(IFNUM)");

	/* Allocate my struct ifreq array buffer */
	lif_size = (if_num.lifn_count + 1) * sizeof (struct lifreq);
	current_lif = realloc(current_lif, lif_size);
	if (! current_lif)
		die(1, "realloc");

	/* Get the current interface list via the ioctl() */
	if_conf.lifc_family = AF_UNSPEC;
	if_conf.lifc_flags = if_num.lifn_flags;
	if_conf.lifc_len = lif_size;
	if_conf.lifc_buf = (caddr_t)current_lif;
	if (ioctl(g_sock, SIOCGLIFCONF, &if_conf) < 0)
		die(1, "ioctl(IFCONF)");
	lif_size = if_conf.lifc_len;
	lif_count = if_conf.lifc_len / sizeof (struct lifreq);

	/*
	 * Loop through entries in lifc_req, making a list of interfaces
	 */
	if_reqp = if_conf.lifc_req;
	(void) memset((void *) &req, 0, sizeof (struct lifreq));
	for (i = lif_count; i; i--, if_reqp++) {
		/* Skip virtual IP's */
		if (strchr(if_reqp->lifr_name, ':'))
			continue;
		(void) strlcpy(req.lifr_name, if_reqp->lifr_name, LIFNAMSIZ);

		/*
		 * Skip interface if "-i" was used, and it is not
		 * a matching interface
		 */
		if (if_is_ignored(if_reqp->lifr_name))
			continue;

		/* Add to list */
		if (p->name) {
			/* Need new tail */
			newp = allocate(sizeof (if_list_t));
			p->next = newp;
			p = newp;
		}
		p->name = new_string(if_reqp->lifr_name);
	}
	return (headp);
}
#endif	/* OS_SOLARIS */

#ifdef USE_DLADM
/*
 * dladm_callback - Function called by dladm_walk_datalink_id() for each
 * link.
 */
/* ARGSUSED */
static int
dladm_callback(dladm_handle_t dh, datalink_id_t linkid, void *arg)
{
	dladm_status_t		status;
	char			link[MAXLINKNAMELEN];
	datalink_class_t	class;
	uint_t			mtu;
	uint32_t		flags;
	struct if_list		*p, *newp;

	if ((status = dladm_datalink_id2info(g_handle, linkid, &flags, &class,
	    NULL, link, sizeof (link))) != DLADM_STATUS_OK) {
		return (status);
	}

	/*
	 * Skip interface if "-i" was used, and it is not
	 * a matching interface
	 */
	if (if_is_ignored(link))
		return (DLADM_WALK_CONTINUE);

	p = g_getif_list;
	if (p->name) {
		/* Need new tail */
		newp = allocate(sizeof (struct if_list));
		p->next = newp;
		p = newp;
		g_getif_list = newp;
	}
	p->name = new_string(link);
	return (DLADM_WALK_CONTINUE);
}

/*
 * Get the current list of interfaces
 */
static struct if_list *
get_if_list_dl(if_list_t *p)
{
	uint32_t flags = DLADM_OPT_ACTIVE;

	/* Start with "lo0" unless it is ignored */
	if (! g_nonlocal && (! if_is_ignored("lo0"))) {
		p->name = new_string("lo0");
		p->next = (struct if_list *)NULL;
	}

	/* dladm_callback() will append entries to g_getif_list */
	g_getif_list = p;
	(void) dladm_walk_datalink_id(dladm_callback, g_handle,
	    NULL, DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE,
	    flags);

	return (g_getif_list = p);
}
#endif	/* USE_DLADM */

#ifdef OS_SOLARIS
/*
 * Get the list from kstats, looking for one of:
 *
 *	Class	4-tuple
 *	=====	=======
 *	net	link::<ifname>:link_state
 *	net	<drv>:<inst>:mac:link_state
 *	mac	<ifname>::<ifname>/xx:link_state
 *
 * with a value of "1".
 *
 * This is only useful on S10 or newer; where interfaces given
 * exclusively to non-global zones may not be visible via
 * get_if_list_lifc(); and where USE_DLADM is not available.
 */
static if_list_t *
get_if_list_kstat(if_list_t *p)
{
	if_list_t *newp, *headp;
	kstat_t *ksp;
	kstat_named_t *knp;
	char ifname[MAXLINKNAMELEN];
	char *namep;

	headp = p;

	/* Start with "lo0" unless it is ignored */
	if (! g_nonlocal && (! if_is_ignored("lo0"))) {
		p->name = new_string("lo0");
		p->next = (struct if_list *)NULL;
	}

	for (ksp = g_kc->kc_chain; ksp != NULL; ksp = ksp->ks_next) {
		if (ksp->ks_type != KSTAT_TYPE_NAMED)
			continue;
		if (streql(ksp->ks_class, "net")) {
			if (streql(ksp->ks_module, "link")) {
				namep = ksp->ks_name;
				goto lookup;
			}
			if (streql(ksp->ks_name, "mac")) {
				(void) sprintf(ifname, "%s%u", ksp->ks_module,
					ksp->ks_instance);
				namep = ifname;
				goto lookup;
			}
			continue;
		}
		if (streql(ksp->ks_class, "mac")) {
			namep = ksp->ks_module;
			goto lookup;
		}
		continue;

	lookup:
		if (kstat_read(g_kc, ksp, NULL) < 0)
			die(1, "kstat_read");
		if (! (knp = kstat_data_lookup(ksp, "link_state")))
			continue;
		/* We have a "link_state" */
		if (knp->data_type != KSTAT_DATA_UINT32)
			continue;
		if (knp->value.ui32 != 1)
			continue;

		/* We have a value of 1 - link is UP */
		if (if_is_ignored(ifname))
			continue;

		/* Add to list */
		if (p->name) {
			/* Need new tail */
			newp = allocate(sizeof (if_list_t));
			p->next = newp;
			p = newp;
		}
		p->name = new_string(namep);
	}
	return (headp);
}
#endif /* OS_SOLARIS */

#ifdef OS_SOLARIS
static if_list_t *
get_if_list()
{
	/* Free g_getif_list if needed */
	if (g_getif_list) {
		struct if_list *p, *next;

		for (p = g_getif_list; p; ) {
			next = p->next;
			if (p->name)
				free(p->name);
			free(p);
			p = next;
		}
	}

	/* Allocate new g_getif_list */
	g_getif_list = allocate(sizeof (if_list_t));

	if (g_opt_k)
		return (get_if_list_kstat(g_getif_list));
#ifdef USE_DLADM
	if (g_use_dladm)
		return (get_if_list_dl(g_getif_list));
#endif
	return (get_if_list_lifc(g_getif_list));
}
#endif /* OS_SOLARIS */

#ifdef OS_SOLARIS
static LIFR_FLAGS_TYPE
get_lif_flags(char *if_name)
{
	struct lifreq req;

	(void) strlcpy(req.lifr_name, if_name, LIFNAMSIZ);
	if (ioctl(g_sock, SIOCGLIFINDEX, &req) == -1) {
		return (0);
	}
	if (ioctl(g_sock, SIOCGLIFFLAGS, &req) == -1) {
		return (0);
	}
	return (req.lifr_flags);
}

/*
 * split_ifname()
 *
 * Splits interface names like "bge0", "e1000g7001" into driver/module name
 * and instance number.  The instance number is the largest set of trailing
 * digits.
 */
static int
split_ifname(char *if_name, char *drv, uint32_t *instance)
{
	char *p;
	int n, m;

	n = 0;
	for (p = if_name; *p; p++)
		n++;
	if (n <= 1)
		return (B_FALSE);
	m = n;
	for (p--; isdigit(*p); p--)
		n--;
	if (m == n || n == 0)
		return (B_FALSE);
	(void) strncpy(drv, if_name, n);
	drv[n] = '\0';
	*instance = (uint32_t)atol(++p);
	return (B_TRUE);
}

/*
 * OUTPUTS
 *	nic->ls_ksp
 *	nic->op_ksp
 *	nic->flags (NIC_KS_UP bit)
 */
static nicdata_t *
discover_kstats(char *if_name, nicdata_t *nic)
{
	uint32_t if_instance;
	kstat_t *ksp;
	kstat_named_t *knp;
	int ks_link_state;	/* :::link_state */
	int ks_opackets;	/* :::opackets */
	int ks_link_module;	/* link::: */
	int ks_drv_module;	/* <drv>::: */
	int ks_ifname_module;	/* <ifname>::: */
	uint32_t n;
	uint32_t ttype;
	char if_drv[MAXLINKNAMELEN];

	if (! split_ifname(if_name, if_drv, &if_instance))
		die(0, "%s: %s: invalid interface name\n", g_progname,
			if_name);

	nic->ls_ksp = NULL;
	nic->op_ksp = NULL;
	for (ksp = g_kc->kc_chain; ksp != NULL; ksp = ksp->ks_next) {
		if (ksp->ks_type != KSTAT_TYPE_NAMED)
			continue;
		if (strcmp(ksp->ks_class, "net") != 0)
			continue;

		ks_link_module = ks_drv_module = ks_ifname_module = B_FALSE;
		if (streql(ksp->ks_module, "link"))
			ks_link_module = B_TRUE;
		else if (streql(ksp->ks_module, if_drv) &&
		    (ksp->ks_instance == if_instance))
			ks_drv_module = B_TRUE;
		else if (streql(ksp->ks_module, if_name))
			ks_ifname_module = B_TRUE;
		else
			continue;

		/* We have [link:::], [<drv>:<instance>::] or [<ifname>:::] */

		(void) kstat_read(g_kc, ksp, NULL);
		knp = KSTAT_NAMED_PTR(ksp);
		for (n = 0; n < ksp->ks_ndata; n++, knp++) {
			ks_link_state = B_FALSE;
			ks_opackets = B_FALSE;
			if (streql(knp->name, "link_state"))
				ks_link_state = B_TRUE;
			else if (streql(knp->name, "opackets"))
				ks_opackets = B_TRUE;
			else
				continue;

			/* knp is one of our desired statistics */
			if (ks_link_module) {
				if (streql(ksp->ks_name, if_name)) {
					ttype = KS_LINK;
					if (ks_link_state)
						goto set_ls_kstat;
					else
						goto set_op_kstat;
				}
				continue;
			}

			if (ks_drv_module &&
			    (ksp->ks_instance == if_instance)) {
				if (streql(ksp->ks_name, "mac")) {
					ttype = KS_DRV_MAC;
					if (ks_link_state)
						goto set_ls_kstat;
					else
						goto set_op_kstat;
				} else if (streql(ksp->ks_name, if_name)) {
					ttype = KS_DIN;
					if (ks_link_state)
						goto set_ls_kstat;
					else
						goto set_op_kstat;
				} else {
					ttype = KS_DRV;
					if (ks_link_state)
						goto set_ls_kstat;
					else
						goto set_op_kstat;
				}
			}

			if (ks_ifname_module) {
				ttype = KS_NAME;
				if (ks_link_state)
					goto set_ls_kstat;
				else
					goto set_op_kstat;
			}

		set_ls_kstat:
			if (ttype > nic->ls_types) {
				nic->ls_ksp = ksp;
				if (knp->value.ui32 == 1)
					nic->flags |= NIC_KS_UP;
				nic->flags |= (NIC_LK_UPDATED |
					NIC_KU_UPDATED);
			}
			nic->ls_types |= ttype;
			continue;

		set_op_kstat:
			if (ttype > nic->op_types) {
				nic->op_ksp = ksp;
				nic->flags |= NIC_OK_UPDATED;
			}
			nic->op_types |= ttype;
			continue;
		}
	}
	if (nic->ls_ksp == NULL) {
		nic->flags |= NIC_NO_LINKSTATE;
		if (nic->op_ksp == NULL)
			nic->flags |= NIC_NO_KSTATS;
	} else if (nic->ls_ksp == nic->op_ksp)
		nic->flags |= NIC_LK_IS_OK;
	return (nic);
}

static kstat_t *
fetch_ksp(char *module, uint32_t instance, char *name)
{
	kstat_t *ksp;

	ksp = kstat_lookup(g_kc, module, instance, name);
	if (! ksp)
		die(1, "kstat_lookup (\"%s:%u:%s\")", module, instance, name);
	if (kstat_read(g_kc, ksp, NULL) == -1)
		die(1, "kstat_read (\"%s:%u:%s\")", module, instance, name);
	return (ksp);
}

static void
update_ksp_by_type(kstat_t **kspp, uint32_t types, char *name)
{
	char drv[MAXLINKNAMELEN];
	uint32_t instance;

	if (*kspp && (! g_new_kstat_chain))
		return;

	/* Need to get new ksp */
	if (types & KS_LINK) {
		*kspp = fetch_ksp("link", 0, name);
		return;
	}
	(void) split_ifname(name, drv, &instance);
	if (types & KS_DRV_MAC) {
		*kspp = fetch_ksp(drv, instance, "mac");
		return;
	}
	if (types & KS_DIN) {
		*kspp = fetch_ksp(drv, instance, name);
		return;
	}
	if (types & KS_DRV) {
		*kspp = fetch_ksp(drv, instance, NULL);
		return;
	}
	if (types & KS_NAME) {
		*kspp = fetch_ksp(name, -1, NULL);
		return;
	}
	die(0, "types = 0x%08x", types);
}

static void
update_linkstate(nicdata_t *nicp)
{
	kstat_named_t *knp;

	knp = kstat_data_lookup(nicp->ls_ksp, "link_state");
	if (! knp)
		die(1, "kstat_data_lookup(\"link_state\")");
	if (knp->value.ui32 == 1)
		nicp->flags |= NIC_KS_UP;
	else
		nicp->flags &= ~NIC_KS_UP;
	nicp->flags |= NIC_KU_UPDATED;
}

/*
 * update_nicdata_list - update global linked list of nic data
 *
 *	get current list of nics
 *	foreach (current nic)
 *		reclaim nicdata from g_nicdatap
 *		if (ioctl available)
 *			update NIC_IF_UP
 *		else
 *			update NIC_KS_UP
 *		if (iface is up)
 *			if (iface is new || kstat chain updated)
 *				update kstat pointers
 *		add current nic to new list
 *	free any remaining on old list
 */
static void
update_nicdata_list()
{
	struct nicdata *nicp, *new_nicdatap, *old_nicdatap;
	struct nicdata *new_headp, *new_tailp;
	struct if_list *if_listp, *ifp;
	LIFR_FLAGS_TYPE if_flags;
	uint32_t new_nics;

	if_listp = get_if_list();

	new_headp = NULL;
	new_tailp = NULL;
	new_nics = 0;
	/* Outer loop - if_listp */
	for (ifp = if_listp; ifp && ifp->name; ifp = ifp->next) {
		if (interface_in_list(ifp->name, new_headp))
			/* Seen it */
			continue;
		nicp = reclaim_nicdata(ifp->name);
		if (! nicp) {
			/* Was not previously known */
			nicp = allocate(sizeof (nicdata_t));
			nicp->name = new_string(ifp->name);
			if_flags = get_lif_flags(ifp->name);
			if (if_flags == 0) {
				nicp->flags |= NIC_NO_GLIFFLAGS;
			} else {
				if (if_flags & IFF_UP)
					nicp->flags |= NIC_LIF_UP;
				nicp->flags |= NIC_LU_UPDATED;
				if (if_flags & IFF_LOOPBACK)
					nicp->flags |= NIC_LOOPBACK;
			}
			if (! discover_kstats(ifp->name, nicp))
				nicp->flags |= NIC_NO_KSTATS;
		} else {
			/* Assume state is now out of date */
			nicp->flags &= ~(NIC_UPDATED_FLAGS);
		}

		/* Add to new_nicdatap */
		if (new_tailp)
			new_tailp->next = nicp;
		else
			new_headp = nicp;
		new_tailp = nicp;

		if (g_nonlocal && (nicp->flags & NIC_LOOPBACK))
			continue;

		/* Update UP/DOWN */
		if (nicp->flags & NIC_NO_GLIFFLAGS) {
			if ((nicp->flags & NIC_NO_KSTATS) ||
			    (nicp->flags & NIC_NO_LINKSTATE))
				/* We will never know */
				continue;
			else if (! (nicp->flags & NIC_LK_UPDATED)) {
				update_ksp_by_type(&(nicp->ls_ksp),
					nicp->ls_types, nicp->name);
				update_linkstate(nicp);
				nicp->flags |= (NIC_LK_UPDATED |
					NIC_KU_UPDATED);
			}
		} else {
			if (! (nicp->flags & NIC_LU_UPDATED)) {
				if_flags = get_lif_flags(ifp->name);
				if (if_flags & IFF_UP)
					nicp->flags |= NIC_LIF_UP;
				else
					nicp->flags &= ~NIC_LIF_UP;
				nicp->flags |= NIC_LU_UPDATED;
			}
		}
		if (! (nicp->flags & NIC_UP))
		    /* IF is down */
			if (! g_list)
				continue;
		new_nics++;
	}
	g_nicdata_count = new_nics;

	/* Clean up any left in the old list */
	for (new_nicdatap = g_nicdatap; new_nicdatap; ) {
		old_nicdatap = new_nicdatap;
		new_nicdatap = new_nicdatap->next;
		free(old_nicdatap->name);
		free(old_nicdatap);
	}

	/* Save the new list we just built in our global pointer */
	g_nicdatap = new_headp;
}
#endif /* OS_SOLARIS */

#ifdef OS_LINUX
/*
 * find_nicdatap - find a struct nicdata * from linked list
 *
 * We search the linked list starting from *lastp (or *headp if *lastp
 * is NULL).  All entries are searched until either:
 *
 * - matching if_name found, and we return the struct pointer
 *
 * - no match, so we initialise a new struct, add to the end of
 *   the list (or after *lastp if non-null) and return a pointer to it
 *
 * SIDE EFFECT - *lastp is always set to a pointer to the
 * matched (or newly-created) struct.  This allows an efficient
 * sequential update of the list.
 */

enum search_state {HEAD, LAST, LAST_LOOPED};

static struct nicdata *
find_nicdatap(struct nicdata **headp, struct nicdata **lastp, char *if_name)
{
	struct nicdata *prevp, *p;
	enum search_state state;

	prevp = NULL;

	if (*lastp && (*lastp)->next) {
		state = LAST;
		p = (*lastp)->next;
	} else {
		state = HEAD;
		p = *headp;
	}
	while (p) {
		/* Check for a match */
		if (streql(p->name, if_name)) {
			/* We have a match */
			*lastp = p;
			return (p);
		}
		prevp = p;
		p = p->next;
		if (p == NULL) {
			switch (state) {
			case HEAD:
			case LAST_LOOPED:
				/* Will terminate loop */
				break;
			case LAST:
				/* Start from head */
				state = LAST_LOOPED;
				p = *headp;
				break;
			}
		} else
			if (state == LAST_LOOPED &&
			    p == *lastp)
				/* No match */
				break;
	}

	/* We get here if we have no match */
	p = allocate(sizeof (struct nicdata));
	p->name = new_string(if_name);

	if (state == HEAD) {
		/* prevp will point to the last struct in the list */
		if (prevp)
			prevp->next = p;
		else
			*headp = p;
	} else {
		/* Insert new entry after **lastp */
		prevp = (*lastp)->next;
		(*lastp)->next = p;
		p->next = prevp;
	}

	*lastp = p;
	return (p);
}
#endif /* OS_LINUX */

#ifdef OS_LINUX
static int
find_interface_speed(struct nicdata *nicp)
{
	struct if_speed_list	*if_speed_list_ptr;

	if_speed_list_ptr = g_if_speed_list;

	while (if_speed_list_ptr != NULL) {
		if (streql(nicp->name, if_speed_list_ptr->name)) {
			nicp->speed = if_speed_list_ptr->speed;
			nicp->duplex = if_speed_list_ptr->duplex;
			return (B_TRUE);
		}
		if_speed_list_ptr = if_speed_list_ptr->next;
	}
	nicp->speed = 0;
	nicp->duplex = DUPLEX_UNKNOWN;
	return (B_FALSE);
}
#endif /* OS_LINUX */

#ifdef OS_SOLARIS

#define	TCP_UPDATE(field, kstat_name)	\
	g_tcp_new->field = fetch64(g_tcp_ksp, kstat_name, 0);
#define	UDP_UPDATE(field, kstat_name)	\
	g_udp_new->field = fetch64(g_udp_ksp, kstat_name, 0);

/*
 * update_stats - update stats for interfaces we are tracking
 */
static void
update_stats()
{
	struct nicdata *nicp;
	struct timeval now_tv;

	(void) gettimeofday(&now_tv, NULL);

	if (g_tcp) {
		/* Update TCP stats */
		if (g_new_kstat_chain) {
			g_tcp_ksp = kstat_lookup(g_kc, "tcp", -1, "tcp");
			if (! g_tcp_ksp)
				die(1, "kstat_lookup");
		}
		if (kstat_read(g_kc, g_tcp_ksp, NULL) < 0)
			die(1, "kstat_read");
		g_tcp_new->tv.tv_sec = now_tv.tv_sec;
		g_tcp_new->tv.tv_usec = now_tv.tv_usec;
		TCP_UPDATE(inDataInorderSegs, "inDataInorderSegs");
		TCP_UPDATE(outDataSegs, "outDataSegs");
		TCP_UPDATE(inDataInorderBytes, "inDataInorderBytes");
		TCP_UPDATE(inDataUnorderSegs, "inDataUnorderSegs");
		TCP_UPDATE(inDataUnorderBytes, "inDataUnorderBytes");
		TCP_UPDATE(outDataBytes, "outDataBytes");
		TCP_UPDATE(estabResets, "estabResets");
		TCP_UPDATE(outRsts, "outRsts");
		TCP_UPDATE(attemptFails, "attemptFails");
		TCP_UPDATE(retransBytes, "retransBytes");
		TCP_UPDATE(passiveOpens, "passiveOpens");
		TCP_UPDATE(activeOpens, "activeOpens");
		TCP_UPDATE(halfOpenDrop, "halfOpenDrop");
		TCP_UPDATE(listenDrop, "listenDrop");
		TCP_UPDATE(listenDropQ0, "listenDropQ0");
	}
	if (g_udp) {
		/* Update UDP stats */
		if (g_new_kstat_chain) {
			g_udp_ksp = kstat_lookup(g_kc, "udp", -1, "udp");
			if (! g_udp_ksp)
				die(1, "kstat_lookup");
		}
		if (kstat_read(g_kc, g_udp_ksp, NULL) < 0)
			die(1, "kstat_read");
		g_udp_new->tv.tv_sec = now_tv.tv_sec;
		g_udp_new->tv.tv_usec = now_tv.tv_usec;
		UDP_UPDATE(inDatagrams, "inDatagrams");
		UDP_UPDATE(outDatagrams, "outDatagrams");
		UDP_UPDATE(inErrors, "inErrors");
		UDP_UPDATE(outErrors, "outErrors");
	}

	if (g_style == STYLE_NONE && ! g_list)
		return;

	/* Update interface stats */
	for (nicp = g_nicdatap; nicp; nicp = nicp->next) {
		if (! (nicp->flags & NIC_UP))
			/* Link is not up */
			continue;
		if (g_nonlocal && (nicp->flags & NIC_LOOPBACK))
			continue;
		if (! (nicp->flags & NIC_OK_UPDATED))
			if (kstat_read(g_kc, nicp->op_ksp, NULL) < 0)
				die(1, "kstat_read");
		/* Save network values */
		nicp->new.tv.tv_sec = now_tv.tv_sec;
		nicp->new.tv.tv_usec = now_tv.tv_usec;
		nicp->new.rbytes =
			fetch6432(nicp->op_ksp, "rbytes64", "rbytes", 0);
		nicp->new.wbytes =
			fetch6432(nicp->op_ksp, "obytes64", "obytes", 0);
		nicp->new.rpackets =
			fetch6432(nicp->op_ksp, "ipackets64", "ipackets", 0);
		nicp->new.wpackets =
			fetch6432(nicp->op_ksp, "opackets64", "opackets", 0);
		switch (g_style) {
		case STYLE_EXTENDED_PARSEABLE:
		case STYLE_EXTENDED:
			nicp->new.ierr = fetch32(nicp->op_ksp, "ierrors", 0);
			nicp->new.oerr = fetch32(nicp->op_ksp, "oerrors", 0);
			/*FALLTHROUGH*/
		case STYLE_FULL:
		case STYLE_SUMMARY:
			nicp->new.coll = fetch32(nicp->op_ksp, "collisions",
				0);
			nicp->new.nocp = fetch_nocanput(nicp->op_ksp, 0);
			nicp->new.defer = fetch32(nicp->op_ksp, "defer_xmts",
				0);
			nicp->new.sat = nicp->new.defer + nicp->new.nocp +
				nicp->new.coll;
			nicp->new.sat += fetch32(nicp->op_ksp, "noxmtbuf", 0);
			break;
		}
		nicp->speed = fetch64(nicp->op_ksp, "ifspeed", 0);
		nicp->duplex = fetch32(nicp->op_ksp, "link_duplex", 0);
	}

}
#endif /* OS_SOLARIS */

#ifdef OS_LINUX
/*
 * load_netstat() -	Reads PROC_NET_NETSTAT_PATH to get TCP stat(s)
 */

static void
load_netstat(FILE *netstat)
{
	char buf[2048];
	char *p;
	int remaining;
	long long ll[2];

	if (fseek(netstat, 0, SEEK_SET) != 0)
		die(1, "fseek: %s", PROC_NET_NETSTAT_PATH);
	remaining = 1;
	while (remaining) {
		p = fgets(buf, sizeof (buf), netstat);
		if (! p)
			break;
		if (g_tcp && strncmp("TcpExt: SyncookiesSent SyncookiesRecv "
		    "SyncookiesFailed EmbryonicRsts PruneCalled RcvPruned "
		    "OfoPruned OutOfWindowIcmps LockDroppedIcmps "
		    "ArpFilter TW TWRecycled TWKilled PAWSPassive "
		    "PAWSActive PAWSEstab DelayedACKs DelayedACKLocked "
		    "DelayedACKLost ListenOverflows ListenDrops ",
		    p, 273) == 0) {
			/* We are after field 20 and 21 */
			int n = fscanf(netstat, "TcpExt: %*d %*d %*d "
				"%*d %*d %*d %*d %*d %*d %*d "
				"%*d %*d %*d %*d %*d %*d %*d "
				"%*d %*d %lld %lld ",
				&ll[0], &ll[1]);
			if (n == 2)
				g_tcp_new->listenDrop = ll[0] + ll[1];
			remaining--;
		}
	}
}


/*
 * load_snmp() -	Reads PROC_NET_SNMP_PATH to get TCP & UDP stats
 */

static void
load_snmp(FILE *snmp)
{
	char buf[2048];
	char *p;
	int remaining;
	long long ll[14];

	/* Load TCP and/or UDP stats from /proc/net/snmp */
	if (fseek(snmp, 0, SEEK_SET) != 0)
		die(1, "fseek: %s", PROC_NET_SNMP_PATH);
	remaining = 0;
	if (g_tcp)
		remaining++;
	if (g_udp)
		remaining++;
	while (remaining) {
		p = fgets(buf, sizeof (buf), snmp);
		if (! p)
			break;
		if (g_tcp && strncmp("Tcp: RtoAlgorithm RtoMin RtoMax MaxConn "
				"ActiveOpens PassiveOpens AttemptFails "
				"EstabResets CurrEstab InSegs OutSegs "
				"RetransSegs InErrs OutRsts", p, 141) == 0) {
			int n;
			n = fscanf(snmp, "Tcp: %lld %lld %lld %lld "
			    "%lld %lld %lld %lld %lld %lld "
			    "%lld %lld %lld %lld\n",
			    &ll[0], &ll[1], &ll[2], &ll[3],
			    &ll[4], &ll[5], &ll[6], &ll[7],
			    &ll[8], &ll[9], &ll[10], &ll[11],
			    &ll[12], &ll[13]);
			if (n == 14) {
				g_tcp_new->inDataInorderSegs = ll[9];
				g_tcp_new->outDataSegs = ll[10];
				g_tcp_new->estabResets = ll[7];
				g_tcp_new->outRsts = ll[13];
				g_tcp_new->attemptFails = ll[6];
				/* Note: bytes */
				g_tcp_new->retransBytes = ll[11];
				g_tcp_new->passiveOpens = ll[5];
				g_tcp_new->activeOpens = ll[4];
			}
			remaining--;
		} else if (g_udp && strncmp("Udp: InDatagrams NoPorts "
				"InErrors OutDatagrams RcvbufErrors "
				"SndbufErrors\n", p, 72) == 0) {
			int n;
			n = fscanf(snmp, "Udp: %lld %lld %lld %lld "
			    "%lld %lld\n",
			    &ll[0], &ll[1], &ll[2], &ll[3],
			    &ll[4], &ll[5]);
			if (n == 6) {
				g_udp_new->inDatagrams = ll[0];
				g_udp_new->outDatagrams = ll[3];
				g_udp_new->inErrors = ll[2]; /* + ll[4]? */
				g_udp_new->outErrors = ll[5];
			}
			remaining--;
		}
	}
}

#endif /* OS_LINUX */

#ifdef OS_LINUX
static void
get_speed_duplex(nicdata_t *nicp)
{
	struct ifreq ifr;
	struct ethtool_cmd edata;
	int status;

	if (find_interface_speed(nicp))
		return;

	if (nicp->flags & NIC_NO_GSET) {
		if (nicp->speed > 0)
			/* Already got something */
			return;
		if (nicp->flags & NIC_NO_SFLAG)
			return;
		if (! find_interface_speed(nicp))
			nicp->flags |= NIC_NO_SFLAG;
		return;
	}

	/* Try SIOCETHTOOL */
	strncpy(ifr.ifr_name, nicp->name, sizeof (ifr.ifr_name));
	ifr.ifr_data = (void *) &edata;
	edata.cmd = ETHTOOL_GSET;
	status = ioctl(g_sock, SIOCETHTOOL, &ifr);
	if (status < 0) {
		nicp->flags |= NIC_NO_GSET;
		get_speed_duplex(nicp);
		return;
	}
	nicp->speed = (long long) edata.speed * 1000000;
	nicp->duplex = edata.duplex;
}
#endif /* OS_LINUX */

#ifdef OS_LINUX

/*
 * update_stats - update stats for interfaces we are tracking
 */
static void
update_stats(int net_dev)
{
	struct nicdata *nicp, *lastp;
	struct timeval now_tv;
	static int validated_format = 0;
	static char proc_net_buffer[PROC_NET_BUFSIZ];
	char *bufp;
	int bufsiz, buf_remain, ret, n, skip_to_newline;
	unsigned long long ll[16];
	char if_name[32];
	int loopback;

	/*
	 * Load PROC_NET_DEV
	 */
	if (lseek(net_dev, 0, SEEK_SET) != 0)
		die(1, "lseek: %s", PROC_NET_DEV_PATH);
	bufsiz = read(net_dev, (void *) proc_net_buffer,
	    sizeof (proc_net_buffer));
	if (bufsiz < 0)
		die(1, "read: %s", PROC_NET_DEV_PATH);
	else if (bufsiz < 200)
		die(0, "%s: invalid format\n", PROC_NET_DEV_PATH);

	/*
	 * Validate if we have not previously done so
	 */
	if (! validated_format) {
		if (strncmp(proc_net_buffer,
		    "Inter-|   Receive                                   "
		    "             |  Transmit\n"
		    " face |bytes    packets errs drop fifo frame compressed"
		    " multicast|bytes    packets errs drop fifo colls carrier"
		    " compressed\n", 200) != 0)
			die(0, "%s: invalid format\n",
			    PROC_NET_DEV_PATH);
		else
			validated_format++;
	}

	/* Terminate our string */
	bufp = proc_net_buffer + 200;
	buf_remain = bufsiz - 200;
	bufp[buf_remain + 1] = '\0';

	(void) gettimeofday(&now_tv, NULL);

	skip_to_newline = 0;
	g_nicdata_count = 0;
	lastp = NULL;
	while (*bufp) {
		if (skip_to_newline) {
			/* Need to skip over previous data */
			for (; *bufp; bufp++)
				if (*bufp == '\n') {
					bufp++;
					break;
			}
			if (! *bufp)
				break;
		}
		skip_to_newline = 1;

		/* Get the interface name */
		while (*bufp == ' ')
			bufp++;
		/* Check the format */
		n = strcspn(bufp, ":");
		if (n >= sizeof (if_name))
			die(0, "%s: interface name too long",
				PROC_NET_DEV_PATH);
		(void) strncpy(if_name, bufp, n);
		if_name[n] = '\0';
		/*
		 * Skip interface if not specifically interested in it
		 */
		if (if_is_ignored(if_name)) {
			continue;
		}
		/*
		 * If g_nonlocal, skip "lo"
		 */
		loopback = streql("lo", if_name);
		if (g_nonlocal && loopback)
			continue;

		/* Scan in values */
		bufp += n + 1;
		ret = sscanf(bufp, "%llu %llu %llu %llu %llu %llu %llu"
			" %llu %llu %llu %llu %llu %llu %llu %llu %llu\n",
			&ll[0], &ll[1], &ll[2], &ll[3], &ll[4], &ll[5],
			&ll[6], &ll[7], &ll[8], &ll[9], &ll[10], &ll[11],
			&ll[12], &ll[13], &ll[14], &ll[15]);
		if (ret != 16)
			die(0, "%s: invalid format", PROC_NET_DEV_PATH);
		/*
		 * Skip interface if it has never seen a packet
		 */
		if (ll[1] == 0 && ll[9] == 0)
			continue;

		/*
		 * OK, we'll keep this one
		 */
		g_nicdata_count++;
		nicp = find_nicdatap(&g_nicdatap, &lastp, if_name);
		nicp->new.tv.tv_sec = now_tv.tv_sec;
		nicp->new.tv.tv_usec = now_tv.tv_usec;
		nicp->new.rbytes = ll[0];
		nicp->new.rpackets = ll[1];
		nicp->new.wbytes = ll[8];
		nicp->new.wpackets = ll[9];
		nicp->new.sat = ll[2];
		nicp->new.sat += ll[3];
		nicp->new.sat += ll[11];
		nicp->new.sat += ll[12];
		nicp->new.sat += ll[13];
		nicp->new.sat += ll[14];
		if (g_opt_x) {
			nicp->new.ierr = ll[2];
			nicp->new.oerr = ll[10];
			nicp->new.coll = ll[13];
		}
		if (loopback)
			nicp->flags |= NIC_LOOPBACK;
		get_speed_duplex(nicp);
		nicp->report = 1;
	}
	if (g_tcp || g_udp)
		load_snmp(g_snmp);
	if (g_tcp) {
		g_tcp_new->tv = now_tv;
		load_netstat(g_netstat);
	}
	if (g_udp)
		g_udp_new->tv = now_tv;
}
#endif /* OS_LINUX */

/*
 * precision -	figure an optimal floating precision for a printf()
 */
static inline int
precision(double value)
{
	if (value < 100)
		return (2);
	else if (value < 100000)
		return (1);
	return (0);
}

static inline int
precision4(double value)
{
	if (value < 10)
		return (2);
	else if (value < 100)
		return (1);
	return (0);
}

static inline int
precision_p(double value)
{
	if (value < 100)
		if (value < 10)
			return (3);
		else
			return (2);
	else if (value < 10000)
		return (1);
	return (0);
}

static char g_timestr[16];

static void
update_timestr(time_t *tptr)
{
	struct tm *tm;
	time_t t;

	if (tptr)
		t = *tptr;
	else
		t = time(NULL);
	tm = localtime(&t);
	(void) strftime(g_timestr, sizeof (g_timestr), "%H:%M:%S", tm);
}

#define	TCPSTAT(field)	(g_tcp_new->field - g_tcp_old->field)
#define	UDPSTAT(field)	(g_udp_new->field - g_udp_old->field)

static void
print_tcp()
{
	double tdiff;
	uint64_t resets;
	double retrans_rate;
	uint64_t outbytes;
	double inkb, outkb, inseg, outseg, reset, attfail, inconn,
		outconn, drops;
	tcpstats_t *tsp;

	if (g_tcp_old->tv.tv_sec == 0)
		/* Not initialised */
		g_tcp_old->tv.tv_sec = fetch_boot_time();
		/* g_tcp_old->tv.tv_sec = g_tcp_new->tv.tv_sec - 100; */
	tdiff = tv_diff(&g_tcp_new->tv, &g_tcp_old->tv);
	if (tdiff == 0)
		tdiff = 1;

	/* Header */
	update_timestr(&(g_tcp_new->tv.tv_sec));
	if (! g_opt_p)
		(void) printf("%8s %7s %7s %7s %7s %5s %5s %4s %5s %5s %5s\n",
			g_timestr, "InKB", "OutKB", "InSeg", "OutSeg",
			"Reset", "AttF", "%ReTX", "InConn", "OutCon", "Drops");

	resets = (TCPSTAT(estabResets) + TCPSTAT(outRsts));
	outbytes = TCPSTAT(outDataBytes);

	inkb = (TCPSTAT(inDataInorderBytes) + TCPSTAT(inDataUnorderBytes)) /
		1024.0 / tdiff;
	outkb = outbytes / 1024.0 / tdiff;
	inseg = (TCPSTAT(inDataInorderSegs) + TCPSTAT(inDataUnorderSegs)) /
		tdiff;
	outseg = TCPSTAT(outDataSegs) / tdiff;
	reset = resets / tdiff;
	attfail = TCPSTAT(attemptFails) / tdiff;
	if (outbytes == 0)
		retrans_rate = 0.0;
	else
		retrans_rate = TCPSTAT(retransBytes) * 100.0 /
			(double)outbytes;
	inconn = TCPSTAT(passiveOpens) / tdiff;
	outconn = TCPSTAT(activeOpens) / tdiff;
	drops = (TCPSTAT(halfOpenDrop) + TCPSTAT(listenDrop) +
		TCPSTAT(listenDropQ0)) / tdiff;

#ifdef NOTDEBUG
	double ods_rate = (g_tcp_new->outDataSegs - g_tcp_old->outDataSegs) /
		tdiff;
	(void) printf("old->outDataSegs = %llu, new->outDataSegs = %llu, "
		"  tdiff = %7.2f; rate = %7.2f\n",
		g_tcp_old->outDataSegs, g_tcp_new->outDataSegs,
		tdiff, ods_rate);
#endif /* DEBUG */
	if (g_opt_p)
		(void) printf("%ld:TCP:%.*f:%.*f:%.*f:%.*f:%.*f:%.*f:"
			"%.*f:%.*f:%.*f:%.*f\n",
			g_tcp_new->tv.tv_sec,
			precision_p(inkb), inkb,
			precision_p(outkb), outkb,
			precision_p(inseg), inseg,
			precision_p(outseg), outseg,
			precision_p(reset), reset,
			precision_p(attfail), attfail,
			precision_p(retrans_rate), retrans_rate,
			precision_p(inconn), inconn,
			precision_p(outconn), outconn,
			precision_p(drops), drops);
	else
		(void) printf("TCP      %7.*f %7.*f %7.*f %7.*f %5.*f %5.*f "
			"%4.*f %6.*f %6.*f %5.*f\n",
			precision(inkb), inkb,
			precision(outkb), outkb,
			precision(inseg), inseg,
			precision(outseg), outseg,
			precision4(reset), reset,
			precision4(attfail), attfail,
			precision_p(retrans_rate), retrans_rate,
			precision4(inconn), inconn,
			precision4(outconn), outconn,
			precision4(drops), drops);
	/* Flip pointers to TCP stats */
	tsp = g_tcp_old;
	g_tcp_old = g_tcp_new;
	g_tcp_new = tsp;
}

static void
print_udp()
{
	double indg, outdg, inerr, outerr;
	udpstats_t *usp;
	double tdiff;

	if (g_udp_old->tv.tv_sec == 0)
		/* Not initialised */
		g_udp_old->tv.tv_sec = fetch_boot_time();
	tdiff = tv_diff(&g_udp_new->tv, &g_udp_old->tv);
	if (tdiff == 0)
		tdiff = 1;

	/* Header */
	update_timestr(&(g_udp_new->tv.tv_sec));
	if (! g_opt_p)
		(void) printf("%8s                 %7s %7s   %7s %7s\n",
			g_timestr, "InDG", "OutDG", "InErr", "OutErr");

	indg = UDPSTAT(inDatagrams) / tdiff;
	outdg = UDPSTAT(outDatagrams) / tdiff;
	inerr = UDPSTAT(inErrors) / tdiff;
	outerr = UDPSTAT(outErrors) / tdiff;

	if (g_opt_p)
		(void) printf("%ld:UDP:%.*f:%.*f:%.*f:%.*f\n",
			g_udp_new->tv.tv_sec,
			precision_p(indg), indg,
			precision_p(outdg), outdg,
			precision_p(inerr), inerr,
			precision_p(outerr), outerr);
	else
		(void) printf("UDP                      "
			"%7.*f %7.*f   %7.*f %7.*f\n",
			precision(indg), indg,
			precision(outdg), outdg,
			precision(inerr), inerr,
			precision(outerr), outerr);

	/* Flip pointers to TCP stats */
	usp = g_udp_old;
	g_udp_old = g_udp_new;
	g_udp_new = usp;
}

/*
 * print_header - print the header line.
 */
static void
print_header(void)
{
#if DEBUG > 1
	(void) printf("<<nic_count = %d>>\n", g_nicdata_count);
#endif
	switch (g_style) {
	case STYLE_SUMMARY:
		(void) printf("%8s %8s %14s %14s\n",
		    "Time", "Int", g_runit_1, g_wunit_1);
		break;
	case STYLE_FULL:
		(void) printf("%8s %8s %7s %7s %7s "
		    "%7s %7s %7s %5s %6s\n",
		    "Time", "Int", g_runit_1, g_wunit_1, "rPk/s",
		    "wPk/s", "rAvs", "wAvs", "%Util", "Sat");
		break;
	case STYLE_FULL_UTIL:
		(void) printf("%8s %8s %7s %7s %7s "
		    "%7s %7s %7s %6s %6s\n",
		    "Time", "Int", g_runit_1, g_wunit_1, "rPk/s",
		    "wPk/s", "rAvs", "wAvs", "%rUtil", "%wUtil");
		break;
	case STYLE_EXTENDED:
		update_timestr(NULL);
		(void) printf("%-10s %7s %7s %7s %7s  "
		    "%5s %5s %5s %5s %5s  %5s\n",
		    g_timestr, g_runit_2, g_wunit_2, "RdPkt", "WrPkt",
		    "IErr", "OErr", "Coll", "NoCP", "Defer", "%Util");
		break;
	case STYLE_EXTENDED_UTIL:
		update_timestr(NULL);
		(void) printf("%-10s %7s %7s %7s %7s  "
		    "%5s %5s %5s %5s %5s %6s %6s\n",
		    g_timestr, g_runit_2, g_wunit_2, "RdPkt", "WrPkt",
		    "IErr", "OErr", "Coll", "NoCP", "Defer",
		    "%rUtil", "%wUtil");
		break;
	}
}

inline static double
max(double d1, double d2)
{
	if (d1 > d2)
		return (d1);
	return (d2);
}

inline static double
min(double d1, double d2)
{
	if (d1 < d2)
		return (d1);
	return (d2);
}

/*
 * print_stats - generate output
 *
 * This routine runs through the linked list of interfaces, prints out
 * statistics where appropriate, then moves the "new" stats to the "old"
 * stats, ready for next time.
 */
static void
print_stats()
{
	struct nicdata *nicp;	/* ptr into g_nicdatap linked list */
	double rbps;		/* read bytes per sec */
	double wbps;		/* write bytes per sec */
	double rkps;		/* read KB per sec */
	double wkps;		/* write KB per sec */
	double rpps;		/* read packets per sec */
	double wpps;		/* write packets per sec */
	double ravs;		/* read average packet size */
	double wavs;		/* write average packet size */
	double sats;		/* saturation value per sec */
	double ierrs;
	double oerrs;
	double colls;
	double nocps;
	double defers;
	double tdiff;		/* time difference between samples */
	double util;		/* utilisation */
	double rutil;		/* In (read) utilisation */
	double wutil;		/* Out (write) utilisation */

	if (g_tcp)
		print_tcp();
	if (g_udp)
		print_udp();

	/* Print header if needed */
	if (! g_list)
		if (g_tcp || g_udp || (g_line >= PAGE_SIZE)) {
			g_line = 0;
			print_header();
		}

	for (nicp = g_nicdatap; nicp; nicp = nicp->next) {
#ifdef OS_SOLARIS
		if (! (nicp->flags & NIC_UP))
			/* Link is not up */
			continue;
		if (g_nonlocal && (nicp->flags & NIC_LOOPBACK))
			continue;
#endif
#ifdef OS_LINUX
		if (! nicp->report)
			continue;
		nicp->report = 0;
#endif
		/* Calculate time difference */
#ifdef OS_LINUX
		if (nicp->old.tv.tv_sec == 0)
			/* Not initialised, so numbers will be since boot */
			nicp->old.tv.tv_sec = g_boot_time;
#endif
		tdiff = tv_diff(&nicp->new.tv, &nicp->old.tv);
		if (tdiff == 0)
			tdiff = 1;

		/* Calculate per second values */
		rbps = (nicp->new.rbytes - nicp->old.rbytes) / tdiff;
		wbps = (nicp->new.wbytes - nicp->old.wbytes) / tdiff;
		rpps = (nicp->new.rpackets - nicp->old.rpackets) / tdiff;
		wpps = (nicp->new.wpackets - nicp->old.wpackets) / tdiff;
		if (g_style == STYLE_EXTENDED ||
		    g_style == STYLE_EXTENDED_UTIL ||
		    g_style == STYLE_EXTENDED_PARSEABLE) {
			ierrs = (nicp->new.ierr - nicp->old.ierr) / tdiff;
			oerrs = (nicp->new.oerr - nicp->old.oerr) / tdiff;
			colls = (nicp->new.coll - nicp->old.coll) / tdiff;
			nocps = (nicp->new.nocp - nicp->old.nocp) / tdiff;
			defers = (nicp->new.defer - nicp->old.defer) / tdiff;
		} else if (g_style == STYLE_FULL ||
		    g_style == STYLE_FULL_UTIL) {
			if (rpps > 0)
				ravs = rbps / rpps;
			else
				ravs = 0;
			if (wpps > 0)
				wavs = wbps / wpps;
			else
				wavs = 0;
		}
		if (g_style == STYLE_FULL ||
		    g_style == STYLE_FULL_UTIL ||
		    g_style == STYLE_PARSEABLE ||
		    g_style == STYLE_EXTENDED_PARSEABLE)
			sats = (nicp->new.sat - nicp->old.sat) / tdiff;
		if (g_opt_m) {
			/* report in Mbps */
			rkps = rbps / 1024 / 128;
			wkps = wbps / 1024 / 128;
		} else {
			/* original KB/sec */
			rkps = rbps / 1024;
			wkps = wbps / 1024;
		}

		/* Calculate utilisation */
		if (nicp->speed > 0) {
			/*
			 * The following have a mysterious "800", it is
			 * 100 for the % conversion, and 8 for
			 * bytes2bits.
			 */
			rutil = min(rbps * 800 / nicp->speed, 100);
			wutil = min(wbps * 800 / nicp->speed, 100);
			if (nicp->duplex == DUPLEX_FULL) {
				/* Full duplex */
				util = max(rutil, wutil);
			} else {
				/* Half Duplex */
				util = min((rbps + wbps) * 800 / nicp->speed,
				    100);
			}
		} else {
			util = 0;
			rutil = 0;
			wutil = 0;
		}
		/* always print header if there are multiple NICs */
		if (g_nicdata_count > 1)
			g_line += PAGE_SIZE;
		else
			g_line++;

		/* Skip zero lines */
		if (g_skipzero && wpps == 0 && rpps == 0)
			continue;

		/* Print output line */
		switch (g_style) {
		case STYLE_SUMMARY:
			update_timestr(&nicp->new.tv.tv_sec);
			(void) printf("%s %8s %14.3f %14.3f\n",
				g_timestr, nicp->name, rkps, wkps);
			break;
		case STYLE_FULL:
			update_timestr(&nicp->new.tv.tv_sec);
			(void) printf("%s %8s %7.*f %7.*f %7.*f %7.*f "
				"%7.*f %7.*f %5.*f %6.*f\n",
				g_timestr, nicp->name,
				precision(rkps), rkps,
				precision(wkps), wkps,
				precision(rpps), rpps,
				precision(wpps), wpps,
				precision(ravs), ravs,
				precision(wavs), wavs,
				precision4(util), util,
				precision(sats), sats);
			break;
		case STYLE_FULL_UTIL:
			update_timestr(&nicp->new.tv.tv_sec);
			(void) printf("%s %8s %7.*f %7.*f %7.*f %7.*f "
				"%7.*f %7.*f %6.*f %6.*f\n",
				g_timestr, nicp->name,
				precision(rkps), rkps,
				precision(wkps), wkps,
				precision(rpps), rpps,
				precision(wpps), wpps,
				precision(ravs), ravs,
				precision(wavs), wavs,
				precision4(rutil), rutil,
				precision4(wutil), wutil);
			break;
		case STYLE_PARSEABLE:
			(void) printf("%ld:%s:%.*f:%.*f:%.*f:%.*f:"
				"%.*f:%.*f\n",
				nicp->new.tv.tv_sec, nicp->name,
				precision_p(rkps), rkps,
				precision_p(wkps), wkps,
				precision_p(rpps), rpps,
				precision_p(wpps), wpps,
				precision4(util), util,
				precision(sats), sats);
			break;
		case STYLE_EXTENDED:
			(void) printf("%-10s %7.*f %7.*f %7.*f %7.*f  "
				"%5.*f %5.*f %5.*f %5.*f %5.*f  %5.*f\n",
				nicp->name,
				precision(rkps), rkps,
				precision(wkps), wkps,
				precision(rpps), rpps,
				precision(wpps), wpps,
				precision4(ierrs), ierrs,
				precision4(oerrs), oerrs,
				precision4(colls), colls,
				precision4(nocps), nocps,
				precision4(defers), defers,
				precision4(util), util);
			break;
		case STYLE_EXTENDED_UTIL:
			(void) printf("%-10s %7.*f %7.*f %7.*f %7.*f  "
				"%5.*f %5.*f %5.*f %5.*f %5.*f %6.*f %6.*f\n",
				nicp->name,
				precision(rkps), rkps,
				precision(wkps), wkps,
				precision(rpps), rpps,
				precision(wpps), wpps,
				precision4(ierrs), ierrs,
				precision4(oerrs), oerrs,
				precision4(colls), colls,
				precision4(nocps), nocps,
				precision4(defers), defers,
				precision4(rutil), rutil,
				precision4(wutil), wutil);
			break;
		case STYLE_EXTENDED_PARSEABLE:
			/*
			 * Use same initial order as STYLE_PARSEABLE
			 * for backward compatibility
			 */
			(void) printf("%ld:%s:%.*f:%.*f:%.*f:%.*f:"
				"%.*f:%.*f:%.*f:%.*f:%.*f:%.*f:%.*f\n",
				nicp->new.tv.tv_sec, nicp->name,
				precision_p(rkps), rkps,
				precision_p(wkps), wkps,
				precision_p(rpps), rpps,
				precision_p(wpps), wpps,
				precision4(util), util,
				precision(sats), sats,
				precision(ierrs), ierrs,
				precision(oerrs), oerrs,
				precision(colls), colls,
				precision(nocps), nocps,
				precision(defers), defers);
		}

		/* Save the current values for next time */
		nicp->old = nicp->new;
	}
}

static void
cont_handler(int sig_number)
{
	/* Re-set the signal handler */
	(void) signal(sig_number, cont_handler);
#if DEBUG > 0
	(void) fprintf(stderr, "<< caught SIGCONT >>\n");
#endif
	g_caught_cont = 1;
}

#ifdef OS_SOLARIS
/*
 * sleep_for - sleep until start_n + period
 *
 * This Solaris version uses gethrtime() and nanosleep()
 */
static void
sleep_for(hrtime_t period, hrtime_t start_n)
{
	struct timespec pause_tv;
	hrtime_t now_n, pause_n;
	int status;

	pause_n = period;
	do {
		pause_tv.tv_sec = pause_n / NANOSEC;
		pause_tv.tv_nsec = pause_n % NANOSEC;
		status = nanosleep(&pause_tv, (struct timespec *)NULL);
		if (status < 0)
			if (errno == EINTR) {
				now_n = gethrtime();
				pause_n = start_n + period - now_n;
				if (pause_n < 100)
					/* Forget about it */
					return;
			} else {
				die(1, "nanosleep", g_progname);
			}
	} while (status != 0);
}
#endif /* OS_SOLARIS */

#ifdef OS_LINUX
/*
 * sleep_for - sleep until now + millisec
 */
static inline void
sleep_for(int period_ms, struct timeval *start_tv)
{
	int status;
	int done = 0;
	struct timeval then;
	int us;

	then.tv_sec = 0;
	do {
		status = poll(NULL, 0, period_ms);
		if (status < 0) {
			if (errno != EINTR) {
				perror("poll");
				exit(1);
			}
			/* Interrupted - we are not done yet */
			if (then.tv_sec == 0) {
				then.tv_sec = start_tv->tv_sec +
					(period_ms / 1000);
				us = ((period_ms % 1000) * 1000) +
					start_tv->tv_usec;
				if (us > 1000000) {
					/* Wrapped */
					then.tv_sec++;
					then.tv_usec = us - 1000000;
				} else
					then.tv_usec = us;
			}
			(void) gettimeofday(start_tv, NULL);
			period_ms = (then.tv_sec - start_tv->tv_sec) * 1000;
			period_ms += (then.tv_usec - start_tv->tv_usec) / 1000;
			if (period_ms <= 0)
				done = 1;
		} else
			done = 1;
	} while (! done);
}
#endif /* OS_LINUX */

#ifdef OS_LINUX
static void
init_if_speed_list(char *speed_list)
{
	struct if_speed_list	*list_elem;
	char			*speed_list_save_ptr;
	char			*if_record;
	char			name[32];
	uint64_t		speed;
	char			duplex_s[32];
	int			tokens;

	if_record = strtok_r(speed_list, ",", &speed_list_save_ptr);
	while (if_record) {
		duplex_s[0] = '\0';
		tokens = sscanf(if_record, "%31[^:]:%llu%31s",
			name, &speed, duplex_s);
		if (tokens == 0)
			continue;
		if (speed <= 0)
			die(0, "invalid speed for -S %s", name, if_record);
		if (name == NULL)
			die(0, "invalid -S argument");

		list_elem = allocate(sizeof (struct if_speed_list));
		list_elem->name = new_string(name);
		/* speed is in megabits/second */
		list_elem->speed = speed * 1000000;
		/* Do we have a duplex suffix? */
		switch (duplex_s[0]) {
		case 'h':
		case 'H':
			list_elem->duplex = DUPLEX_HALF;
			break;
		case 'f':
		case 'F':
		case '\0':	/* Not specified - default is full */
			list_elem->duplex = DUPLEX_FULL;
			break;
		default:
			list_elem->duplex = DUPLEX_UNKNOWN;
		}
#if DEBUG > 0
		fprintf(stderr, "<< %s - %llu mbps, duplex = %d >>\n",
			name, speed, list_elem->duplex);
#endif
		list_elem->next = g_if_speed_list;
		g_if_speed_list = list_elem;

		if_record = strtok_r(NULL, ",", &speed_list_save_ptr);
	}
}
#endif /* OS_LINUX */

/*
 * split - Split a string of delimited fields, returning an array of char *
 *
 * NOTE: the input string gets modified by this routine
 */
static char **
split(char *string, char *delim, int *nitems)
{
	int ndelim, i;
	char *p;
	char *lasts;
	char **ptrs;

	/* How many delimiters do we have? */
	ndelim = 0;
	for (p = string; *p; p++)
		if (*p == *delim)
			ndelim++;

	/* We need that many ptrs + 2 (max) */
	ptrs = allocate((ndelim + 2) * sizeof (char *));

	/* Tokenize */
	i = 0;
	ptrs[i] = strtok_r(string, delim, &lasts);
	while (ptrs[i])
		ptrs[++i] = strtok_r(NULL, delim, &lasts);
	*nitems = i;
	return (ptrs);
}

static char *
duplex_to_string(duplex_t duplex)
{
	switch (duplex) {
	case DUPLEX_HALF:
		return ("half");
	case DUPLEX_FULL:
		return ("full");
	default:
		return ("unkn");
	}
}

static void
list_ifs()
{
	nicdata_t *p;
	int loopback;
	uint64_t speed;
	int verbose;
	int if_up;

#ifdef OS_SOLARIS
	verbose = g_verbose;
#else
	verbose = 0;
#endif

	if (verbose)
		(void) printf("Int      Loopback   Mbit/s Duplex State"
			"    Flags ls_types op_types\n");
	else
		(void) printf("Int      Loopback   Mbit/s Duplex State\n");
	for (p = g_nicdatap; p; p = p->next) {
		if (if_is_ignored(p->name))
			continue;
		loopback = p->flags & NIC_LOOPBACK;
#ifdef OS_SOLARIS
		if_up = p->flags & NIC_UP;
#else
		if_up = B_TRUE;
#endif
		if (loopback)
			(void) printf("%-12s  Yes        -   %4s  %4s",
				p->name, duplex_to_string(p->duplex),
				if_up ? "up" : "down");
		else {
			speed = (p->speed) / 1000000;
			(void) printf("%-12s   No %8llu   %4s  %4s",
				p->name, speed, duplex_to_string(p->duplex),
				if_up ? "up" : "down");
		}
#ifdef OS_SOLARIS
		if (verbose) {
			(void) printf(" %08x %08x %08x\n",
				p->flags, p->ls_types, p->op_types);
			continue;
		}
#endif
		(void) printf("\n");
	}
}

static void
init_tcp()
{
	g_tcp_old = allocate(sizeof (tcpstats_t));
	g_tcp_new = allocate(sizeof (tcpstats_t));
#ifdef OS_SOLARIS
	g_tcp_ksp = kstat_lookup(g_kc, "tcp", -1, "tcp");
	if (! g_tcp_ksp) {
		diag(0, "tcp kstats not found");
	}
#endif
}

static void
init_udp()
{
	g_udp_old = allocate(sizeof (udpstats_t));
	g_udp_new = allocate(sizeof (udpstats_t));
#ifdef OS_SOLARIS
	g_udp_ksp = kstat_lookup(g_kc, "udp", -1, "udp");
	if (! g_udp_ksp)
		diag(0, "udp kstats not found");
#endif
}

#ifdef USE_DLADM
/*
 * Do not be confused - the prefix "dl" can stand for Dynamic Linking,
 * as well as "Data Link"...
 */
static void
init_dladm()
{
	void *handle;
	dladm_status_t (*fptr)();
	dladm_status_t dlstat;

	g_use_dladm = B_FALSE;
	if ((handle = dlopen("libdladm.so.1", RTLD_LAZY)) == NULL)
		return;
	if ((fptr = (dladm_status_t (*)())
	    dlsym(handle, "dladm_datalink_id2info")) == NULL) {
		(void) dlclose(handle);
		return;
	}
	g_use_dladm = B_TRUE;
	/* Get a handle to use for libdladm call(s) */
	/* NOTE: This changed in S11.1 */
#ifdef NETADM_ACTIVE_PROFILE
	dlstat = dladm_open(&g_handle, NULL);
#else
	dlstat = dladm_open(&g_handle);
#endif
	if (dlstat != DLADM_STATUS_OK) {
		char errmsg[DLADM_STRSIZE];

		die(0, "could not open /dev/dld: %s",
		    dladm_status2str(dlstat, errmsg));
	}
}
#endif /* USE_DLADM */

/*
 * Main Program
 */
int
main(int argc, char **argv)
{
	/*
	 * Variable Declaration
	 */
	int interval;		/* interval, secs */
	int loop_max;		/* max output lines */
	int loop;		/* current loop number */
	int option;		/* command line switch */
	int tracked_ifs;
	int time_is_up;
#ifdef OS_SOLARIS
	hrtime_t period_n;	/* period of each iteration in nanoseconds */
	hrtime_t start_n;	/* start point of an iteration, nsec */
	hrtime_t end_n;		/* end time of work in an iteration, nsec */
	hrtime_t pause_n;	/* time until start of next iteration, nsec */
	kid_t kc_id;
#else /* OS_SOLARIS */
	int net_dev;		/* file descriptor for stats file */
	int pause_m;		/* time to pause, milliseconds */
	struct timeval start;	/* start point of an iteration */
	struct timeval now;
#endif /* OS_SOLARIS */
#if DEBUG > 1
	struct timeval debug_now;
#endif

	/* defaults */
	interval = INTERVAL;
	loop_max = LOOP_MAX;
	g_line = PAGE_SIZE;
	loop = 0;
	g_style = STYLE_FULL;
	g_skipzero = B_FALSE;
	g_nonlocal = B_FALSE;
	g_someif = B_FALSE;
	g_forever = B_FALSE;
	g_caught_cont = B_FALSE;
	g_opt_m = B_FALSE;
#ifdef OS_SOLARIS
	g_list = B_FALSE;
	g_verbose = B_FALSE;
	g_opt_x = B_FALSE;
	g_opt_p = B_FALSE;
	g_opt_k = B_FALSE;
#endif

	/*
	 * Process arguments
	 */
	g_progname = argv[0];
	while ((option = getopt(argc, argv, GETOPT_OPTIONS)) != -1) {
		switch (option) {
		case 'h':
			usage();
			break;
		case 'i':
			g_tracked = split(optarg, ",", &tracked_ifs);
			g_someif = tracked_ifs > 0;
			break;
		case 's':
			g_style = STYLE_SUMMARY;
			break;
		case 'v':
			g_verbose = B_TRUE;
			break;
		case 'z':
			g_skipzero = 1;
			break;
		case 'n':
			g_nonlocal = 1;
			break;
		case 't':
			g_tcp = B_TRUE;
			if (g_style == STYLE_FULL)
				g_style = STYLE_NONE;
			break;
		case 'u':
			g_udp = B_TRUE;
			if (g_style == STYLE_FULL)
				g_style = STYLE_NONE;
			break;
		case 'x':
			g_opt_x = B_TRUE;
			break;
		case 'a':
			g_tcp = g_udp = B_TRUE;
			if (g_style == STYLE_FULL)
				g_opt_x = B_TRUE;
			break;
		case 'M':
		case 'm':	/* Undocumented */
			g_opt_m = B_TRUE;
			break;
		case 'p':
			g_opt_p = B_TRUE;
			break;
		case 'l':
			g_list = B_TRUE;
			g_style = STYLE_NONE;
			break;
		case 'U':
			g_opt_U = B_TRUE;
			break;
#ifdef OS_LINUX
		case 'S':
			init_if_speed_list(optarg);
			break;
#endif
#ifdef OS_SOLARIS
		case 'k':
			g_opt_k = B_TRUE;
			break;
#endif /* OS_SOLARIS */
		default:
			usage();
		}
	}
	if (g_opt_p) {
		if (g_opt_x)
			g_style = STYLE_EXTENDED_PARSEABLE;
		else if (! g_tcp && ! g_udp)
			g_style = STYLE_PARSEABLE;
		/* Always output KB in the parseable format */
		g_opt_m = B_FALSE;
	} else
		if (g_opt_x)
			g_style = STYLE_EXTENDED;
	if (g_opt_U)
		switch (g_style) {
		case STYLE_FULL:
			g_style = STYLE_FULL_UTIL;
			break;
		case STYLE_EXTENDED:
			g_style = STYLE_EXTENDED_UTIL;
		}
	if (g_opt_m) {
		g_runit_1 = "rMbps";
		g_wunit_1 = "wMbps";
		g_runit_2 = "RdMbps";
		g_wunit_2 = "WrMbps";
	}

	argv += optind;
	if ((argc - optind) >= 1) {
		interval = atoi(*argv);
		if (interval == 0)
			usage();
		argv++;
		if ((argc - optind) >= 2)
			loop_max = atoi(*argv);
		else
			g_forever = 1;
	}

#ifdef OS_SOLARIS
	/* Open Kstat */
	if ((g_kc = kstat_open()) == NULL)
		die(1, "kstat_open");
#endif
	if (g_tcp)
		init_tcp();
	if (g_udp)
		init_udp();
#ifdef OS_SOLARIS
	if ((g_style == STYLE_NONE) && (g_tcp || g_udp))
		if ((! g_tcp_ksp) && (! g_udp_ksp))
			/* Nothing to show */
			exit(1);
	g_tcp = g_tcp && g_tcp_ksp;
	g_udp = g_udp && g_udp_ksp;
#endif

#ifdef USE_DLADM
	init_dladm();
#endif

	/* Get a socket so I can do ioctl's */
	if ((g_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		die(1, "socket");

#ifdef OS_SOLARIS
	/* Calculate the period of each iteration */
	period_n = (hrtime_t)interval * NANOSEC;

	/* Get time when we started */
	start_n = gethrtime();
#else /* OS_SOLARIS */
	/* Open the file we got stats from (in Linux) */
	net_dev = open(PROC_NET_DEV_PATH, O_RDONLY, 0);
	if (net_dev < 0)
		die(1, "open: %s", PROC_NET_DEV_PATH);
	if (g_tcp || g_udp) {
		g_snmp = fopen(PROC_NET_SNMP_PATH, "r");
		if (! g_snmp)
			die(1, "fopen: %s", PROC_NET_SNMP_PATH);
	}
	if (g_tcp) {
		g_netstat = fopen(PROC_NET_NETSTAT_PATH, "r");
		if (! g_netstat)
			die(1, "fopen: %s", PROC_NET_NETSTAT_PATH);
	}

	/* Get boot-time */
	g_boot_time = fetch_boot_time();

	/* Get time when we started */
	if (gettimeofday(&start, (void *) NULL) < 0)
		die(1, "gettimeofday");
#endif /* OS_SOLARIS */

	/*
	 * Set up signal handling
	 */
	(void) signal(SIGCONT, cont_handler);

	if (g_verbose) {
		(void) printf("nicstat version " NICSTAT_VERSION "\n");
	}

	/*
	 * Main Loop
	 */
	for (;;) {
#if DEBUG > 1
		if (gettimeofday(&debug_now, (void *) NULL) < 0) {
			perror("gettimeofday");
			exit(2);
		}
		fprintf(stderr, "        pre-op = %ld.%06ld\n",
			debug_now.tv_sec, debug_now.tv_usec);
#endif

		/*
		 * Fetch data and update statistics
		 */
#ifdef OS_SOLARIS
		update_nicdata_list();
		update_stats();
#else
		update_stats(net_dev);
#endif

		/* Check we matched some NICs */
		if (g_nicdata_count <= 0)
			die(0, "no matching interface");

		/*
		 * Just a list?
		 */
		if (g_list) {
			list_ifs();
			break;
		}

		/*
		 * Print statistics
		 */
		print_stats();

		/* end point */
		if (! g_forever)
			if (++loop == loop_max) break;

		/* flush output */
		if (fflush(stdout) != 0)
			die(1, "fflush(stdout)");

		/*
		 * have a kip
		 */
#ifdef OS_SOLARIS
		end_n = gethrtime();
		pause_n = start_n + period_n - end_n;
		time_is_up = pause_n <= 0 || pause_n < (period_n / 4);
#else /* OS_SOLARIS */
		(void) gettimeofday(&now, NULL);
		start.tv_sec += interval;
		pause_m = (start.tv_sec - now.tv_sec) * 1000;
		pause_m += (start.tv_usec - now.tv_usec) / 1000;
		time_is_up = pause_m <= 0 || pause_m < (interval * 250);
#endif /* OS_SOLARIS */
		if (time_is_up)
			if (g_forever || g_caught_cont) {
				/* Reset our cadence */
#ifdef OS_SOLARIS
				start_n = end_n + period_n;
				pause_n = period_n;
#else /* OS_SOLARIS */
				start.tv_sec = now.tv_sec + interval;
				start.tv_usec = now.tv_usec;
				pause_m = interval * 1000;
#endif /* OS_SOLARIS */
			} else {
				/*
				 * The case for better observability
				 *
				 * If we got here, then the time
				 * between the output we just did, and
				 * the scheduled time for the next
				 * output is < 1/4 of our requested
				 * interval AND the number of
				 * intervals has been requested AND we
				 * have never caught a SIGCONT (so we
				 * have never been suspended).  In
				 * this case, we'll try to get back to
				 * the desired cadence, so we will
				 * pause for 1/2 the normal interval
				 * this time.
				 */
#ifdef OS_SOLARIS
				pause_n = period_n / 2;
				start_n += period_n;
#else /* OS_SOLARIS */
				pause_m = interval * 500;
#endif /* OS_SOLARIS */
			}
#ifdef OS_SOLARIS
		else
			start_n += period_n;
		if (pause_n > 0)
			sleep_for(pause_n, end_n);
		if ((kc_id = kstat_chain_update(g_kc)) == -1)
			die(1, "kstat_chain_update");
		g_new_kstat_chain = (kc_id != 0);
#else /* OS_SOLARIS */
		if (pause_m > 0)
			sleep_for(pause_m, &now);
#endif /* OS_SOLARIS */
	}


	/*
	 * Close Kstat & socket
	 */
#ifdef OS_SOLARIS
	(void) kstat_close(g_kc);
#endif
	(void) close(g_sock);

	return (0);
}
