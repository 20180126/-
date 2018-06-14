## ぽすとふぃっくす

***

```c

// postqueue

/* stream.
/* ENVIRONMENT
/* .ad
/* .fi
/* .IP MAIL_CONFIG
/* Directory with the \fBmain.cf\fR file. In order to avoid exploitation
/* of set-group ID privileges, a non-standard directory is allowed only
/* if:
/* .RS
/* .IP \(bu
/* The name is listed in the standard \fBmain.cf\fR file with the
/* \fBalternate_config_directories\fR configuration parameter.
/* .IP \(bu
/* The command is invoked by the super-user.
/* .RE
/* CONFIGURATION PARAMETERS
/* .ad
/* .fi
/* The following \fBmain.cf\fR parameters are especially relevant to
/* this program.
/* The text below provides only a parameter summary. See
/* \fBpostconf\fR(5) for more details including examples.
/* .IP "\fBalternate_config_directories (empty)\fR"
/* A list of non-default Postfix configuration directories that may
/* be specified with "-c config_directory" on the command line, or
/* via the MAIL_CONFIG environment parameter.
/* .IP "\fBconfig_directory (see 'postconf -d' output)\fR"
/* The default location of the Postfix main.cf and master.cf
/* configuration files.
/* .IP "\fBcommand_directory (see 'postconf -d' output)\fR"
/* The location of all postfix administrative commands.
/* .IP "\fBfast_flush_domains ($relay_domains)\fR"
/* Optional list of destinations that are eligible for per-destination
/* logfiles with mail that is queued to those destinations.
/* .IP "\fBimport_environment (see 'postconf -d' output)\fR"
/* The list of environment parameters that a Postfix process will
/* import from a non-Postfix parent process.
/* .IP "\fBqueue_directory (see 'postconf -d' output)\fR"
/* The location of the Postfix top-level queue directory.
/* .IP "\fBsyslog_facility (mail)\fR"
/* The syslog facility of Postfix logging.
/* .IP "\fBsyslog_name (see 'postconf -d' output)\fR"
/* The mail system name that is prepended to the process name in syslog
/* records, so that "smtpd" becomes, for example, "postfix/smtpd".
/* .IP "\fBtrigger_timeout (10s)\fR"
/* The time limit for sending a trigger to a Postfix daemon (for
/* example, the \fBpickup\fR(8) or \fBqmgr\fR(8) daemon).
/* .PP
/* Available in Postfix version 2.2 and later:
/* .IP "\fBauthorized_flush_users (static:anyone)\fR"
/* List of users who are authorized to flush the queue.
/* .IP "\fBauthorized_mailq_users (static:anyone)\fR"
/* List of users who are authorized to view the queue.
/* FILES
/* /var/spool/postfix, mail queue
/* SEE ALSO
/* qmgr(8), queue manager
/* showq(8), list mail queue
/* flush(8), fast flush service
/* sendmail(1), Sendmail-compatible user interface
/* postsuper(1), privileged queue operations
/* README FILES
/* .ad
/* .fi
/* Use "\fBpostconf readme_directory\fR" or
/* "\fBpostconf html_directory\fR" to locate this information.
/* .na
/* .nf
/* ETRN_README, Postfix ETRN howto
/* LICENSE
/* .ad
/* .fi
/* The Secure Mailer license must be distributed with this software.
/* HISTORY
/* .ad
/* .fi
/* The postqueue command was introduced with Postfix version 1.1.
/* AUTHOR(S)
/* Wietse Venema
/* IBM T.J. Watson Research
/* P.O. Box 704
/* Yorktown Heights, NY 10598, USA
/*--*/

/* System library. */

#include <sys_defs.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sysexits.h>
#include <errno.h>

/* Utility library. */

#include <msg.h>
#include <mymalloc.h>
#include <clean_env.h>
#include <vstream.h>
#include <msg_vstream.h>
#include <msg_syslog.h>
#include <argv.h>
#include <safe.h>
#include <connect.h>
#include <valid_hostname.h>
#include <events.h>

/* Global library. */

#include <mail_proto.h>
#include <mail_params.h>
#include <mail_version.h>
#include <mail_conf.h>
#include <mail_task.h>
#include <mail_run.h>
#include <mail_flush.h>
#include <mail_queue.h>
#include <flush_clnt.h>
#include <smtp_stream.h>
#include <user_acl.h>
#include <valid_mailhost_addr.h>
#include <mail_dict.h>

/* Application-specific. */

 /*
  * WARNING WARNING WARNING
  * 
  * This software is designed to run set-gid. In order to avoid exploitation of
  * privilege, this software should not run any external commands, nor should
  * it take any information from the user, unless that information can be
  * properly sanitized. To get an idea of how much information a process can
  * inherit from a potentially hostile user, examine all the members of the
  * process structure (typically, in /usr/include/sys/proc.h): the current
  * directory, open files, timers, signals, environment, command line, umask,
  * and so on.
  */

 /*
  * Modes of operation.
  * 
  * XXX To support flush by recipient domain, or for destinations that have no
  * mapping to logfile, the server has to defend against resource exhaustion
  * attacks. A malicious user could fork off a postqueue client that starts
  * an expensive requests and then kills the client immediately; this way she
  * could create a high Postfix load on the system without ever exceeding her
  * own per-user process limit. To prevent this, either the server needs to
  * establish frequent proof of client liveliness with challenge/response, or
  * the client needs to restrict expensive requests to privileged users only.
  * 
  * We don't have this problem with queue listings. The showq server detects an
  * EPIPE error after reporting a few queue entries.
  */
#define PQ_MODE_DEFAULT  0 /* noop */
#define PQ_MODE_MAILQ_LIST 1 /* list mail queue */
#define PQ_MODE_FLUSH_QUEUE 2 /* flush queue */
#define PQ_MODE_FLUSH_SITE 3 /* flush site */
#define PQ_MODE_FLUSH_FILE 4 /* flush message */

 /*
  * Silly little macros (SLMs).
  */
#define STR vstring_str

 /*
  * Queue manipulation access lists.
  */
char   *var_flush_acl;
char   *var_showq_acl;

static const CONFIG_STR_TABLE str_table[] = {
    VAR_FLUSH_ACL, DEF_FLUSH_ACL, &var_flush_acl, 0, 0,
    VAR_SHOWQ_ACL, DEF_SHOWQ_ACL, &var_showq_acl, 0, 0,
    0,
};

/* show_queue - show queue status */

static void show_queue(void)
{
    const char *errstr;
    char    buf[VSTREAM_BUFSIZE];
    VSTREAM *showq;
    int     n;
    uid_t   uid = getuid();

    if (uid != 0 && uid != var_owner_uid
 && (errstr = check_user_acl_byuid(var_showq_acl, uid)) != 0)
 msg_fatal_status(EX_NOPERM,
         "User %s(%ld) is not allowed to view the mail queue",
    errstr, (long) uid);

    /*
     * Connect to the show queue service. Terminate silently when piping into
     * a program that terminates early.
     */
    if ((showq = mail_connect(MAIL_CLASS_PUBLIC, var_showq_service, BLOCKING)) != 0) {
 while ((n = vstream_fread(showq, buf, sizeof(buf))) > 0) {
     if (vstream_fwrite(VSTREAM_OUT, buf, n) != n
  || vstream_fflush(VSTREAM_OUT) != 0) {
  if (errno == EPIPE)
      break;
  msg_fatal("write error: %m");
     }
 }
 if (vstream_fclose(showq) && errno != EPIPE)
     msg_warn("close: %m");
    }

    /*
     * Don't assume that the mail system is down when the user has
     * insufficient permission to access the showq socket.
     */
    else if (errno == EACCES) {
 msg_fatal_status(EX_SOFTWARE,
    "Connect to the %s %s service: %m",
    var_mail_name, var_showq_service);
    }

    /*
     * When the mail system is down, the superuser can still access the queue
     * directly. Just run the showq program in stand-alone mode.
     */
    else if (geteuid() == 0) {
 ARGV   *argv;
 int     stat;

 msg_warn("Mail system is down -- accessing queue directly");
 argv = argv_alloc(6);
 argv_add(argv, var_showq_service, "-u", "-S", (char *) 0);
 for (n = 0; n < msg_verbose; n++)
     argv_add(argv, "-v", (char *) 0);
 argv_terminate(argv);
 stat = mail_run_foreground(var_daemon_dir, argv->argv);
 argv_free(argv);
    }

    /*
     * When the mail system is down, unprivileged users are stuck, because by
     * design the mail system contains no set_uid programs. The only way for
     * an unprivileged user to cross protection boundaries is to talk to the
     * showq daemon.
     */
    else {
 msg_fatal_status(EX_UNAVAILABLE,
    "Queue report unavailable - mail system is down");
    }
}

/* flush_queue - force delivery */

static void flush_queue(void)
{
    const char *errstr;
    uid_t   uid = getuid();

    if (uid != 0 && uid != var_owner_uid
 && (errstr = check_user_acl_byuid(var_flush_acl, uid)) != 0)
 msg_fatal_status(EX_NOPERM,
        "User %s(%ld) is not allowed to flush the mail queue",
    errstr, (long) uid);

    /*
     * Trigger the flush queue service.
     */
    if (mail_flush_deferred() < 0)
 msg_fatal_status(EX_UNAVAILABLE,
    "Cannot flush mail queue - mail system is down");
    if (mail_flush_maildrop() < 0)
 msg_fatal_status(EX_UNAVAILABLE,
    "Cannot flush mail queue - mail system is down");
    event_drain(2);
}

/* flush_site - flush mail for site */

static void flush_site(const char *site)
{
    int     status;
    const char *errstr;
    uid_t   uid = getuid();

    if (uid != 0 && uid != var_owner_uid
 && (errstr = check_user_acl_byuid(var_flush_acl, uid)) != 0)
 msg_fatal_status(EX_NOPERM,
        "User %s(%ld) is not allowed to flush the mail queue",
    errstr, (long) uid);

    flush_init();

    switch (status = flush_send_site(site)) {
    case FLUSH_STAT_OK:
 exit(0);
    case FLUSH_STAT_BAD:
 msg_fatal_status(EX_USAGE, "Invalid request: \"%s\"", site);
    case FLUSH_STAT_FAIL:
 msg_fatal_status(EX_UNAVAILABLE,
    "Cannot flush mail queue - mail system is down");
    case FLUSH_STAT_DENY:
 msg_fatal_status(EX_UNAVAILABLE,
     "Flush service is not configured for destination \"%s\"",
    site);
    default:
 msg_fatal_status(EX_SOFTWARE,
    "Unknown flush server reply status %d", status);
    }
}

/* flush_file - flush mail with specific queue ID */

static void flush_file(const char *queue_id)
{
    int     status;
    const char *errstr;
    uid_t   uid = getuid();

    if (uid != 0 && uid != var_owner_uid
 && (errstr = check_user_acl_byuid(var_flush_acl, uid)) != 0)
 msg_fatal_status(EX_NOPERM,
        "User %s(%ld) is not allowed to flush the mail queue",
    errstr, (long) uid);

    switch (status = flush_send_file(queue_id)) {
    case FLUSH_STAT_OK:
 exit(0);
    case FLUSH_STAT_BAD:
 msg_fatal_status(EX_USAGE, "Invalid request: \"%s\"", queue_id);
    case FLUSH_STAT_FAIL:
 msg_fatal_status(EX_UNAVAILABLE,
    "Cannot flush mail queue - mail system is down");
    default:
 msg_fatal_status(EX_SOFTWARE,
    "Unexpected flush server reply status %d", status);
    }
}

/* unavailable - sanitize exit status from library run-time errors */

static void unavailable(void)
{
    exit(EX_UNAVAILABLE);
}

/* usage - scream and die */

static NORETURN usage(void)
{
    msg_fatal_status(EX_USAGE, "usage: postqueue -f | postqueue -i queueid | postqueue -p | postqueue -s site");
}

MAIL_VERSION_STAMP_DECLARE;

/* main - the main program */

int     main(int argc, char **argv)
{
    struct stat st;
    char   *slash;
    int     c;
    int     fd;
    int     mode = PQ_MODE_DEFAULT;
    char   *site_to_flush = 0;
    char   *id_to_flush = 0;
    ARGV   *import_env;
    int     bad_site;

    /*
     * Fingerprint executables and core dumps.
     */
    MAIL_VERSION_STAMP_ALLOCATE;

    /*
     * Be consistent with file permissions.
     */
    umask(022);

    /*
     * To minimize confusion, make sure that the standard file descriptors
     * are open before opening anything else. XXX Work around for 44BSD where
     * fstat can return EBADF on an open file descriptor.
     */
    for (fd = 0; fd < 3; fd++)
 if (fstat(fd, &st) == -1
     && (close(fd), open("/dev/null", O_RDWR, 0)) != fd)
     msg_fatal_status(EX_UNAVAILABLE, "open /dev/null: %m");

    /*
     * Initialize. Set up logging, read the global configuration file and
     * extract configuration information. Set up signal handlers so that we
     * can clean up incomplete output.
     */
    if ((slash = strrchr(argv[0], '/')) != 0 && slash[1])
 argv[0] = slash + 1;
    msg_vstream_init(argv[0], VSTREAM_ERR);
    msg_cleanup(unavailable);
    msg_syslog_init(mail_task("postqueue"), LOG_PID, LOG_FACILITY);
    set_mail_conf_str(VAR_PROCNAME, var_procname = mystrdup(argv[0]));

    /*
     * Parse JCL. This program is set-gid and must sanitize all command-line
     * parameters. The configuration directory argument is validated by the
     * mail configuration read routine. Don't do complex things until we have
     * completed initializations.
     */
    while ((c = GETOPT(argc, argv, "c:fi:ps:v")) > 0) {
 switch (c) {
 case 'c':    /* non-default configuration */
     if (setenv(CONF_ENV_PATH, optarg, 1) < 0)
  msg_fatal_status(EX_UNAVAILABLE, "out of memory");
     break;
 case 'f':    /* flush queue */
     if (mode != PQ_MODE_DEFAULT)
  usage();
     mode = PQ_MODE_FLUSH_QUEUE;
     break;
 case 'i':    /* flush queue file */
     if (mode != PQ_MODE_DEFAULT)
  usage();
     mode = PQ_MODE_FLUSH_FILE;
     id_to_flush = optarg;
     break;
 case 'p':    /* traditional mailq */
     if (mode != PQ_MODE_DEFAULT)
  usage();
     mode = PQ_MODE_MAILQ_LIST;
     break;
 case 's':    /* flush site */
     if (mode != PQ_MODE_DEFAULT)
  usage();
     mode = PQ_MODE_FLUSH_SITE;
     site_to_flush = optarg;
     break;
 case 'v':
     if (geteuid() == 0)
  msg_verbose++;
     break;
 default:
     usage();
 }
    }
    if (argc > optind)
 usage();

    /*
     * Further initialization...
     */
    mail_conf_read();
    if (strcmp(var_syslog_name, DEF_SYSLOG_NAME) != 0)
 msg_syslog_init(mail_task("postqueue"), LOG_PID, LOG_FACILITY);
    mail_dict_init();    /* proxy, sql, ldap */
    get_mail_conf_str_table(str_table);

    /*
     * This program is designed to be set-gid, which makes it a potential
     * target for attack. If not running as root, strip the environment so we
     * don't have to trust the C library. If running as root, don't strip the
     * environment so that showq can receive non-default configuration
     * directory info when the mail system is down.
     */
    if (geteuid() != 0) {
 import_env = argv_split(var_import_environ, ", \t\r\n");
 clean_env(import_env->argv);
 argv_free(import_env);
    }
    if (chdir(var_queue_dir))
 msg_fatal_status(EX_UNAVAILABLE, "chdir %s: %m", var_queue_dir);

    signal(SIGPIPE, SIG_IGN);

    /* End of initializations. */

    /*
     * Further input validation.
     */
    if (site_to_flush != 0) {
 bad_site = 0;
 if (*site_to_flush == '[') {
     bad_site = !valid_mailhost_literal(site_to_flush, DONT_GRIPE);
 } else {
     bad_site = !valid_hostname(site_to_flush, DONT_GRIPE);
 }
 if (bad_site)
     msg_fatal_status(EX_USAGE,
       "Cannot flush mail queue - invalid destination: \"%.100s%s\"",
     site_to_flush, strlen(site_to_flush) > 100 ? "..." : "");
    }
    if (id_to_flush != 0) {
 if (!mail_queue_id_ok(id_to_flush))
     msg_fatal_status(EX_USAGE,
         "Cannot flush queue ID - invalid name: \"%.100s%s\"",
         id_to_flush, strlen(id_to_flush) > 100 ? "..." : "");
    }

    /*
     * Start processing.
     */
    switch (mode) {
    default:
 msg_panic("unknown operation mode: %d", mode);
 /* NOTREACHED */
    case PQ_MODE_MAILQ_LIST:
 show_queue();
 exit(0);
 break;
    case PQ_MODE_FLUSH_SITE:
 flush_site(site_to_flush);
 exit(0);
 break;
    case PQ_MODE_FLUSH_FILE:
 flush_file(id_to_flush);
 exit(0);
 break;
    case PQ_MODE_FLUSH_QUEUE:
 flush_queue();
 exit(0);
 break;
    case PQ_MODE_DEFAULT:
 usage();
 /* NOTREACHED */
    }
}

//-----------------------------------
// pmgr
//-----------------------------------

/*++



























































































































































/* COMPATIBILITY CONTROLS
/* .ad
/* .fi
/* Available before Postfix version 2.5:
/* .IP "\fBallow_min_user (no)\fR"
/* Allow a sender or recipient address to have `-' as the first
/* character.
/* ACTIVE QUEUE CONTROLS
/* .ad
/* .fi
/* .IP "\fBqmgr_clog_warn_time (300s)\fR"
/* The minimal delay between warnings that a specific destination is
/* clogging up the Postfix active queue.
/* .IP "\fBqmgr_message_active_limit (20000)\fR"
/* The maximal number of messages in the active queue.
/* .IP "\fBqmgr_message_recipient_limit (20000)\fR"
/* The maximal number of recipients held in memory by the Postfix
/* queue manager, and the maximal size of the size of the short-term,
/* in-memory "dead" destination status cache.
/* .IP "\fBqmgr_message_recipient_minimum (10)\fR"
/* The minimal number of in-memory recipients for any message.
/* .IP "\fBdefault_recipient_limit (20000)\fR"
/* The default per-transport upper limit on the number of in-memory
/* recipients.
/* .IP "\fItransport\fB_recipient_limit ($default_recipient_limit)\fR"
/* Idem, for delivery via the named message \fItransport\fR.
/* .IP "\fBdefault_extra_recipient_limit (1000)\fR"
/* The default value for the extra per-transport limit imposed on the
/* number of in-memory recipients.
/* .IP "\fItransport\fB_extra_recipient_limit ($default_extra_recipient_limit)\fR"
/* Idem, for delivery via the named message \fItransport\fR.
/* .PP
/* Available in Postfix version 2.4 and later:
/* .IP "\fBdefault_recipient_refill_limit (100)\fR"
/* The default per-transport limit on the number of recipients refilled at
/* once.
/* .IP "\fItransport\fB_recipient_refill_limit ($default_recipient_refill_limit)\fR"
/* Idem, for delivery via the named message \fItransport\fR.
/* .IP "\fBdefault_recipient_refill_delay (5s)\fR"
/* The default per-transport maximum delay between recipients refills.
/* .IP "\fItransport\fB_recipient_refill_delay ($default_recipient_refill_delay)\fR"
/* Idem, for delivery via the named message \fItransport\fR.
/* DELIVERY CONCURRENCY CONTROLS
/* .ad
/* .fi
/* .IP "\fBinitial_destination_concurrency (5)\fR"
/* The initial per-destination concurrency level for parallel delivery
/* to the same destination.
/* .IP "\fBdefault_destination_concurrency_limit (20)\fR"
/* The default maximal number of parallel deliveries to the same
/* destination.
/* .IP "\fItransport\fB_destination_concurrency_limit ($default_destination_concurrency_limit)\fR"
/* Idem, for delivery via the named message \fItransport\fR.
/* .PP
/* Available in Postfix version 2.5 and later:
/* .IP "\fItransport\fB_initial_destination_concurrency ($initial_destination_concurrency)\fR"
/* Initial concurrency for delivery via the named message
/* \fItransport\fR.
/* .IP "\fBdefault_destination_concurrency_failed_cohort_limit (1)\fR"
/* How many pseudo-cohorts must suffer connection or handshake
/* failure before a specific destination is considered unavailable
/* (and further delivery is suspended).
/* .IP "\fItransport\fB_destination_concurrency_failed_cohort_limit ($default_destination_concurrency_failed_cohort_limit)\fR"
/* Idem, for delivery via the named message \fItransport\fR.
/* .IP "\fBdefault_destination_concurrency_negative_feedback (1)\fR"
/* The per-destination amount of delivery concurrency negative
/* feedback, after a delivery completes with a connection or handshake
/* failure.
/* .IP "\fItransport\fB_destination_concurrency_negative_feedback ($default_destination_concurrency_negative_feedback)\fR"
/* Idem, for delivery via the named message \fItransport\fR.
/* .IP "\fBdefault_destination_concurrency_positive_feedback (1)\fR"
/* The per-destination amount of delivery concurrency positive
/* feedback, after a delivery completes without connection or handshake
/* failure.
/* .IP "\fItransport\fB_destination_concurrency_positive_feedback ($default_destination_concurrency_positive_feedback)\fR"
/* Idem, for delivery via the named message \fItransport\fR.
/* .IP "\fBdestination_concurrency_feedback_debug (no)\fR"
/* Make the queue manager's feedback algorithm verbose for performance
/* analysis purposes.
/* RECIPIENT SCHEDULING CONTROLS
/* .ad
/* .fi
/* .IP "\fBdefault_destination_recipient_limit (50)\fR"
/* The default maximal number of recipients per message delivery.
/* .IP "\fItransport\fB_destination_recipient_limit ($default_destination_recipient_limit)\fR"
/* Idem, for delivery via the named message \fItransport\fR.
/* MESSAGE SCHEDULING CONTROLS
/* .ad
/* .fi
/* .IP "\fBdefault_delivery_slot_cost (5)\fR"
/* How often the Postfix queue manager's scheduler is allowed to
/* preempt delivery of one message with another.
/* .IP "\fItransport\fB_delivery_slot_cost ($default_delivery_slot_cost)\fR"
/* Idem, for delivery via the named message \fItransport\fR.
/* .IP "\fBdefault_minimum_delivery_slots (3)\fR"
/* How many recipients a message must have in order to invoke the
/* Postfix queue manager's scheduling algorithm at all.
/* .IP "\fItransport\fB_minimum_delivery_slots ($default_minimum_delivery_slots)\fR"
/* Idem, for delivery via the named message \fItransport\fR.
/* .IP "\fBdefault_delivery_slot_discount (50)\fR"
/* The default value for transport-specific _delivery_slot_discount
/* settings.
/* .IP "\fItransport\fB_delivery_slot_discount ($default_delivery_slot_discount)\fR"
/* Idem, for delivery via the named message \fItransport\fR.
/* .IP "\fBdefault_delivery_slot_loan (3)\fR"
/* The default value for transport-specific _delivery_slot_loan
/* settings.
/* .IP "\fItransport\fB_delivery_slot_loan ($default_delivery_slot_loan)\fR"
/* Idem, for delivery via the named message \fItransport\fR.
/* OTHER RESOURCE AND RATE CONTROLS
/* .ad
/* .fi
/* .IP "\fBminimal_backoff_time (300s)\fR"
/* The minimal time between attempts to deliver a deferred message;
/* prior to Postfix 2.4 the default value was 1000s.
/* .IP "\fBmaximal_backoff_time (4000s)\fR"
/* The maximal time between attempts to deliver a deferred message.
/* .IP "\fBmaximal_queue_lifetime (5d)\fR"
/* The maximal time a message is queued before it is sent back as
/* undeliverable.
/* .IP "\fBqueue_run_delay (300s)\fR"
/* The time between deferred queue scans by the queue manager;
/* prior to Postfix 2.4 the default value was 1000s.
/* .IP "\fBtransport_retry_time (60s)\fR"
/* The time between attempts by the Postfix queue manager to contact
/* a malfunctioning message delivery transport.
/* .PP
/* Available in Postfix version 2.1 and later:
/* .IP "\fBbounce_queue_lifetime (5d)\fR"
/* The maximal time a bounce message is queued before it is considered
/* undeliverable.
/* .PP
/* Available in Postfix version 2.5 and later:
/* .IP "\fBdefault_destination_rate_delay (0s)\fR"
/* The default amount of delay that is inserted between individual
/* deliveries to the same destination; with per-destination recipient
/* limit > 1, a destination is a domain, otherwise it is a recipient.
/* .IP "\fItransport\fB_destination_rate_delay $default_destination_rate_delay
/* Idem, for delivery via the named message \fItransport\fR.
/* MISCELLANEOUS CONTROLS
/* .ad
/* .fi
/* .IP "\fBconfig_directory (see 'postconf -d' output)\fR"
/* The default location of the Postfix main.cf and master.cf
/* configuration files.
/* .IP "\fBdefer_transports (empty)\fR"
/* The names of message delivery transports that should not deliver mail
/* unless someone issues "\fBsendmail -q\fR" or equivalent.
/* .IP "\fBdelay_logging_resolution_limit (2)\fR"
/* The maximal number of digits after the decimal point when logging
/* sub-second delay values.
/* .IP "\fBhelpful_warnings (yes)\fR"
/* Log warnings about problematic configuration settings, and provide
/* helpful suggestions.
/* .IP "\fBipc_timeout (3600s)\fR"
/* The time limit for sending or receiving information over an internal
/* communication channel.
/* .IP "\fBprocess_id (read-only)\fR"
/* The process ID of a Postfix command or daemon process.
/* .IP "\fBprocess_name (read-only)\fR"
/* The process name of a Postfix command or daemon process.
/* .IP "\fBqueue_directory (see 'postconf -d' output)\fR"
/* The location of the Postfix top-level queue directory.
/* .IP "\fBsyslog_facility (mail)\fR"
/* The syslog facility of Postfix logging.
/* .IP "\fBsyslog_name (see 'postconf -d' output)\fR"
/* The mail system name that is prepended to the process name in syslog
/* records, so that "smtpd" becomes, for example, "postfix/smtpd".
/* FILES
/* /var/spool/postfix/incoming, incoming queue
/* /var/spool/postfix/active, active queue
/* /var/spool/postfix/deferred, deferred queue
/* /var/spool/postfix/bounce, non-delivery status
/* /var/spool/postfix/defer, non-delivery status
/* /var/spool/postfix/trace, delivery status
/* SEE ALSO
/* trivial-rewrite(8), address routing
/* bounce(8), delivery status reports
/* postconf(5), configuration parameters
/* master(5), generic daemon options
/* master(8), process manager
/* syslogd(8), system logging
/* README FILES
/* .ad
/* .fi
/* Use "\fBpostconf readme_directory\fR" or
/* "\fBpostconf html_directory\fR" to locate this information.
/* .na
/* .nf
/* SCHEDULER_README, scheduling algorithm
/* QSHAPE_README, Postfix queue analysis
/* LICENSE
/* .ad
/* .fi
/* The Secure Mailer license must be distributed with this software.
/* AUTHOR(S)
/* Wietse Venema
/* IBM T.J. Watson Research
/* P.O. Box 704
/* Yorktown Heights, NY 10598, USA
/*
/* Preemptive scheduler enhancements:
/* Patrik Rak
/* Modra 6
/* 155 00, Prague, Czech Republic
/*--*/

/* System library. */

#include <sys_defs.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

/* Utility library. */

#include <msg.h>
#include <events.h>
#include <vstream.h>
#include <dict.h>

/* Global library. */

#include <mail_queue.h>
#include <recipient_list.h>
#include <mail_conf.h>
#include <mail_params.h>
#include <mail_version.h>
#include <mail_proto.h>   /* QMGR_SCAN constants */
#include <mail_flow.h>
#include <flush_clnt.h>

/* Master process interface */

#include <master_proto.h>
#include <mail_server.h>

/* Application-specific. */

#include "qmgr.h"

 /*
  * Tunables.
  */
int     var_queue_run_delay;
int     var_min_backoff_time;
int     var_max_backoff_time;
int     var_max_queue_time;
int     var_dsn_queue_time;
int     var_qmgr_active_limit;
int     var_qmgr_rcpt_limit;
int     var_qmgr_msg_rcpt_limit;
int     var_xport_rcpt_limit;
int     var_stack_rcpt_limit;
int     var_xport_refill_limit;
int     var_xport_refill_delay;
int     var_delivery_slot_cost;
int     var_delivery_slot_loan;
int     var_delivery_slot_discount;
int     var_min_delivery_slots;
int     var_init_dest_concurrency;
int     var_transport_retry_time;
int     var_dest_con_limit;
int     var_dest_rcpt_limit;
char   *var_defer_xports;
int     var_local_con_lim;
int     var_local_rcpt_lim;
int     var_proc_limit;
bool    var_verp_bounce_off;
int     var_qmgr_clog_warn_time;
char   *var_conc_pos_feedback;
char   *var_conc_neg_feedback;
int     var_conc_cohort_limit;
int     var_conc_feedback_debug;
int     var_dest_rate_delay;

static QMGR_SCAN *qmgr_scans[2];

#define QMGR_SCAN_IDX_INCOMING 0
#define QMGR_SCAN_IDX_DEFERRED 1
#define QMGR_SCAN_IDX_COUNT (sizeof(qmgr_scans) / sizeof(qmgr_scans[0]))

/* qmgr_deferred_run_event - queue manager heartbeat */

static void qmgr_deferred_run_event(int unused_event, char *dummy)
{

    /*
     * This routine runs when it is time for another deferred queue scan.
     * Make sure this routine gets called again in the future.
     */
    qmgr_scan_request(qmgr_scans[QMGR_SCAN_IDX_DEFERRED], QMGR_SCAN_START);
    event_request_timer(qmgr_deferred_run_event, dummy, var_queue_run_delay);
}

/* qmgr_trigger_event - respond to external trigger(s) */

static void qmgr_trigger_event(char *buf, int len,
                  char *unused_service, char **argv)
{
    int     incoming_flag = 0;
    int     deferred_flag = 0;
    int     i;

    /*
     * Sanity check. This service takes no command-line arguments.
     */
    if (argv[0])
 msg_fatal("unexpected command-line argument: %s", argv[0]);

    /*
     * Collapse identical requests that have arrived since we looked last
     * time. There is no client feedback so there is no need to process each
     * request in order. And as long as we don't have conflicting requests we
     * are free to sort them into the most suitable order.
     */
#define QMGR_FLUSH_BEFORE (QMGR_FLUSH_ONCE | QMGR_FLUSH_DFXP)

    for (i = 0; i < len; i++) {
 if (msg_verbose)
     msg_info("request: %d (%c)",
       buf[i], ISALNUM(buf[i]) ? buf[i] : '?');
 switch (buf[i]) {
 case TRIGGER_REQ_WAKEUP:
 case QMGR_REQ_SCAN_INCOMING:
     incoming_flag |= QMGR_SCAN_START;
     break;
 case QMGR_REQ_SCAN_DEFERRED:
     deferred_flag |= QMGR_SCAN_START;
     break;
 case QMGR_REQ_FLUSH_DEAD:
     deferred_flag |= QMGR_FLUSH_BEFORE;
     incoming_flag |= QMGR_FLUSH_BEFORE;
     break;
 case QMGR_REQ_SCAN_ALL:
     deferred_flag |= QMGR_SCAN_ALL;
     incoming_flag |= QMGR_SCAN_ALL;
     break;
 default:
     if (msg_verbose)
  msg_info("request ignored");
     break;
 }
    }

    /*
     * Process each request type at most once. Modifiers take effect upon the
     * next queue run. If no queue run is in progress, and a queue scan is
     * requested, the request takes effect immediately.
     */
    if (incoming_flag != 0)
 qmgr_scan_request(qmgr_scans[QMGR_SCAN_IDX_INCOMING], incoming_flag);
    if (deferred_flag != 0)
 qmgr_scan_request(qmgr_scans[QMGR_SCAN_IDX_DEFERRED], deferred_flag);
}

/* qmgr_loop - queue manager main loop */

static int qmgr_loop(char *unused_name, char **unused_argv)
{
    char   *path;
    int     token_count;
    int     feed = 0;
    int     scan_idx;   /* Priority order scan index */
    static int first_scan_idx = QMGR_SCAN_IDX_INCOMING;
    int     last_scan_idx = QMGR_SCAN_IDX_COUNT - 1;
    int     delay;

    /*
     * This routine runs as part of the event handling loop, after the event
     * manager has delivered a timer or I/O event (including the completion
     * of a connection to a delivery process), or after it has waited for a
     * specified amount of time. The result value of qmgr_loop() specifies
     * how long the event manager should wait for the next event.
     */
#define DONT_WAIT 0
#define WAIT_FOR_EVENT (-1)

    /*
     * Attempt to drain the active queue by allocating a suitable delivery
     * process and by delivering mail via it. Delivery process allocation and
     * mail delivery are asynchronous.
     */
    qmgr_active_drain();

    /*
     * Let some new blood into the active queue when the queue size is
     * smaller than some configurable limit.
     * 
     * We import one message per interrupt, to optimally tune the input count
     * for the number of delivery agent protocol wait states, as explained in
     * qmgr_transport.c.
     */
    delay = WAIT_FOR_EVENT;
    for (scan_idx = 0; qmgr_message_count < var_qmgr_active_limit
  && scan_idx < QMGR_SCAN_IDX_COUNT; ++scan_idx) {
 last_scan_idx = (scan_idx + first_scan_idx) % QMGR_SCAN_IDX_COUNT;
 if ((path = qmgr_scan_next(qmgr_scans[last_scan_idx])) != 0) {
     delay = DONT_WAIT;
     if ((feed = qmgr_active_feed(qmgr_scans[last_scan_idx], path)) != 0)
  break;
 }
    }

    /*
     * Round-robin the queue scans. When the active queue becomes full,
     * prefer new mail over deferred mail.
     */
    if (qmgr_message_count < var_qmgr_active_limit) {
 first_scan_idx = (last_scan_idx + 1) % QMGR_SCAN_IDX_COUNT;
    } else if (first_scan_idx != QMGR_SCAN_IDX_INCOMING) {
 first_scan_idx = QMGR_SCAN_IDX_INCOMING;
    }

    /*
     * Global flow control. If enabled, slow down receiving processes that
     * get ahead of the queue manager, but don't block them completely.
     */
    if (var_in_flow_delay > 0) {
 token_count = mail_flow_count();
 if (token_count < var_proc_limit) {
     if (feed != 0 && last_scan_idx == QMGR_SCAN_IDX_INCOMING)
  mail_flow_put(1);
     else if (qmgr_scans[QMGR_SCAN_IDX_INCOMING]->handle == 0)
  mail_flow_put(var_proc_limit - token_count);
 } else if (token_count > var_proc_limit) {
     mail_flow_get(token_count - var_proc_limit);
 }
    }
    return (delay);
}

/* pre_accept - see if tables have changed */

static void pre_accept(char *unused_name, char **unused_argv)
{
    const char *table;

    if ((table = dict_changed_name()) != 0) {
 msg_info("table %s has changed -- restarting", table);
 exit(0);
    }
}

/* qmgr_pre_init - pre-jail initialization */

static void qmgr_pre_init(char *unused_name, char **unused_argv)
{
    flush_init();
}

/* qmgr_post_init - post-jail initialization */

static void qmgr_post_init(char *name, char **unused_argv)
{

    /*
     * Backwards compatibility.
     */
    if (strcmp(var_procname, "nqmgr") == 0) {
 msg_warn("please update the %s/%s file; the new queue manager",
   var_config_dir, MASTER_CONF_FILE);
 msg_warn("(old name: nqmgr) has become the standard queue manager (new name: qmgr)");
 msg_warn("support for the name old name (nqmgr) will be removed from Postfix");
    }

    /*
     * Sanity check.
     */
    if (var_qmgr_rcpt_limit < var_qmgr_active_limit) {
 msg_warn("%s is smaller than %s - adjusting %s",
       VAR_QMGR_RCPT_LIMIT, VAR_QMGR_ACT_LIMIT, VAR_QMGR_RCPT_LIMIT);
 var_qmgr_rcpt_limit = var_qmgr_active_limit;
    }
    if (var_dsn_queue_time > var_max_queue_time) {
 msg_warn("%s is larger than %s - adjusting %s",
   VAR_DSN_QUEUE_TIME, VAR_MAX_QUEUE_TIME, VAR_DSN_QUEUE_TIME);
 var_dsn_queue_time = var_max_queue_time;
    }

    /*
     * This routine runs after the skeleton code has entered the chroot jail.
     * Prevent automatic process suicide after a limited number of client
     * requests or after a limited amount of idle time. Move any left-over
     * entries from the active queue to the incoming queue, and give them a
     * time stamp into the future, in order to allow ongoing deliveries to
     * finish first. Start scanning the incoming and deferred queues.
     * Left-over active queue entries are moved to the incoming queue because
     * the incoming queue has priority; moving left-overs to the deferred
     * queue could cause anomalous delays when "postfix reload/start" are
     * issued often.
     */
    var_use_limit = 0;
    var_idle_limit = 0;
    qmgr_move(MAIL_QUEUE_ACTIVE, MAIL_QUEUE_INCOMING, event_time());
    qmgr_scans[QMGR_SCAN_IDX_INCOMING] = qmgr_scan_create(MAIL_QUEUE_INCOMING);
    qmgr_scans[QMGR_SCAN_IDX_DEFERRED] = qmgr_scan_create(MAIL_QUEUE_DEFERRED);
    qmgr_scan_request(qmgr_scans[QMGR_SCAN_IDX_INCOMING], QMGR_SCAN_START);
    qmgr_deferred_run_event(0, (char *) 0);
}

MAIL_VERSION_STAMP_DECLARE;

/* main - the main program */

int     main(int argc, char **argv)
{
    static const CONFIG_STR_TABLE str_table[] = {
 VAR_DEFER_XPORTS, DEF_DEFER_XPORTS, &var_defer_xports, 0, 0,
 VAR_CONC_POS_FDBACK, DEF_CONC_POS_FDBACK, &var_conc_pos_feedback, 1, 0,
 VAR_CONC_NEG_FDBACK, DEF_CONC_NEG_FDBACK, &var_conc_neg_feedback, 1, 0,
 0,
    };
    static const CONFIG_TIME_TABLE time_table[] = {
 VAR_QUEUE_RUN_DELAY, DEF_QUEUE_RUN_DELAY, &var_queue_run_delay, 1, 0,
 VAR_MIN_BACKOFF_TIME, DEF_MIN_BACKOFF_TIME, &var_min_backoff_time, 1, 0,
 VAR_MAX_BACKOFF_TIME, DEF_MAX_BACKOFF_TIME, &var_max_backoff_time, 1, 0,
 VAR_MAX_QUEUE_TIME, DEF_MAX_QUEUE_TIME, &var_max_queue_time, 0, 8640000,
 VAR_DSN_QUEUE_TIME, DEF_DSN_QUEUE_TIME, &var_dsn_queue_time, 0, 8640000,
 VAR_XPORT_RETRY_TIME, DEF_XPORT_RETRY_TIME, &var_transport_retry_time, 1, 0,
 VAR_QMGR_CLOG_WARN_TIME, DEF_QMGR_CLOG_WARN_TIME, &var_qmgr_clog_warn_time, 0, 0,
 VAR_XPORT_REFILL_DELAY, DEF_XPORT_REFILL_DELAY, &var_xport_refill_delay, 1, 0,
 VAR_DEST_RATE_DELAY, DEF_DEST_RATE_DELAY, &var_dest_rate_delay, 0, 0,
 0,
    };
    static const CONFIG_INT_TABLE int_table[] = {
 VAR_QMGR_ACT_LIMIT, DEF_QMGR_ACT_LIMIT, &var_qmgr_active_limit, 1, 0,
 VAR_QMGR_RCPT_LIMIT, DEF_QMGR_RCPT_LIMIT, &var_qmgr_rcpt_limit, 1, 0,
 VAR_QMGR_MSG_RCPT_LIMIT, DEF_QMGR_MSG_RCPT_LIMIT, &var_qmgr_msg_rcpt_limit, 1, 0,
 VAR_XPORT_RCPT_LIMIT, DEF_XPORT_RCPT_LIMIT, &var_xport_rcpt_limit, 0, 0,
 VAR_STACK_RCPT_LIMIT, DEF_STACK_RCPT_LIMIT, &var_stack_rcpt_limit, 0, 0,
 VAR_XPORT_REFILL_LIMIT, DEF_XPORT_REFILL_LIMIT, &var_xport_refill_limit, 1, 0,
 VAR_DELIVERY_SLOT_COST, DEF_DELIVERY_SLOT_COST, &var_delivery_slot_cost, 0, 0,
 VAR_DELIVERY_SLOT_LOAN, DEF_DELIVERY_SLOT_LOAN, &var_delivery_slot_loan, 0, 0,
 VAR_DELIVERY_SLOT_DISCOUNT, DEF_DELIVERY_SLOT_DISCOUNT, &var_delivery_slot_discount, 0, 100,
 VAR_MIN_DELIVERY_SLOTS, DEF_MIN_DELIVERY_SLOTS, &var_min_delivery_slots, 0, 0,
 VAR_INIT_DEST_CON, DEF_INIT_DEST_CON, &var_init_dest_concurrency, 1, 0,
 VAR_DEST_CON_LIMIT, DEF_DEST_CON_LIMIT, &var_dest_con_limit, 0, 0,
 VAR_DEST_RCPT_LIMIT, DEF_DEST_RCPT_LIMIT, &var_dest_rcpt_limit, 0, 0,
 VAR_LOCAL_RCPT_LIMIT, DEF_LOCAL_RCPT_LIMIT, &var_local_rcpt_lim, 0, 0,
 VAR_LOCAL_CON_LIMIT, DEF_LOCAL_CON_LIMIT, &var_local_con_lim, 0, 0,
 VAR_PROC_LIMIT, DEF_PROC_LIMIT, &var_proc_limit, 1, 0,
 VAR_CONC_COHORT_LIM, DEF_CONC_COHORT_LIM, &var_conc_cohort_limit, 0, 0,
 0,
    };
    static const CONFIG_BOOL_TABLE bool_table[] = {
 VAR_VERP_BOUNCE_OFF, DEF_VERP_BOUNCE_OFF, &var_verp_bounce_off,
 VAR_CONC_FDBACK_DEBUG, DEF_CONC_FDBACK_DEBUG, &var_conc_feedback_debug,
 0,
    };

    /*
     * Fingerprint executables and core dumps.
     */
    MAIL_VERSION_STAMP_ALLOCATE;

    /*
     * Use the trigger service skeleton, because no-one else should be
     * monitoring our service port while this process runs, and because we do
     * not talk back to the client.
     */
    trigger_server_main(argc, argv, qmgr_trigger_event,
   MAIL_SERVER_INT_TABLE, int_table,
   MAIL_SERVER_STR_TABLE, str_table,
   MAIL_SERVER_BOOL_TABLE, bool_table,
   MAIL_SERVER_TIME_TABLE, time_table,
   MAIL_SERVER_PRE_INIT, qmgr_pre_init,
   MAIL_SERVER_POST_INIT, qmgr_post_init,
   MAIL_SERVER_LOOP, qmgr_loop,
   MAIL_SERVER_PRE_ACCEPT, pre_accept,
   MAIL_SERVER_SOLITARY,
   0);
}

```
