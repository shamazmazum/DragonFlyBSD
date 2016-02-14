/*
 * Copyright (c) 1983, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * @(#) Copyright (c) 1983, 1993 The Regents of the University of California.  All rights reserved.
 * @(#)tip.c	8.1 (Berkeley) 6/6/93
 * $FreeBSD: src/usr.bin/tip/tip/tip.c,v 1.12.2.2 2001/06/02 08:08:24 phk Exp $
 */

/*
	Forward declarations
*/
void ttysetup (int speed);

/*
 * tip - UNIX link to other systems
 *  tip [-v] [-speed] system-name
 * or
 *  cu phone-number [-s speed] [-l line] [-a acu]
 */

#include <err.h>
#include <errno.h>
#include <sys/types.h>
#include <libutil.h>
#include "tip.h"
#include "pathnames.h"

static void	intprompt(int);
static void	killchild(void);
static void	tipdone(int);
static char	*sname(char *);
char	PNbuf[256];			/* This limits the size of a number */

static void usage(void);
void setparity(char *);
void xpwrite(int, char *, int);
char escape(void);
void tipin(void);
int prompt(char *, char *, size_t);
void unraw(void);
void shell_uid(void);
void daemon_uid(void);
void user_uid(void);

int
main(int argc, char *argv[])
{
	char *system = NULL;
	int i;
	char *p;
	char sbuf[12];

	gid = getgid();
	egid = getegid();
	uid = getuid();
	euid = geteuid();

	if (equal(sname(argv[0]), "cu")) {
		cumode = 1;
		cumain(argc, argv);
		goto cucommon;
	}

	if (argc > 4)
		usage();
	if (!isatty(0))
		errx(1, "must be interactive");

	for (; argc > 1; argv++, argc--) {
		if (argv[1][0] != '-')
			system = argv[1];
		else switch (argv[1][1]) {

		case 'v':
			vflag++;
			break;

		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			BR = atoi(&argv[1][1]);
			break;

		default:
			warnx("%s, unknown option", argv[1]);
			break;
		}
	}

	if (system == NULL)
		goto notnumber;
	if (isalpha(*system))
		goto notnumber;
	/*
	 * System name is really a phone number...
	 * Copy the number then stomp on the original (in case the number
	 *	is private, we don't want 'ps' or 'w' to find it).
	 */
	if (strlen(system) > sizeof(PNbuf) - 1)
		errx(1, "phone number too long (max = %zd bytes)", sizeof PNbuf - 1);
	strncpy(PNbuf, system, sizeof(PNbuf) - 1);
	for (p = system; *p; p++)
		*p = '\0';
	PN = PNbuf;
	(void)snprintf(sbuf, sizeof(sbuf), "tip%ld", BR);
	system = sbuf;

notnumber:
	(void)signal(SIGINT, cleanup);
	(void)signal(SIGQUIT, cleanup);
	(void)signal(SIGHUP, cleanup);
	(void)signal(SIGTERM, cleanup);
	(void)signal(SIGUSR1, tipdone);

	if ((i = hunt(system)) == 0) {
		printf("all ports busy\n");
		exit(3);
	}
	if (i == -1) {
		printf("link down\n");
		(void)uu_unlock(uucplock);
		exit(3);
	}
	setbuf(stdout, NULL);
	loginit();

	/*
	 * Kludge, their's no easy way to get the initialization
	 *   in the right order, so force it here
	 */
	if ((PH = getenv("PHONES")) == NULL)
		PH = _PATH_PHONES;
	vinit();				/* init variables */
	setparity("even");			/* set the parity table */
	if ((i = speed(number(value(BAUDRATE)))) == 0) {
		printf("tip: bad baud rate %d\n", number(value(BAUDRATE)));
		(void)uu_unlock(uucplock);
		exit(3);
	}

	/*
	 * Now that we have the logfile and the ACU open
	 *  return to the real uid and gid.  These things will
	 *  be closed on exit.  Swap real and effective uid's
	 *  so we can get the original permissions back
	 *  for removing the uucp lock.
	 */
	user_uid();

	/*
	 * Hardwired connections require the
	 *  line speed set before they make any transmissions
	 *  (this is particularly true of things like a DF03-AC)
	 */
	if (HW)
		ttysetup(i);
	if ((p = connect())) {
		printf("\07%s\n[EOT]\n", p);
		daemon_uid();
		(void)uu_unlock(uucplock);
		exit(1);
	}
	if (!HW)
		ttysetup(i);
cucommon:
	/*
	 * From here down the code is shared with
	 * the "cu" version of tip.
	 */

	tcgetattr (0, &otermios);
	ctermios = otermios;
	ctermios.c_iflag = (IMAXBEL|IXANY|ISTRIP|IXON|BRKINT);
	ctermios.c_lflag = (PENDIN|IEXTEN|ISIG|ECHOCTL|ECHOE|ECHOKE);
	ctermios.c_cflag = (CLOCAL|HUPCL|CREAD|CS8);
	ctermios.c_cc[VINTR] = 	ctermios.c_cc[VQUIT] = -1;
	ctermios.c_cc[VSUSP] = ctermios.c_cc[VDSUSP] = ctermios.c_cc[VDISCARD] =
		ctermios.c_cc[VLNEXT] = -1;
	raw();

	pipe(fildes); pipe(repdes);
	(void)signal(SIGALRM, timeoutfunc);

	/*
	 * Everything's set up now:
	 *	connection established (hardwired or dialup)
	 *	line conditioned (baud rate, mode, etc.)
	 *	internal data structures (variables)
	 * so, fork one process for local side and one for remote.
	 */
	printf(cumode ? "Connected\r\n" : "\07connected\r\n");

	if (LI != NULL && tiplink (LI, 0) != 0) {
		tipabort ("login failed");
	}

	if ((pid = fork()))
		tipin();
	else
		tipout();
	/*NOTREACHED*/
}

static void
usage(void)
{
	fprintf(stderr, "usage: tip [-v] [-speed] [system-name]\n");
	exit(1);
}

void
killchild(void)
{
	if (pid != 0) {
		kill(pid, SIGTERM);
		pid = 0;
	}
}

void
cleanup(int signo)
{

	daemon_uid();
	(void)uu_unlock(uucplock);
	exit(0);
}

void
tipdone(int signo)
{
	tipabort("Hangup.");
}
/*
 * Muck with user ID's.  We are setuid to the owner of the lock
 * directory when we start.  user_uid() reverses real and effective
 * ID's after startup, to run with the user's permissions.
 * daemon_uid() switches back to the privileged uid for unlocking.
 * Finally, to avoid running a shell with the wrong real uid,
 * shell_uid() sets real and effective uid's to the user's real ID.
 */
static int uidswapped;

void
user_uid(void)
{
	if (uidswapped == 0) {
		seteuid(uid);
		uidswapped = 1;
	}
}

void
daemon_uid(void)
{
	if (uidswapped) {
		seteuid(euid);
		uidswapped = 0;
	}
}

void
shell_uid(void)
{
	setegid(gid);
	seteuid(uid);
}

/*
 * put the controlling keyboard into raw mode
 */
void
raw(void)
{
	tcsetattr (0, TCSANOW, &ctermios);
}


/*
 * return keyboard to normal mode
 */
void
unraw(void)
{
	tcsetattr (0, TCSANOW, &otermios);
}

static	jmp_buf promptbuf;

/*
 * Print string ``s'', then read a string
 *  in from the terminal.  Handles signals & allows use of
 *  normal erase and kill characters.
 */
int
prompt(char *s, char *p, size_t sz)
{
	char *b = p;
	sig_t oint, oquit;

	stoprompt = 0;
	oint = signal(SIGINT, intprompt);
	oquit = signal(SIGQUIT, SIG_IGN);
	unraw();
	printf("%s", s);
	if (setjmp(promptbuf) == 0)
		while ((*p = getchar()) != EOF && *p != '\n' && --sz > 0)
			p++;
	*p = '\0';

	raw();
	(void)signal(SIGINT, oint);
	(void)signal(SIGQUIT, oquit);
	return (stoprompt || p == b);
}

/*
 * Interrupt service routine during prompting
 */
void
intprompt(int signo)
{

	(void)signal(SIGINT, SIG_IGN);
	stoprompt = 1;
	printf("\r\n");
	longjmp(promptbuf, 1);
}

/*
 * ****TIPIN   TIPIN****
 */
void
tipin(void)
{
	int i;
	char gch, bol = 1;

	atexit(killchild);

	/*
	 * Kinda klugey here...
	 *   check for scripting being turned on from the .tiprc file,
	 *   but be careful about just using setscript(), as we may
	 *   send a SIGEMT before tipout has a chance to set up catching
	 *   it; so wait a second, then setscript()
	 */
	if (boolean(value(SCRIPT))) {
		sleep(1);
		setscript();
	}

	while (1) {
		i = getchar();
		if (i == EOF)
			break;
		gch = i&0177;
		if ((gch == character(value(ESCAPE))) && bol) {
			if (!(gch = escape()))
				continue;
		} else if (!cumode && gch == character(value(RAISECHAR))) {
			boolean(value(RAISE)) = !boolean(value(RAISE));
			continue;
		} else if (gch == '\r') {
			bol = 1;
			xpwrite(FD, &gch, 1);
			if (boolean(value(HALFDUPLEX)))
				printf("\r\n");
			continue;
		} else if (!cumode && gch == character(value(FORCE))) {
			i = getchar();
			if (i == EOF)
				break;
			gch = i & 0177;
		}
		bol = any(gch, value(EOL));
		if (boolean(value(RAISE)) && islower(gch))
			gch = toupper(gch);
		xpwrite(FD, &gch, 1);
		if (boolean(value(HALFDUPLEX)))
			printf("%c", gch);
	}
}

extern esctable_t etable[];

/*
 * Escape handler --
 *  called on recognition of ``escapec'' at the beginning of a line
 */
char
escape(void)
{
	char gch;
	esctable_t *p;
	char c = character(value(ESCAPE));
	int i;

	i = getchar();
	if (i == EOF)
		return 0;
	gch = (i&0177);
	for (p = etable; p->e_char; p++)
		if (p->e_char == gch) {
			if ((p->e_flags&PRIV) && uid)
				continue;
			printf("%s", ctrl(c));
			(*p->e_func)(gch);
			return (0);
		}
	/* ESCAPE ESCAPE forces ESCAPE */
	if (c != gch)
		xpwrite(FD, &c, 1);
	return (gch);
}

int
speed(int n)
{
	return (n);
}

int
any(char c, char *p)
{
	while (p && *p)
		if (*p++ == c)
			return (1);
	return (0);
}

int
size(char *s)
{
	int i = 0;

	while (s && *s++)
		i++;
	return (i);
}

char *
interp(char *s)
{
	static char buf[256];
	char *p = buf, c, *q;

	while ((c = *s++)) {
		for (q = "\nn\rr\tt\ff\033E\bb"; *q; q++)
			if (*q++ == c) {
				*p++ = '\\'; *p++ = *q;
				goto next;
			}
		if (c < 040) {
			*p++ = '^'; *p++ = c + 'A'-1;
		} else if (c == 0177) {
			*p++ = '^'; *p++ = '?';
		} else
			*p++ = c;
	next:
		;
	}
	*p = '\0';
	return (buf);
}

char *
ctrl(char c)
{
	static char s[3];

	if (c < 040 || c == 0177) {
		s[0] = '^';
		s[1] = c == 0177 ? '?' : c+'A'-1;
		s[2] = '\0';
	} else {
		s[0] = c;
		s[1] = '\0';
	}
	return (s);
}

/*
 * Help command
 */
void
help(int c)
{
	esctable_t *p;

	printf("%c\r\n", c);
	for (p = etable; p->e_char; p++) {
		if ((p->e_flags&PRIV) && uid)
			continue;
		printf("%2s", ctrl(character(value(ESCAPE))));
		printf("%-2s %c   %s\r\n", ctrl(p->e_char),
			(p->e_flags&EXP) ? '*': ' ', p->e_help);
	}
}

/*
 * Set up the "remote" tty's state
 */
void
ttysetup (int speed)
{
	struct termios termios;
	tcgetattr (FD, &termios);
	if (boolean(value(TAND)))
		termios.c_iflag = IXOFF;
	else
		termios.c_iflag = 0;
	termios.c_lflag = (PENDIN|ECHOKE|ECHOE);
	termios.c_cflag = (CLOCAL|HUPCL|CREAD|CS8);
	termios.c_ispeed = termios.c_ospeed = speed;
	tcsetattr (FD, TCSANOW, &termios);
}

/*
 * Return "simple" name from a file name,
 * strip leading directories.
 */
char *
sname(char *s)
{
	char *p = s;

	while (*s)
		if (*s++ == '/')
			p = s;
	return (p);
}

static char partab[0200];
static int bits8;

/*
 * Do a write to the remote machine with the correct parity.
 * We are doing 8 bit wide output, so we just generate a character
 * with the right parity and output it.
 */
void
xpwrite(int fd, char *buf, int n)
{
	int i;
	char *bp;

	bp = buf;
	if (bits8 == 0)
		for (i = 0; i < n; i++) {
			*bp = partab[(*bp) & 0177];
			bp++;
		}
	if (write(fd, buf, n) < 0) {
		if (errno == EIO)
			tipabort("Lost carrier.");
		if (errno == ENODEV)
			tipabort("tty not available.");
		tipabort("Something wrong...");
	}
}

/*
 * Build a parity table with appropriate high-order bit.
 */
void
setparity(char *defparity)
{
	int i, flip, clr, set;
	char *parity;
	extern char evenpartab[];

	if (value(PARITY) == NULL)
		value(PARITY) = defparity;
	parity = value(PARITY);
	if (equal(parity, "none")) {
		bits8 = 1;
		return;
	}
	bits8 = 0;
	flip = 0;
	clr = 0377;
	set = 0;
	if (equal(parity, "odd"))
		flip = 0200;			/* reverse bit 7 */
	else if (equal(parity, "zero"))
		clr = 0177;			/* turn off bit 7 */
	else if (equal(parity, "one"))
		set = 0200;			/* turn on bit 7 */
	else if (!equal(parity, "even")) {
		(void) fprintf(stderr, "%s: unknown parity value\r\n", parity);
		(void) fflush(stderr);
	}
	for (i = 0; i < 0200; i++)
		partab[i] = (evenpartab[i] ^ flip) | (set & clr);
}
