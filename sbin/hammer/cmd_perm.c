#include <pwd.h>
#include "hammer.h"

static const struct {
	const char *command;
	const char *desc;
	u_int64_t perm;
	u_int64_t visible;
} perm_command[] = {
	{"snap-add", "Snapshot creation", HAMMER_PERM_ADD_SNAPSHOT, 1},
	{"snap-del", "Snapshot deletion", HAMMER_PERM_DEL_SNAPSHOT, 1},
	{"snap",	 "Snapshot manipulation", HAMMER_PERM_SNAPSHOT_MASK, 0},
	{"mirror-write", "Mirror write", HAMMER_PERM_MIRROR_WRITE, 1},
	{"mirror-read",	 "Mirror read", HAMMER_PERM_MIRROR_READ, 1},
};

static void perm_usage(void);
static int get_perm (const char *cmd);

void hammer_cmd_show_perm(char **av, int ac)
{
	int fd;
	unsigned int i;
	int error = 0;
	struct hammer_ioc_perm perm;
	struct passwd *pass;
	struct hammer_ioc_pseudofs_rw pfs;

	if (!(UserOpt) && !(GroupOpt))
		perm_usage();

	if (ac != 1)
		perm_usage();

	if (UserOpt) {
		pass = getpwnam (UserOpt);
		if (pass == NULL)
			err (2, "show-perm: Cannot get user info");
		perm.uid = pass->pw_uid;
	}

	if (GroupOpt) {
		fprintf (stderr, "Not implemented yet\n");
		exit (1);
	}

	fd = getpfs (&pfs, av[0]);
	if (ioctl (fd, HAMMERIOC_GET_PERM, &perm))
		error = errno;
	if (error == 0 && perm.head.error)
		error = perm.head.error;
	relpfs (fd, &pfs);
	if (error)
		errx(1, "show-perm %s failed: %s", av[0], strerror (error));

	printf ("User permissions for PFS #%d:\n", pfs.pfs_id);
	for (i=0; i<sizeof(perm_command)/sizeof(perm_command[0]); i++) {
		if ((perm_command[i].perm & perm.perm) && (perm_command[i].visible))
			printf ("%s\n", perm_command[i].desc);
	}

	printf ("\nPossible user permissions are:\n");
	for (i=0; i<sizeof(perm_command)/sizeof(perm_command[0]); i++) {
		printf ("%s: %s\n", perm_command[i].command, perm_command[i].desc);
	}
}

void hammer_cmd_change_perm(char **av, int ac, int add)
{
	int fd;
	int error = 0;
	struct hammer_ioc_perm perm;
	struct passwd *pass;
	struct hammer_ioc_pseudofs_rw pfs;
	const char *command_name = (add) ? "add-perm" : "del-perm";

	if (!(UserOpt) && !(GroupOpt))
		perm_usage();

	if (ac != 2)
		perm_usage();

	if (UserOpt) {
		pass = getpwnam (UserOpt);
		if (pass == NULL)
			err (2, "%s: Cannot get user info", command_name);
		perm.uid = pass->pw_uid;
	}

	if (GroupOpt) {
		fprintf (stderr, "Not implemented yet\n");
		exit (1);
	}

	fd = getpfs (&pfs, av[0]);
	perm.changed_perm = get_perm (av[1]);
	if (ioctl (fd, (add) ? HAMMERIOC_ADD_PERM : HAMMERIOC_DEL_PERM, &perm))
		error = errno;
	if (error == 0 && perm.head.error)
		error = perm.head.error;
	relpfs (fd, &pfs);
	if (error) {
		errx(1, "%s %s failed: %s", command_name,
			 av[0], strerror (error));
	}
}

static int get_perm (const char *cmd)
{
	unsigned int i;
	for (i=0; i<sizeof(perm_command)/sizeof(perm_command[0]); i++) {
		if (strcmp (cmd, perm_command[i].command) == 0)
			return perm_command[i].perm;
	}
	fprintf (stderr, "%s: no such permission\n", cmd);
	exit (1);
	return 0;
}

static void perm_usage(void)
{
	fprintf (stderr, "hammer -u user | -g group show-perm <filesystem>\n");
	fprintf (stderr, "hammer -u user | -g group add-perm <filesystem> <perm>\n");
	fprintf (stderr, "hammer -u user | -g group del-perm <filesystem> <perm>\n");
	exit (1);
}
