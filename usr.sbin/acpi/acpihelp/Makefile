#
# acpihelp - ACPI Help utility. Displays ASL operator syntax and
# information about ACPI predefined names.
#

UTILDIR=${.CURDIR}/../../../sys/contrib/dev/acpica/source/tools/acpihelp

.PATH:	${UTILDIR}

PROG=	acpihelp
MAN=	acpihelp.8

SRCS=	\
	ahamlops.c \
	ahaslkey.c \
	ahaslops.c \
	ahdecode.c \
	ahids.c \
	ahpredef.c \
	ahmain.c \
	ahtable.c \
	ahuuids.c

SRCS+=	\
	getopt.c \
	oslibcfs.c \
	osunixxf.c \
	utdebug.c \
	utexcep.c \
	utglobal.c \
	uthex.c \
	utmath.c \
	utnonansi.c \
	utpredef.c \
	utprint.c \
	utuuid.c

CFLAGS+= \
	-DACPI_HELP_APP \
	-I${UTILDIR}

.include <bsd.prog.mk>
