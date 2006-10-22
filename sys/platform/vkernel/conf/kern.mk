# $DragonFly: src/sys/platform/vkernel/conf/kern.mk,v 1.1 2006/10/22 16:09:14 dillon Exp $
#
# On the i386, do not align the stack to 16-byte boundaries.  Otherwise GCC
# adds code to the entry and exit point of every function to align the
# stack to 16-byte boundaries -- thus wasting approximately 12 bytes of stack
# per function call.  While the 16-byte alignment may benefit micro benchmarks, 
# it is probably an overall loss as it makes the code bigger (less efficient
# use of code cache tag lines) and uses more stack (less efficient use of data
# cache tag lines)
#
# Prohibit the use of FP registers in the kernel.  The user FP state is
# only saved and restored under strictly managed conditions and mainline
# kernel code cannot safely use the FP system.
#
CFLAGS+=	-mpreferred-stack-boundary=2
CFLAGS+=	-fno-stack-protector
CFLAGS+=	-mno-mmx -mno-3dnow -mno-sse -mno-sse2 -mno-sse3

INLINE_LIMIT=	8000
