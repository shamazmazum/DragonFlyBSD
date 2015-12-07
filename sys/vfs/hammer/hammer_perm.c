#include "hammer.h"

static int hammer_get_perm (hammer_transaction_t trans, hammer_inode_t ip,
							uid_t uid, gid_t gid, u_int64_t *perm);
static int hammer_set_perm (hammer_transaction_t trans, hammer_inode_t ip,
							uid_t uid, gid_t gid, u_int64_t *perm);

/* This function does not fail in the case of ENOENT
 * creating dummy permission entry. Returns EINVAL if permission entry
   is requested for root.
 */
int hammer_ioc_get_perm(hammer_transaction_t trans, hammer_inode_t ip,
						struct hammer_ioc_perm *perm)
{
	int error;
	perm->head.error = 0;

	/* Sanity checks */
	if ((perm->gid == 0) && (perm->uid == 0)) {
		perm->head.error = EINVAL;
		return 0;
	}

	error = hammer_get_perm (trans, ip,
							 perm->uid, perm->gid, &(perm->perm));
	if (error == ENOENT) {
		error = 0;
		bzero(&(perm->perm), sizeof (perm->perm));
	}
	return error;
}

/* Returns an error in case of HAMMER operations failure.
 * Sets the following errors in perm->head.error:
 *
 * EINVAL: Permission is out of range or both uid and gid are set to 0
 *		   (root has not a permission entry). User tries to set the same
 *		   permission twice.
 */
int hammer_ioc_add_perm(hammer_transaction_t trans, hammer_inode_t ip,
						struct hammer_ioc_perm *perm)
{
	int error;
	u_int64_t perm_data;

	perm->head.error = 0;
	/* Sanity checks */
	if (perm->changed_perm > HAMMER_MAX_PERM_MASK) {
		perm->head.error = EINVAL;
		return 0;
	}
	if ((perm->gid == 0) && (perm->uid == 0)) {
		perm->head.error = EINVAL;
		return 0;
	}

	error = hammer_get_perm (trans, ip, perm->uid, perm->gid, &perm_data);
	if (error == ENOENT) {
		error = 0;
		bzero (&perm_data, sizeof (perm_data));
	}
	if (error)
		return error;

	/* Check if we must add anything at all */
	if ((perm_data & perm->changed_perm) == perm->changed_perm) {
		perm->head.error = EINVAL;
		return 0;
	}

	perm_data |= perm->changed_perm;

	error = hammer_set_perm (trans, ip, perm->uid, perm->gid, &perm_data);
	return error;
}

/* Returns an error in case of HAMMER operations failure.
 * Sets the following errors in perm->head.error:
 *
 * EINVAL: Permission is out of range or both uid and gid are set to 0
 *		   (root has not a permission entry). User tries to delete
 *			a permission which is not set earlier.
 */
int hammer_ioc_del_perm(hammer_transaction_t trans, hammer_inode_t ip,
						struct hammer_ioc_perm *perm)
{
	int error;
	u_int64_t perm_data;

	perm->head.error = 0;
	/* Sanity checks */
	if (perm->changed_perm > HAMMER_MAX_PERM_MASK) {
		perm->head.error = EINVAL;
		return 0;
	}
	if ((perm->gid == 0) && (perm->uid == 0)) {
		perm->head.error = EINVAL;
		return 0;
	}

	error = hammer_get_perm (trans, ip, perm->uid, perm->gid, &perm_data);
	if (error == ENOENT) {
		perm->head.error = EINVAL;
		return 0;
	}
	if (error)
		return error;

	/* Nothing to delete */
	if ((perm->changed_perm & perm_data) != perm->changed_perm) {
		perm->head.error = EINVAL;
		return 0;
	}

	perm_data &= ~perm->changed_perm;

	error = hammer_set_perm (trans, ip, perm->uid, perm->gid, &perm_data);
	return error;
}

int hammer_checkperm(hammer_transaction_t trans, hammer_inode_t ip,
					 u_long com, struct ucred *cred)
{
	int error;
	int p = -1;
	u_int64_t perm;

	switch (com) {
		/* Unprivileged ioctl()'s */
	case HAMMERIOC_GETHISTORY:
	case HAMMERIOC_SYNCTID:
	case HAMMERIOC_GET_PSEUDOFS:
	case HAMMERIOC_GET_VERSION:
	case HAMMERIOC_GET_INFO:
	case HAMMERIOC_LIST_VOLUMES:
	case HAMMERIOC_GET_SNAPSHOT:
	case HAMMERIOC_GET_CONFIG:
	case HAMMERIOC_PFS_ITERATE:
	case HAMMERIOC_GET_PERM:
		return 0;
	case HAMMERIOC_ADD_SNAPSHOT:
		p = HAMMER_PERM_ADD_SNAPSHOT;
		break;
	case HAMMERIOC_DEL_SNAPSHOT:
		p = HAMMER_PERM_DEL_SNAPSHOT;
		break;
	case HAMMERIOC_MIRROR_READ:
		p = HAMMER_PERM_MIRROR_READ;
		break;
	case HAMMERIOC_MIRROR_WRITE:
		p = HAMMER_PERM_MIRROR_WRITE;
		break;
	case HAMMERIOC_SET_PSEUDOFS:
		p = HAMMER_PERM_MIRROR_WRITE;
		break;
	case HAMMERIOC_WAI_PSEUDOFS:
		p = HAMMER_PERM_MIRROR_READ;
		break;
		/* 'Global' (non per-PFS) ioctl()'s */
	case HAMMERIOC_SET_VERSION:
	case HAMMERIOC_ADD_VOLUME:
	case HAMMERIOC_DEL_VOLUME:
	default:
		return EPERM;
	}

	if (p == -1)
		return EINVAL; /* Unknown ioctl */

	error = hammer_get_perm(trans, ip, cred->cr_uid, cred->cr_gid, &perm);
	if (error == ENOENT)
		return EPERM;
	if (error)
		return error;

	if ((perm & p) == p)
		return 0;
	return EPERM;
}

static int hammer_get_perm (hammer_transaction_t trans, hammer_inode_t ip,
							uid_t uid, gid_t gid, u_int64_t *perm)
{
	int error;
	struct hammer_cursor cursor;

	error = hammer_init_cursor(trans, &cursor, &ip->cache[0], NULL);
	if (error) {
		hammer_done_cursor(&cursor);
		return error;
	}

	cursor.key_beg.obj_id = HAMMER_OBJID_ROOT;
	cursor.key_beg.create_tid = 0;
	cursor.key_beg.delete_tid = 0;
	cursor.key_beg.obj_type = 0;
	cursor.key_beg.rec_type = HAMMER_RECTYPE_PERM;
	cursor.key_beg.localization = ip->obj_localization + HAMMER_LOCALIZE_INODE;
	cursor.key_beg.key = uid;

	cursor.asof = HAMMER_MAX_TID;
	cursor.flags |= HAMMER_CURSOR_ASOF;

	error = hammer_btree_lookup(&cursor);
	if (error == 0) {
		error = hammer_btree_extract(&cursor, HAMMER_CURSOR_GET_LEAF |
							  HAMMER_CURSOR_GET_DATA);
		if (error == 0) {
			*perm = cursor.data->perm;
			KASSERT (*perm <= HAMMER_MAX_PERM_MASK, ("Permissions are invalid %lu", *perm));
		}
	}

	hammer_done_cursor(&cursor);
	return error;
}

static int hammer_set_perm (hammer_transaction_t trans, hammer_inode_t ip,
							uid_t uid, gid_t gid, u_int64_t *perm)
{
	struct hammer_btree_leaf_elm leaf;
	struct hammer_cursor cursor;
	hammer_mount_t hmp = ip->hmp;
	int error;

again:
	error = hammer_init_cursor(trans, &cursor, &ip->cache[0], NULL);
	if (error) {
		hammer_done_cursor(&cursor);
		return(error);
	}

	bzero(&leaf, sizeof(leaf));
	leaf.base.obj_id = HAMMER_OBJID_ROOT;
	leaf.base.rec_type = HAMMER_RECTYPE_PERM;
	leaf.base.create_tid = hammer_alloc_tid(hmp, 1);
	leaf.base.btype = HAMMER_BTREE_TYPE_RECORD;
	leaf.base.localization = ip->obj_localization + HAMMER_LOCALIZE_INODE;
	leaf.base.key = uid;
	leaf.data_len = sizeof(*perm);

	cursor.key_beg = leaf.base;

	cursor.asof = HAMMER_MAX_TID;
	cursor.flags |= HAMMER_CURSOR_BACKEND | HAMMER_CURSOR_ASOF;

	error = hammer_btree_lookup(&cursor);
	if (error == 0) {
		error = hammer_btree_extract(&cursor, HAMMER_CURSOR_GET_LEAF |
							  HAMMER_CURSOR_GET_DATA);
		error = hammer_delete_at_cursor(&cursor, HAMMER_DELETE_DESTROY,
						0, 0, 0, NULL);
		if (error == EDEADLK) {
			hammer_done_cursor(&cursor);
			goto again;
		}
	}
	if (error == ENOENT)
		error = 0;
	if (error == 0) {
		/*
		 * NOTE: Must reload key_beg after an ASOF search because
		 *	 the create_tid may have been modified during the
		 *	 search.
		 */
		cursor.flags &= ~HAMMER_CURSOR_ASOF;
		cursor.key_beg = leaf.base;
		error = hammer_create_at_cursor(&cursor, &leaf,
						perm,
						HAMMER_CREATE_MODE_SYS);
		if (error == EDEADLK) {
			hammer_done_cursor(&cursor);
			goto again;
		}
	}
	hammer_done_cursor(&cursor);
	return error;
}
