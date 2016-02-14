/*
 * Created: Fri Jan 19 10:48:35 2001 by faith@acm.org
 *
 * Copyright 2001 VA Linux Systems, Inc., Sunnyvale, California.
 * All Rights Reserved.
 *
 * Author Rickard E. (Rik) Faith <faith@valinux.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * PRECISION INSIGHT AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <drm/drmP.h>
#include <drm/drm_core.h>
#include "drm_legacy.h"
#include "drm_internal.h"

unsigned int drm_debug = 0;	/* 1 to enable debug output */
EXPORT_SYMBOL(drm_debug);

int drm_vblank_offdelay = 5000;    /* Default to 5000 msecs. */

unsigned int drm_timestamp_precision = 20;  /* Default to 20 usecs. */

/*
 * Default to use monotonic timestamps for wait-for-vblank and page-flip
 * complete events.
 */
unsigned int drm_timestamp_monotonic = 1;

MODULE_AUTHOR(CORE_AUTHOR);
MODULE_DESCRIPTION(CORE_DESC);
MODULE_PARM_DESC(debug, "Enable debug output");
MODULE_PARM_DESC(vblankoffdelay, "Delay until vblank irq auto-disable [msecs] (0: never disable, <0: disable immediately)");
MODULE_PARM_DESC(timestamp_precision_usec, "Max. error on timestamps [usecs]");
MODULE_PARM_DESC(timestamp_monotonic, "Use monotonic timestamps");

module_param_named(debug, drm_debug, int, 0600);
module_param_named(vblankoffdelay, drm_vblank_offdelay, int, 0600);
module_param_named(timestamp_precision_usec, drm_timestamp_precision, int, 0600);
module_param_named(timestamp_monotonic, drm_timestamp_monotonic, int, 0600);

#if 0
static DEFINE_SPINLOCK(drm_minor_lock);
static struct idr drm_minors_idr;
#endif

struct class *drm_class;
#if 0
static struct dentry *drm_debugfs_root;
#endif

void drm_err(const char *format, ...)
{
#if 0
	struct va_format vaf;
	va_list args;
	int r;

	va_start(args, format);

	vaf.fmt = format;
	vaf.va = &args;

	printk(KERN_ERR "[" DRM_NAME ":%pf] *ERROR* %pV",
	       __builtin_return_address(0), &vaf);

	va_end(args);

	return r;
#endif
}
EXPORT_SYMBOL(drm_err);

void drm_ut_debug_printk(const char *function_name, const char *format, ...)
{
#if 0
	struct va_format vaf;
	va_list args;

	va_start(args, format);
	vaf.fmt = format;
	vaf.va = &args;

	printk(KERN_DEBUG "[" DRM_NAME ":%s] %pV", function_name, &vaf);

	va_end(args);
#endif
}
EXPORT_SYMBOL(drm_ut_debug_printk);

#if 0
struct drm_master *drm_master_create(struct drm_minor *minor)
{
	struct drm_master *master;

	master = kzalloc(sizeof(*master), GFP_KERNEL);
	if (!master)
		return NULL;

	kref_init(&master->refcount);
	spin_lock_init(&master->lock.spinlock);
	init_waitqueue_head(&master->lock.lock_queue);
	if (drm_ht_create(&master->magiclist, DRM_MAGIC_HASH_ORDER)) {
		kfree(master);
		return NULL;
	}
	INIT_LIST_HEAD(&master->magicfree);
	master->minor = minor;

	return master;
}

struct drm_master *drm_master_get(struct drm_master *master)
{
	kref_get(&master->refcount);
	return master;
}
EXPORT_SYMBOL(drm_master_get);

static void drm_master_destroy(struct kref *kref)
{
	struct drm_master *master = container_of(kref, struct drm_master, refcount);
	struct drm_device *dev = master->minor->dev;
	struct drm_map_list *r_list, *list_temp;

	mutex_lock(&dev->struct_mutex);
	if (dev->driver->master_destroy)
		dev->driver->master_destroy(dev, master);

	list_for_each_entry_safe(r_list, list_temp, &dev->maplist, head) {
		if (r_list->master == master) {
			drm_legacy_rmmap_locked(dev, r_list->map);
			r_list = NULL;
		}
	}

	if (master->unique) {
		kfree(master->unique);
		master->unique = NULL;
		master->unique_len = 0;
	}

	drm_ht_remove(&master->magiclist);

	mutex_unlock(&dev->struct_mutex);
	kfree(master);
}

void drm_master_put(struct drm_master **master)
{
	kref_put(&(*master)->refcount, drm_master_destroy);
	*master = NULL;
}
EXPORT_SYMBOL(drm_master_put);
#endif

int drm_setmaster_ioctl(struct drm_device *dev, void *data,
			struct drm_file *file_priv)
{
	DRM_DEBUG("setmaster\n");

	if (file_priv->master != 0)
		return (0);

	return (-EPERM);
}

int drm_dropmaster_ioctl(struct drm_device *dev, void *data,
			 struct drm_file *file_priv)
{
	DRM_DEBUG("dropmaster\n");
	if (file_priv->master != 0)
		return -EINVAL;
	return 0;
}

#if 0
/*
 * DRM Minors
 * A DRM device can provide several char-dev interfaces on the DRM-Major. Each
 * of them is represented by a drm_minor object. Depending on the capabilities
 * of the device-driver, different interfaces are registered.
 *
 * Minors can be accessed via dev->$minor_name. This pointer is either
 * NULL or a valid drm_minor pointer and stays valid as long as the device is
 * valid. This means, DRM minors have the same life-time as the underlying
 * device. However, this doesn't mean that the minor is active. Minors are
 * registered and unregistered dynamically according to device-state.
 */

static struct drm_minor **drm_minor_get_slot(struct drm_device *dev,
					     unsigned int type)
{
	switch (type) {
	case DRM_MINOR_LEGACY:
		return &dev->primary;
	case DRM_MINOR_RENDER:
		return &dev->render;
	case DRM_MINOR_CONTROL:
		return &dev->control;
	default:
		return NULL;
	}
}

static int drm_minor_alloc(struct drm_device *dev, unsigned int type)
{
	struct drm_minor *minor;
	unsigned long flags;
	int r;

	minor = kzalloc(sizeof(*minor), GFP_KERNEL);
	if (!minor)
		return -ENOMEM;

	minor->type = type;
	minor->dev = dev;

	idr_preload(GFP_KERNEL);
	spin_lock_irqsave(&drm_minor_lock, flags);
	r = idr_alloc(&drm_minors_idr,
		      NULL,
		      64 * type,
		      64 * (type + 1),
		      GFP_NOWAIT);
	spin_unlock_irqrestore(&drm_minor_lock, flags);
	idr_preload_end();

	if (r < 0)
		goto err_free;

	minor->index = r;

	minor->kdev = drm_sysfs_minor_alloc(minor);
	if (IS_ERR(minor->kdev)) {
		r = PTR_ERR(minor->kdev);
		goto err_index;
	}

	*drm_minor_get_slot(dev, type) = minor;
	return 0;

err_index:
	spin_lock_irqsave(&drm_minor_lock, flags);
	idr_remove(&drm_minors_idr, minor->index);
	spin_unlock_irqrestore(&drm_minor_lock, flags);
err_free:
	kfree(minor);
	return r;
}

static void drm_minor_free(struct drm_device *dev, unsigned int type)
{
	struct drm_minor **slot, *minor;
	unsigned long flags;

	slot = drm_minor_get_slot(dev, type);
	minor = *slot;
	if (!minor)
		return;

	drm_mode_group_destroy(&minor->mode_group);
	put_device(minor->kdev);

	spin_lock_irqsave(&drm_minor_lock, flags);
	idr_remove(&drm_minors_idr, minor->index);
	spin_unlock_irqrestore(&drm_minor_lock, flags);

	kfree(minor);
	*slot = NULL;
}

static int drm_minor_register(struct drm_device *dev, unsigned int type)
{
	struct drm_minor *minor;
	unsigned long flags;
	int ret;

	DRM_DEBUG("\n");

	minor = *drm_minor_get_slot(dev, type);
	if (!minor)
		return 0;

	ret = drm_debugfs_init(minor, minor->index, drm_debugfs_root);
	if (ret) {
		DRM_ERROR("DRM: Failed to initialize /sys/kernel/debug/dri.\n");
		return ret;
	}

	ret = device_add(minor->kdev);
	if (ret)
		goto err_debugfs;

	/* replace NULL with @minor so lookups will succeed from now on */
	spin_lock_irqsave(&drm_minor_lock, flags);
	idr_replace(&drm_minors_idr, minor, minor->index);
	spin_unlock_irqrestore(&drm_minor_lock, flags);

	DRM_DEBUG("new minor registered %d\n", minor->index);
	return 0;

err_debugfs:
	drm_debugfs_cleanup(minor);
	return ret;
}

static void drm_minor_unregister(struct drm_device *dev, unsigned int type)
{
	struct drm_minor *minor;
	unsigned long flags;

	minor = *drm_minor_get_slot(dev, type);
	if (!minor || !device_is_registered(minor->kdev))
		return;

	/* replace @minor with NULL so lookups will fail from now on */
	spin_lock_irqsave(&drm_minor_lock, flags);
	idr_replace(&drm_minors_idr, NULL, minor->index);
	spin_unlock_irqrestore(&drm_minor_lock, flags);

	device_del(minor->kdev);
	dev_set_drvdata(minor->kdev, NULL); /* safety belt */
	drm_debugfs_cleanup(minor);
}

/**
 * drm_minor_acquire - Acquire a DRM minor
 * @minor_id: Minor ID of the DRM-minor
 *
 * Looks up the given minor-ID and returns the respective DRM-minor object. The
 * refence-count of the underlying device is increased so you must release this
 * object with drm_minor_release().
 *
 * As long as you hold this minor, it is guaranteed that the object and the
 * minor->dev pointer will stay valid! However, the device may get unplugged and
 * unregistered while you hold the minor.
 *
 * Returns:
 * Pointer to minor-object with increased device-refcount, or PTR_ERR on
 * failure.
 */
struct drm_minor *drm_minor_acquire(unsigned int minor_id)
{
	struct drm_minor *minor;
	unsigned long flags;

	spin_lock_irqsave(&drm_minor_lock, flags);
	minor = idr_find(&drm_minors_idr, minor_id);
	if (minor)
		drm_dev_ref(minor->dev);
	spin_unlock_irqrestore(&drm_minor_lock, flags);

	if (!minor) {
		return ERR_PTR(-ENODEV);
	} else if (drm_device_is_unplugged(minor->dev)) {
		drm_dev_unref(minor->dev);
		return ERR_PTR(-ENODEV);
	}

	return minor;
}

/**
 * drm_minor_release - Release DRM minor
 * @minor: Pointer to DRM minor object
 *
 * Release a minor that was previously acquired via drm_minor_acquire().
 */
void drm_minor_release(struct drm_minor *minor)
{
	drm_dev_unref(minor->dev);
}

/**
 * drm_put_dev - Unregister and release a DRM device
 * @dev: DRM device
 *
 * Called at module unload time or when a PCI device is unplugged.
 *
 * Use of this function is discouraged. It will eventually go away completely.
 * Please use drm_dev_unregister() and drm_dev_unref() explicitly instead.
 *
 * Cleans up all DRM device, calling drm_lastclose().
 */
void drm_put_dev(struct drm_device *dev)
{
	DRM_DEBUG("\n");

	if (!dev) {
		DRM_ERROR("cleanup called no dev\n");
		return;
	}

	drm_dev_unregister(dev);
	drm_dev_unref(dev);
}
EXPORT_SYMBOL(drm_put_dev);

void drm_unplug_dev(struct drm_device *dev)
{
	/* for a USB device */
	drm_minor_unregister(dev, DRM_MINOR_LEGACY);
	drm_minor_unregister(dev, DRM_MINOR_RENDER);
	drm_minor_unregister(dev, DRM_MINOR_CONTROL);

	mutex_lock(&drm_global_mutex);

	drm_device_set_unplugged(dev);

	if (dev->open_count == 0) {
		drm_put_dev(dev);
	}
	mutex_unlock(&drm_global_mutex);
}
EXPORT_SYMBOL(drm_unplug_dev);

/*
 * DRM internal mount
 * We want to be able to allocate our own "struct address_space" to control
 * memory-mappings in VRAM (or stolen RAM, ...). However, core MM does not allow
 * stand-alone address_space objects, so we need an underlying inode. As there
 * is no way to allocate an independent inode easily, we need a fake internal
 * VFS mount-point.
 *
 * The drm_fs_inode_new() function allocates a new inode, drm_fs_inode_free()
 * frees it again. You are allowed to use iget() and iput() to get references to
 * the inode. But each drm_fs_inode_new() call must be paired with exactly one
 * drm_fs_inode_free() call (which does not have to be the last iput()).
 * We use drm_fs_inode_*() to manage our internal VFS mount-point and share it
 * between multiple inode-users. You could, technically, call
 * iget() + drm_fs_inode_free() directly after alloc and sometime later do an
 * iput(), but this way you'd end up with a new vfsmount for each inode.
 */

static int drm_fs_cnt;
static struct vfsmount *drm_fs_mnt;

static const struct dentry_operations drm_fs_dops = {
	.d_dname	= simple_dname,
};

static const struct super_operations drm_fs_sops = {
	.statfs		= simple_statfs,
};

static struct dentry *drm_fs_mount(struct file_system_type *fs_type, int flags,
				   const char *dev_name, void *data)
{
	return mount_pseudo(fs_type,
			    "drm:",
			    &drm_fs_sops,
			    &drm_fs_dops,
			    0x010203ff);
}

static struct file_system_type drm_fs_type = {
	.name		= "drm",
	.owner		= THIS_MODULE,
	.mount		= drm_fs_mount,
	.kill_sb	= kill_anon_super,
};

static struct inode *drm_fs_inode_new(void)
{
	struct inode *inode;
	int r;

	r = simple_pin_fs(&drm_fs_type, &drm_fs_mnt, &drm_fs_cnt);
	if (r < 0) {
		DRM_ERROR("Cannot mount pseudo fs: %d\n", r);
		return ERR_PTR(r);
	}

	inode = alloc_anon_inode(drm_fs_mnt->mnt_sb);
	if (IS_ERR(inode))
		simple_release_fs(&drm_fs_mnt, &drm_fs_cnt);

	return inode;
}

static void drm_fs_inode_free(struct inode *inode)
{
	if (inode) {
		iput(inode);
		simple_release_fs(&drm_fs_mnt, &drm_fs_cnt);
	}
}

/**
 * drm_dev_alloc - Allocate new DRM device
 * @driver: DRM driver to allocate device for
 * @parent: Parent device object
 *
 * Allocate and initialize a new DRM device. No device registration is done.
 * Call drm_dev_register() to advertice the device to user space and register it
 * with other core subsystems.
 *
 * The initial ref-count of the object is 1. Use drm_dev_ref() and
 * drm_dev_unref() to take and drop further ref-counts.
 *
 * Note that for purely virtual devices @parent can be NULL.
 *
 * RETURNS:
 * Pointer to new DRM device, or NULL if out of memory.
 */
struct drm_device *drm_dev_alloc(struct drm_driver *driver,
				 struct device *parent)
{
	struct drm_device *dev;
	int ret;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return NULL;

	kref_init(&dev->ref);
	dev->dev = parent;
	dev->driver = driver;

	INIT_LIST_HEAD(&dev->filelist);
	INIT_LIST_HEAD(&dev->ctxlist);
	INIT_LIST_HEAD(&dev->vmalist);
	INIT_LIST_HEAD(&dev->maplist);
	INIT_LIST_HEAD(&dev->vblank_event_list);

	spin_lock_init(&dev->buf_lock);
	spin_lock_init(&dev->event_lock);
	mutex_init(&dev->struct_mutex);
	mutex_init(&dev->ctxlist_mutex);
	mutex_init(&dev->master_mutex);

	dev->anon_inode = drm_fs_inode_new();
	if (IS_ERR(dev->anon_inode)) {
		ret = PTR_ERR(dev->anon_inode);
		DRM_ERROR("Cannot allocate anonymous inode: %d\n", ret);
		goto err_free;
	}

	if (drm_core_check_feature(dev, DRIVER_MODESET)) {
		ret = drm_minor_alloc(dev, DRM_MINOR_CONTROL);
		if (ret)
			goto err_minors;
	}

	if (drm_core_check_feature(dev, DRIVER_RENDER)) {
		ret = drm_minor_alloc(dev, DRM_MINOR_RENDER);
		if (ret)
			goto err_minors;
	}

	ret = drm_minor_alloc(dev, DRM_MINOR_LEGACY);
	if (ret)
		goto err_minors;

	if (drm_ht_create(&dev->map_hash, 12))
		goto err_minors;

	ret = drm_legacy_ctxbitmap_init(dev);
	if (ret) {
		DRM_ERROR("Cannot allocate memory for context bitmap.\n");
		goto err_ht;
	}

	if (drm_core_check_feature(dev, DRIVER_GEM)) {
		ret = drm_gem_init(dev);
		if (ret) {
			DRM_ERROR("Cannot initialize graphics execution manager (GEM)\n");
			goto err_ctxbitmap;
		}
	}

	return dev;

err_ctxbitmap:
	drm_legacy_ctxbitmap_cleanup(dev);
err_ht:
	drm_ht_remove(&dev->map_hash);
err_minors:
	drm_minor_free(dev, DRM_MINOR_LEGACY);
	drm_minor_free(dev, DRM_MINOR_RENDER);
	drm_minor_free(dev, DRM_MINOR_CONTROL);
	drm_fs_inode_free(dev->anon_inode);
err_free:
	mutex_destroy(&dev->master_mutex);
	kfree(dev);
	return NULL;
}
EXPORT_SYMBOL(drm_dev_alloc);

static void drm_dev_release(struct kref *ref)
{
	struct drm_device *dev = container_of(ref, struct drm_device, ref);

	if (drm_core_check_feature(dev, DRIVER_GEM))
		drm_gem_destroy(dev);

	drm_legacy_ctxbitmap_cleanup(dev);
	drm_ht_remove(&dev->map_hash);
	drm_fs_inode_free(dev->anon_inode);

	drm_minor_free(dev, DRM_MINOR_LEGACY);
	drm_minor_free(dev, DRM_MINOR_RENDER);
	drm_minor_free(dev, DRM_MINOR_CONTROL);

	mutex_destroy(&dev->master_mutex);
	kfree(dev->unique);
	kfree(dev);
}

/**
 * drm_dev_ref - Take reference of a DRM device
 * @dev: device to take reference of or NULL
 *
 * This increases the ref-count of @dev by one. You *must* already own a
 * reference when calling this. Use drm_dev_unref() to drop this reference
 * again.
 *
 * This function never fails. However, this function does not provide *any*
 * guarantee whether the device is alive or running. It only provides a
 * reference to the object and the memory associated with it.
 */
void drm_dev_ref(struct drm_device *dev)
{
	if (dev)
		kref_get(&dev->ref);
}
EXPORT_SYMBOL(drm_dev_ref);

/**
 * drm_dev_unref - Drop reference of a DRM device
 * @dev: device to drop reference of or NULL
 *
 * This decreases the ref-count of @dev by one. The device is destroyed if the
 * ref-count drops to zero.
 */
void drm_dev_unref(struct drm_device *dev)
{
	if (dev)
		kref_put(&dev->ref, drm_dev_release);
}
EXPORT_SYMBOL(drm_dev_unref);

/**
 * drm_dev_register - Register DRM device
 * @dev: Device to register
 * @flags: Flags passed to the driver's .load() function
 *
 * Register the DRM device @dev with the system, advertise device to user-space
 * and start normal device operation. @dev must be allocated via drm_dev_alloc()
 * previously.
 *
 * Never call this twice on any device!
 *
 * RETURNS:
 * 0 on success, negative error code on failure.
 */
int drm_dev_register(struct drm_device *dev, unsigned long flags)
{
	int ret;

	mutex_lock(&drm_global_mutex);

	ret = drm_minor_register(dev, DRM_MINOR_CONTROL);
	if (ret)
		goto err_minors;

	ret = drm_minor_register(dev, DRM_MINOR_RENDER);
	if (ret)
		goto err_minors;

	ret = drm_minor_register(dev, DRM_MINOR_LEGACY);
	if (ret)
		goto err_minors;

	if (dev->driver->load) {
		ret = dev->driver->load(dev, flags);
		if (ret)
			goto err_minors;
	}

	/* setup grouping for legacy outputs */
	if (drm_core_check_feature(dev, DRIVER_MODESET)) {
		ret = drm_mode_group_init_legacy_group(dev,
				&dev->primary->mode_group);
		if (ret)
			goto err_unload;
	}

	ret = 0;
	goto out_unlock;

err_unload:
	if (dev->driver->unload)
		dev->driver->unload(dev);
err_minors:
	drm_minor_unregister(dev, DRM_MINOR_LEGACY);
	drm_minor_unregister(dev, DRM_MINOR_RENDER);
	drm_minor_unregister(dev, DRM_MINOR_CONTROL);
out_unlock:
	mutex_unlock(&drm_global_mutex);
	return ret;
}
EXPORT_SYMBOL(drm_dev_register);

/**
 * drm_dev_unregister - Unregister DRM device
 * @dev: Device to unregister
 *
 * Unregister the DRM device from the system. This does the reverse of
 * drm_dev_register() but does not deallocate the device. The caller must call
 * drm_dev_unref() to drop their final reference.
 */
void drm_dev_unregister(struct drm_device *dev)
{
	struct drm_map_list *r_list, *list_temp;

	drm_lastclose(dev);

	if (dev->driver->unload)
		dev->driver->unload(dev);

	if (dev->agp)
		drm_pci_agp_destroy(dev);

	drm_vblank_cleanup(dev);

	list_for_each_entry_safe(r_list, list_temp, &dev->maplist, head)
		drm_legacy_rmmap(dev, r_list->map);

	drm_minor_unregister(dev, DRM_MINOR_LEGACY);
	drm_minor_unregister(dev, DRM_MINOR_RENDER);
	drm_minor_unregister(dev, DRM_MINOR_CONTROL);
}
EXPORT_SYMBOL(drm_dev_unregister);

/**
 * drm_dev_set_unique - Set the unique name of a DRM device
 * @dev: device of which to set the unique name
 * @fmt: format string for unique name
 *
 * Sets the unique name of a DRM device using the specified format string and
 * a variable list of arguments. Drivers can use this at driver probe time if
 * the unique name of the devices they drive is static.
 *
 * Return: 0 on success or a negative error code on failure.
 */
int drm_dev_set_unique(struct drm_device *dev, const char *fmt, ...)
{
	va_list ap;

	kfree(dev->unique);

	va_start(ap, fmt);
	dev->unique = kvasprintf(GFP_KERNEL, fmt, ap);
	va_end(ap);

	return dev->unique ? 0 : -ENOMEM;
}
EXPORT_SYMBOL(drm_dev_set_unique);
#endif

/*
 * DRM Core
 * The DRM core module initializes all global DRM objects and makes them
 * available to drivers. Once setup, drivers can probe their respective
 * devices.
 * Currently, core management includes:
 *  - The "DRM-Global" key/value database
 *  - Global ID management for connectors
 *  - DRM major number allocation
 *  - DRM minor management
 *  - DRM sysfs class
 *  - DRM debugfs root
 *
 * Furthermore, the DRM core provides dynamic char-dev lookups. For each
 * interface registered on a DRM device, you can request minor numbers from DRM
 * core. DRM core takes care of major-number management and char-dev
 * registration. A stub ->open() callback forwards any open() requests to the
 * registered minor.
 */

#if 0
static int drm_stub_open(struct inode *inode, struct file *filp)
{
	const struct file_operations *new_fops;
	struct drm_minor *minor;
	int err;

	DRM_DEBUG("\n");

	mutex_lock(&drm_global_mutex);
	minor = drm_minor_acquire(iminor(inode));
	if (IS_ERR(minor)) {
		err = PTR_ERR(minor);
		goto out_unlock;
	}

	new_fops = fops_get(minor->dev->driver->fops);
	if (!new_fops) {
		err = -ENODEV;
		goto out_release;
	}

	replace_fops(filp, new_fops);
	if (filp->f_op->open)
		err = filp->f_op->open(inode, filp);
	else
		err = 0;

out_release:
	drm_minor_release(minor);
out_unlock:
	mutex_unlock(&drm_global_mutex);
	return err;
}

static const struct file_operations drm_stub_fops = {
	.owner = THIS_MODULE,
	.open = drm_stub_open,
	.llseek = noop_llseek,
};

static int __init drm_core_init(void)
{
	int ret = -ENOMEM;

	drm_global_init();
	drm_connector_ida_init();
	idr_init(&drm_minors_idr);

	if (register_chrdev(DRM_MAJOR, "drm", &drm_stub_fops))
		goto err_p1;

	drm_class = drm_sysfs_create(THIS_MODULE, "drm");
	if (IS_ERR(drm_class)) {
		printk(KERN_ERR "DRM: Error creating drm class.\n");
		ret = PTR_ERR(drm_class);
		goto err_p2;
	}

	drm_debugfs_root = debugfs_create_dir("dri", NULL);
	if (!drm_debugfs_root) {
		DRM_ERROR("Cannot create /sys/kernel/debug/dri\n");
		ret = -1;
		goto err_p3;
	}

	DRM_INFO("Initialized %s %d.%d.%d %s\n",
		 CORE_NAME, CORE_MAJOR, CORE_MINOR, CORE_PATCHLEVEL, CORE_DATE);
	return 0;
err_p3:
	drm_sysfs_destroy();
err_p2:
	unregister_chrdev(DRM_MAJOR, "drm");

	idr_destroy(&drm_minors_idr);
err_p1:
	return ret;
}

static void __exit drm_core_exit(void)
{
	debugfs_remove(drm_debugfs_root);
	drm_sysfs_destroy();

	unregister_chrdev(DRM_MAJOR, "drm");

	drm_connector_ida_destroy();
	idr_destroy(&drm_minors_idr);
}

module_init(drm_core_init);
module_exit(drm_core_exit);
#endif

#include <sys/devfs.h>

#include <linux/export.h>
#include <linux/dmi.h>
#include <drm/drmP.h>
#include <drm/drm_core.h>

#if DRM_DEBUG_DEFAULT_ON == 1
#define DRM_DEBUGBITS_ON (DRM_DEBUGBITS_DEBUG | DRM_DEBUGBITS_KMS | \
    DRM_DEBUGBITS_FAILED_IOCTL)
#elif DRM_DEBUG_DEFAULT_ON == 2
#define DRM_DEBUGBITS_ON (DRM_DEBUGBITS_DEBUG | DRM_DEBUGBITS_KMS | \
    DRM_DEBUGBITS_FAILED_IOCTL | DRM_DEBUGBITS_VERBOSE)
#else
#define DRM_DEBUGBITS_ON (0x0)
#endif

int drm_notyet_flag = 0;

static int drm_load(struct drm_device *dev);
drm_pci_id_list_t *drm_find_description(int vendor, int device,
    drm_pci_id_list_t *idlist);

#define DRIVER_SOFTC(unit) \
	((struct drm_device *)devclass_get_softc(drm_devclass, unit))

static int
drm_modevent(module_t mod, int type, void *data)
{

	switch (type) {
	case MOD_LOAD:
		TUNABLE_INT_FETCH("drm.debug", &drm_debug);
		TUNABLE_INT_FETCH("drm.notyet", &drm_notyet_flag);
		break;
	}
	return (0);
}

static moduledata_t drm_mod = {
	"drm",
	drm_modevent,
	0
};
DECLARE_MODULE(drm, drm_mod, SI_SUB_DRIVERS, SI_ORDER_FIRST);
MODULE_VERSION(drm, 1);
MODULE_DEPEND(drm, agp, 1, 1, 1);
MODULE_DEPEND(drm, pci, 1, 1, 1);
MODULE_DEPEND(drm, iicbus, 1, 1, 1);

static struct dev_ops drm_cdevsw = {
	{ "drm", 0, D_TRACKCLOSE | D_MPSAFE },
	.d_open =	drm_open,
	.d_close =	drm_close,
	.d_read =	drm_read,
	.d_ioctl =	drm_ioctl,
	.d_kqfilter =	drm_kqfilter,
	.d_mmap =	drm_mmap,
	.d_mmap_single = drm_mmap_single,
};

SYSCTL_NODE(_hw, OID_AUTO, drm, CTLFLAG_RW, NULL, "DRM device");
SYSCTL_INT(_hw_drm, OID_AUTO, debug, CTLFLAG_RW, &drm_debug, 0,
    "DRM debugging");

int drm_probe(device_t kdev, drm_pci_id_list_t *idlist)
{
	drm_pci_id_list_t *id_entry;
	int vendor, device;

	vendor = pci_get_vendor(kdev);
	device = pci_get_device(kdev);

	if (pci_get_class(kdev) != PCIC_DISPLAY)
		return ENXIO;

	id_entry = drm_find_description(vendor, device, idlist);
	if (id_entry != NULL) {
		if (!device_get_desc(kdev)) {
			DRM_DEBUG("desc : %s\n", device_get_desc(kdev));
			device_set_desc(kdev, id_entry->name);
		}
		return 0;
	}

	return ENXIO;
}

int drm_attach(device_t kdev, drm_pci_id_list_t *idlist)
{
	struct drm_device *dev;
	drm_pci_id_list_t *id_entry;
	int unit, error;
	u_int irq_flags;
	int msi_enable;

	unit = device_get_unit(kdev);
	dev = device_get_softc(kdev);

	if (!strcmp(device_get_name(kdev), "drmsub"))
		dev->dev = device_get_parent(kdev);
	else
		dev->dev = kdev;

	dev->pci_domain = pci_get_domain(dev->dev);
	dev->pci_bus = pci_get_bus(dev->dev);
	dev->pci_slot = pci_get_slot(dev->dev);
	dev->pci_func = pci_get_function(dev->dev);
	drm_init_pdev(dev->dev, &dev->pdev);

	id_entry = drm_find_description(dev->pdev->vendor,
	    dev->pdev->device, idlist);
	dev->id_entry = id_entry;

	if (drm_core_check_feature(dev, DRIVER_HAVE_IRQ)) {
		msi_enable = 1;

		dev->irq_type = pci_alloc_1intr(dev->dev, msi_enable,
		    &dev->irqrid, &irq_flags);

		dev->irqr = bus_alloc_resource_any(dev->dev, SYS_RES_IRQ,
		    &dev->irqrid, irq_flags);

		if (!dev->irqr) {
			return (ENOENT);
		}

		dev->irq = (int) rman_get_start(dev->irqr);
	}

	lockinit(&dev->dev_lock, "drmdev", 0, LK_CANRECURSE);
	lwkt_serialize_init(&dev->irq_lock);
	lockinit(&dev->event_lock, "drmev", 0, LK_CANRECURSE);
	lockinit(&dev->struct_mutex, "drmslk", 0, LK_CANRECURSE);

	error = drm_load(dev);
	if (error)
		goto error;

	error = drm_create_cdevs(kdev);
	if (error)
		goto error;

	return (error);
error:
	if (dev->irqr) {
		bus_release_resource(dev->dev, SYS_RES_IRQ,
		    dev->irqrid, dev->irqr);
	}
	if (dev->irq_type == PCI_INTR_TYPE_MSI) {
		pci_release_msi(dev->dev);
	}
	return (error);
}

int
drm_create_cdevs(device_t kdev)
{
	struct drm_device *dev;
	int error, unit;

	unit = device_get_unit(kdev);
	dev = device_get_softc(kdev);

	dev->devnode = make_dev(&drm_cdevsw, unit, DRM_DEV_UID, DRM_DEV_GID,
				DRM_DEV_MODE, "dri/card%d", unit);
	error = 0;
	if (error == 0)
		dev->devnode->si_drv1 = dev;
	return (error);
}

#ifndef DRM_DEV_NAME
#define DRM_DEV_NAME "drm"
#endif

devclass_t drm_devclass;

drm_pci_id_list_t *drm_find_description(int vendor, int device,
    drm_pci_id_list_t *idlist)
{
	int i = 0;

	for (i = 0; idlist[i].vendor != 0; i++) {
		if ((idlist[i].vendor == vendor) &&
		    ((idlist[i].device == device) ||
		    (idlist[i].device == 0))) {
			return &idlist[i];
		}
	}
	return NULL;
}

static int drm_load(struct drm_device *dev)
{
	int i, retcode;

	DRM_DEBUG("\n");

	INIT_LIST_HEAD(&dev->maplist);

	drm_mem_init();
	drm_sysctl_init(dev);
	INIT_LIST_HEAD(&dev->filelist);

	dev->counters  = 6;
	dev->types[0]  = _DRM_STAT_LOCK;
	dev->types[1]  = _DRM_STAT_OPENS;
	dev->types[2]  = _DRM_STAT_CLOSES;
	dev->types[3]  = _DRM_STAT_IOCTLS;
	dev->types[4]  = _DRM_STAT_LOCKS;
	dev->types[5]  = _DRM_STAT_UNLOCKS;

	for (i = 0; i < ARRAY_SIZE(dev->counts); i++)
		atomic_set(&dev->counts[i], 0);

	INIT_LIST_HEAD(&dev->vblank_event_list);

	if (drm_core_has_AGP(dev)) {
		if (drm_device_is_agp(dev))
			dev->agp = drm_agp_init();
		if (drm_core_check_feature(dev, DRIVER_REQUIRE_AGP) &&
		    dev->agp == NULL) {
			DRM_ERROR("Card isn't AGP, or couldn't initialize "
			    "AGP.\n");
			retcode = ENOMEM;
			goto error;
		}
		if (dev->agp != NULL && dev->agp->agp_info.ai_aperture_base != 0) {
			if (drm_mtrr_add(dev->agp->agp_info.ai_aperture_base,
			    dev->agp->agp_info.ai_aperture_size, DRM_MTRR_WC) == 0)
				dev->agp->agp_mtrr = 1;
		}
	}

	if (dev->driver->driver_features & DRIVER_GEM) {
		retcode = drm_gem_init(dev);
		if (retcode != 0) {
			DRM_ERROR("Cannot initialize graphics execution "
				  "manager (GEM)\n");
			goto error1;
		}
	}

	if (dev->driver->load != NULL) {
		DRM_LOCK(dev);
		/* Shared code returns -errno. */
		retcode = -dev->driver->load(dev,
		    dev->id_entry->driver_private);
		if (pci_enable_busmaster(dev->dev))
			DRM_ERROR("Request to enable bus-master failed.\n");
		DRM_UNLOCK(dev);
		if (retcode != 0)
			goto error1;
	}

	DRM_INFO("Initialized %s %d.%d.%d %s\n",
	    dev->driver->name,
	    dev->driver->major,
	    dev->driver->minor,
	    dev->driver->patchlevel,
	    dev->driver->date);

	return 0;

error1:
	drm_gem_destroy(dev);
error:
	drm_sysctl_cleanup(dev);
	DRM_LOCK(dev);
	drm_lastclose(dev);
	DRM_UNLOCK(dev);
	if (dev->devnode != NULL)
		destroy_dev(dev->devnode);

	lockuninit(&dev->vbl_lock);
	lockuninit(&dev->dev_lock);
	lockuninit(&dev->event_lock);
	lockuninit(&dev->struct_mutex);

	return retcode;
}

/*
 * Stub is needed for devfs
 */
int drm_close(struct dev_close_args *ap)
{
	return 0;
}

void drm_cdevpriv_dtor(void *cd)
{
	struct drm_file *file_priv = cd;
	struct drm_device *dev = file_priv->dev;
	int retcode = 0;

	DRM_DEBUG("open_count = %d\n", dev->open_count);

	DRM_LOCK(dev);

	if (dev->driver->preclose != NULL)
		dev->driver->preclose(dev, file_priv);

	/* ========================================================
	 * Begin inline drm_release
	 */

	DRM_DEBUG("pid = %d, device = 0x%lx, open_count = %d\n",
	    DRM_CURRENTPID, (long)dev->dev, dev->open_count);

	if (dev->driver->driver_features & DRIVER_GEM)
		drm_gem_release(dev, file_priv);

	if (dev->lock.hw_lock && _DRM_LOCK_IS_HELD(dev->lock.hw_lock->lock)
	    && dev->lock.file_priv == file_priv) {
		DRM_DEBUG("Process %d dead, freeing lock for context %d\n",
			  DRM_CURRENTPID,
			  _DRM_LOCKING_CONTEXT(dev->lock.hw_lock->lock));
		if (dev->driver->reclaim_buffers_locked != NULL)
			dev->driver->reclaim_buffers_locked(dev, file_priv);

		drm_lock_free(&dev->lock,
		    _DRM_LOCKING_CONTEXT(dev->lock.hw_lock->lock));

				/* FIXME: may require heavy-handed reset of
                                   hardware at this point, possibly
                                   processed via a callback to the X
                                   server. */
	} else if (dev->driver->reclaim_buffers_locked != NULL &&
	    dev->lock.hw_lock != NULL) {
		/* The lock is required to reclaim buffers */
		for (;;) {
			if (!dev->lock.hw_lock) {
				/* Device has been unregistered */
				retcode = EINTR;
				break;
			}
			/* Contention */
			retcode = DRM_LOCK_SLEEP(dev, &dev->lock.lock_queue,
			    PCATCH, "drmlk2", 0);
			if (retcode)
				break;
		}
		if (retcode == 0) {
			dev->driver->reclaim_buffers_locked(dev, file_priv);
		}
	}

	if (drm_core_check_feature(dev, DRIVER_HAVE_DMA) &&
	    !dev->driver->reclaim_buffers_locked)
		drm_legacy_reclaim_buffers(dev, file_priv);

	funsetown(&dev->buf_sigio);

	if (dev->driver->postclose != NULL)
		dev->driver->postclose(dev, file_priv);
	list_del(&file_priv->lhead);


	/* ========================================================
	 * End inline drm_release
	 */

	atomic_inc(&dev->counts[_DRM_STAT_CLOSES]);
	device_unbusy(dev->dev);
	if (--dev->open_count == 0) {
		retcode = drm_lastclose(dev);
	}

	DRM_UNLOCK(dev);
}

int
drm_add_busid_modesetting(struct drm_device *dev, struct sysctl_ctx_list *ctx,
    struct sysctl_oid *top)
{
	struct sysctl_oid *oid;

	ksnprintf(dev->busid_str, sizeof(dev->busid_str),
	     "pci:%04x:%02x:%02x.%d", dev->pci_domain, dev->pci_bus,
	     dev->pci_slot, dev->pci_func);
	oid = SYSCTL_ADD_STRING(ctx, SYSCTL_CHILDREN(top), OID_AUTO, "busid",
	    CTLFLAG_RD, dev->busid_str, 0, NULL);
	if (oid == NULL)
		return (ENOMEM);
	dev->modesetting = (dev->driver->driver_features & DRIVER_MODESET) != 0;
	oid = SYSCTL_ADD_INT(ctx, SYSCTL_CHILDREN(top), OID_AUTO,
	    "modesetting", CTLFLAG_RD, &dev->modesetting, 0, NULL);
	if (oid == NULL)
		return (ENOMEM);

	return (0);
}

int
drm_mmap_single(struct dev_mmap_single_args *ap)
{
	struct drm_device *dev;
	struct cdev *kdev = ap->a_head.a_dev;
	vm_ooffset_t *offset = ap->a_offset;
	vm_size_t size = ap->a_size;
	struct vm_object **obj_res = ap->a_object;
	int nprot = ap->a_nprot;

	dev = drm_get_device_from_kdev(kdev);
	if (dev->drm_ttm_bdev != NULL) {
		return (ttm_bo_mmap_single(dev->drm_ttm_bdev, offset, size,
		    obj_res, nprot));
	} else if ((dev->driver->driver_features & DRIVER_GEM) != 0) {
		return (drm_gem_mmap_single(dev, offset, size, obj_res, nprot));
	} else {
		return (ENODEV);
	}
}

#if DRM_LINUX

#include <sys/sysproto.h>

MODULE_DEPEND(DRIVER_NAME, linux, 1, 1, 1);

#define LINUX_IOCTL_DRM_MIN		0x6400
#define LINUX_IOCTL_DRM_MAX		0x64ff

static linux_ioctl_function_t drm_linux_ioctl;
static struct linux_ioctl_handler drm_handler = {drm_linux_ioctl,
    LINUX_IOCTL_DRM_MIN, LINUX_IOCTL_DRM_MAX};

/* The bits for in/out are switched on Linux */
#define LINUX_IOC_IN	IOC_OUT
#define LINUX_IOC_OUT	IOC_IN

static int
drm_linux_ioctl(DRM_STRUCTPROC *p, struct linux_ioctl_args* args)
{
	int error;
	int cmd = args->cmd;

	args->cmd &= ~(LINUX_IOC_IN | LINUX_IOC_OUT);
	if (cmd & LINUX_IOC_IN)
		args->cmd |= IOC_IN;
	if (cmd & LINUX_IOC_OUT)
		args->cmd |= IOC_OUT;
	
	error = ioctl(p, (struct ioctl_args *)args);

	return error;
}
#endif /* DRM_LINUX */

static int
drm_core_init(void *arg)
{

	drm_global_init();

#if DRM_LINUX
	linux_ioctl_register_handler(&drm_handler);
#endif /* DRM_LINUX */

	DRM_INFO("Initialized %s %d.%d.%d %s\n",
		 CORE_NAME, CORE_MAJOR, CORE_MINOR, CORE_PATCHLEVEL, CORE_DATE);
	return 0;
}

static void
drm_core_exit(void *arg)
{

#if DRM_LINUX
	linux_ioctl_unregister_handler(&drm_handler);
#endif /* DRM_LINUX */

	drm_global_release();
}

SYSINIT(drm_register, SI_SUB_DRIVERS, SI_ORDER_MIDDLE,
    drm_core_init, NULL);
SYSUNINIT(drm_unregister, SI_SUB_DRIVERS, SI_ORDER_MIDDLE,
    drm_core_exit, NULL);


#include <linux/dmi.h>

/*
 * Check if dmi_system_id structure matches system DMI data
 */
static bool
dmi_found(const struct dmi_system_id *dsi)
{
	int i, slot;
	bool found = false;
	char *sys_vendor, *board_vendor, *product_name, *board_name;

	sys_vendor = kgetenv("smbios.system.maker");
	board_vendor = kgetenv("smbios.planar.maker");
	product_name = kgetenv("smbios.system.product");
	board_name = kgetenv("smbios.planar.product");

	for (i = 0; i < NELEM(dsi->matches); i++) {
		slot = dsi->matches[i].slot;
		switch (slot) {
		case DMI_NONE:
			break;
		case DMI_SYS_VENDOR:
			if (sys_vendor != NULL &&
			    !strcmp(sys_vendor, dsi->matches[i].substr))
				break;
			else
				goto done;
		case DMI_BOARD_VENDOR:
			if (board_vendor != NULL &&
			    !strcmp(board_vendor, dsi->matches[i].substr))
				break;
			else
				goto done;
		case DMI_PRODUCT_NAME:
			if (product_name != NULL &&
			    !strcmp(product_name, dsi->matches[i].substr))
				break;
			else
				goto done;
		case DMI_BOARD_NAME:
			if (board_name != NULL &&
			    !strcmp(board_name, dsi->matches[i].substr))
				break;
			else
				goto done;
		default:
			goto done;
		}
	}
	found = true;

done:
	if (sys_vendor != NULL)
		kfreeenv(sys_vendor);
	if (board_vendor != NULL)
		kfreeenv(board_vendor);
	if (product_name != NULL)
		kfreeenv(product_name);
	if (board_name != NULL)
		kfreeenv(board_name);

	return found;
}

int dmi_check_system(const struct dmi_system_id *sysid)
{
	const struct dmi_system_id *dsi;
	int num = 0;

	for (dsi = sysid; dsi->matches[0].slot != 0 ; dsi++) {
		if (dmi_found(dsi)) {
			num++;
			if (dsi->callback && dsi->callback(dsi))
				break;
		}
	}
	return (num);
}
