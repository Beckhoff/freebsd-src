/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>

#include <dev/vt/vt.h>

/*
 * FreeBSD uses vt_efifb as generic vt driver. vt_efifb reuses the EFI
 * framebuffer. When using GPU passthrough for a bhyve VM, the guest uses the
 * same EFI framebuffer as the host. Loading the ppt driver for the GPU won't
 * prevent vt_efifb from writing to the EFI framebuffer. That results in stripes
 * on the display output of the guest. Solve this issue by loading this vt_dummy
 * driver which ignores all draw calls.
 */

static int
vt_dummy_probe(struct vt_device *vd)
{
	return (0);
}

static int
vt_dummy_init(struct vt_device *vd)
{
	return (0);
}

static void
vt_dummy_blank(struct vt_device *vd, term_color_t color)
{
}

static void
vt_dummy_bitblt_text(struct vt_device *vd, const struct vt_window *vw,
    const term_rect_t *area)
{
}

static void
vt_dummy_invalidate_text(struct vt_device *vd, const term_rect_t *area)
{
}

static void
vt_dummy_bitblt_bmp(struct vt_device *vd, const struct vt_window *vw,
    const uint8_t *pattern, const uint8_t *mask, unsigned int width,
    unsigned int height, unsigned int x, unsigned int y, term_color_t fg,
    term_color_t bg)
{
}

static void
vt_dummy_drawrect(struct vt_device *vd, int x1, int y1, int x2, int y2,
    int fill, term_color_t color)
{
}

static void
vt_dummy_setpixel(struct vt_device *vd, int x, int y, term_color_t color)
{
}

static int
vt_dummy_fb_ioctl(struct vt_device *vd, u_long cmd, caddr_t data,
    struct thread *td)
{
	return (0);
}

static int
vt_dummy_fb_mmap(struct vt_device *vd, vm_ooffset_t offset, vm_paddr_t *paddr,
    int prot, vm_memattr_t *memattr)
{
	return (-1);
}

static void
vt_dummy_suspend(struct vt_device *vd)
{
}

static void
vt_dummy_resume(struct vt_device *vd)
{
}

static struct vt_driver vt_dummy_driver = {
	.vd_name = "dummy",
	.vd_probe = vt_dummy_probe,
	.vd_init = vt_dummy_init,
	.vd_blank = vt_dummy_blank,
	.vd_bitblt_text = vt_dummy_bitblt_text,
	.vd_invalidate_text = vt_dummy_invalidate_text,
	.vd_bitblt_bmp = vt_dummy_bitblt_bmp,
	.vd_drawrect = vt_dummy_drawrect,
	.vd_setpixel = vt_dummy_setpixel,
	.vd_fb_ioctl = vt_dummy_fb_ioctl,
	.vd_fb_mmap = vt_dummy_fb_mmap,
	.vd_suspend = vt_dummy_suspend,
	.vd_resume = vt_dummy_resume,
	/*
	 * When loading a new vt driver and it's vd_priority is higher than
	 * vd_priority of the current loaded vt driver, the new vt driver will
	 * be loaded. Some specific vt driver like i915 cause system crashes
	 * when they get unloaded. However, it's common that specific vt drivers
	 * use an own framebuffer which won't create issues. For that reason,
	 * just unload generic vt drivers by setting vd_priority to
	 * VD_PRIORITY_SPECIFIC - 1.
	 */
	.vd_priority = VD_PRIORITY_SPECIFIC - 1,
};
VT_DRIVER_DECLARE(vt_dummy, vt_dummy_driver);

static int
vt_dummy_modevent(module_t mod, int type, void *data)
{
	switch (type) {
	case MOD_LOAD:
		vt_allocate(&vt_dummy_driver, NULL);
		printf("vt_dummy module loaded\n");
		break;

	case MOD_UNLOAD:
		vt_deallocate(&vt_dummy_driver, NULL);
		printf("vt_dummy module unloaded\n");
		break;

	default:
		return (EOPNOTSUPP);
	}

	return (0);
}

static moduledata_t vt_dummy_mod = { "vt_dummy", vt_dummy_modevent, NULL };
DECLARE_MODULE(vt_dummy, vt_dummy_mod, SI_SUB_DRIVERS, SI_ORDER_ANY);
