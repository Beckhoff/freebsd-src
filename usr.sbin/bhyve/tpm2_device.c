/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/param.h>

#include <machine/vmm.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <vmmapi.h>

#include "acpi.h"
#include "tpm2_device_priv.h"

#define TPM2_ACPI_DEVICE_NAME "TPM"
#define TPM2_ACPI_HARDWARE_ID "MSFT0101"

SET_DECLARE(tpm2_device_emul_set, struct tpm2_device_emul);

int
tpm2_device_create(struct tpm2_device **const new_dev,
    struct vmctx *const vm_ctx, const char *const opts)
{
	if (new_dev == NULL || vm_ctx == NULL) {
		return (EINVAL);
	}

	struct tpm2_device *const dev = calloc(1, sizeof(*dev));
	if (dev == NULL) {
		return (ENOMEM);
	}

	int error = acpi_device_create(&dev->acpi_dev, vm_ctx,
	    TPM2_ACPI_DEVICE_NAME, TPM2_ACPI_HARDWARE_ID);
	if (error) {
		tpm2_device_destroy(dev);
		return (error);
	}

	dev->control_address = 0;

	struct tpm2_device_emul **ppemul;
	SET_FOREACH(ppemul, tpm2_device_emul_set)
	{
		struct tpm2_device_emul *const pemul = *ppemul;
		if (strcmp(opts, pemul->name))
			continue;
		dev->emul = pemul;
		break;
	}
	if (dev->emul == NULL) {
		tpm2_device_destroy(dev);
		return (EINVAL);
	}

	if (dev->emul->init) {
		error = dev->emul->init(dev, vm_ctx, opts);
		if (error) {
			tpm2_device_destroy(dev);
			return (error);
		}
	}

	*new_dev = dev;

	return (0);
}

void
tpm2_device_destroy(struct tpm2_device *const dev)
{
	if (dev == NULL) {
		return;
	}
	if (dev->emul != NULL && dev->emul->deinit != NULL) {
		dev->emul->deinit(dev);
	}

	acpi_device_destroy((struct acpi_device *)dev);
	free(dev);
}

vm_paddr_t
_tpm2_device_get_control_address(const struct tpm2_device *const dev)
{
	return (dev->control_address);
}

vm_paddr_t
tpm2_device_get_control_address(const struct tpm2_device *const dev)
{
	if (dev == NULL || dev->emul == NULL) {
		return (0);
	}

	if (dev->emul->get_control_address) {
		return dev->emul->get_control_address(dev);
	}

	return _tpm2_device_get_control_address(dev);
}

int
_tpm2_device_set_control_address(struct tpm2_device *const dev,
    const vm_paddr_t control_address)
{
	dev->control_address = control_address;

	return (0);
}

int
tpm2_device_set_control_address(struct tpm2_device *const dev,
    const vm_paddr_t control_address)
{
	if (dev == NULL || dev->emul == NULL) {
		return (EINVAL);
	}

	if (dev->emul->set_control_address) {
		dev->emul->set_control_address(dev, control_address);
	}

	return _tpm2_device_set_control_address(dev, control_address);
}
