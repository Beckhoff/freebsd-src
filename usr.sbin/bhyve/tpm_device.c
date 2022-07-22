/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 - 2022 Beckhoff Automation GmbH & Co. KG
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
#include "tpm_device_priv.h"

#define TPM_ACPI_DEVICE_NAME "TPM"
#define TPM_ACPI_HARDWARE_ID "MSFT0101"

SET_DECLARE(tpm_device_emul_set, struct tpm_device_emul);

static const struct acpi_device_emul tpm_acpi_device_emul = {
	.name = TPM_ACPI_DEVICE_NAME,
	.hid = TPM_ACPI_HARDWARE_ID,
};

int
tpm_device_create(struct tpm_device **const new_dev,
    struct vmctx *const vm_ctx, nvlist_t *const nvl)
{
	if (new_dev == NULL || vm_ctx == NULL) {
		return (EINVAL);
	}

	const char *value = get_config_value_node(nvl, "version");
	if (value == NULL) {
		warnx("%s: no version specified\n", __func__);
		return (EINVAL);
	}

	if (strcmp(value, "2.0")) {
		warnx("%s: unsupported tpm version %s\n", __func__, value);
		return (EINVAL);
	}

	struct tpm_device *const dev = calloc(1, sizeof(*dev));
	if (dev == NULL) {
		return (ENOMEM);
	}

	int error = acpi_device_create(&dev->acpi_dev, dev, vm_ctx,
	    &tpm_acpi_device_emul);
	if (error) {
		tpm_device_destroy(dev);
		return (error);
	}

	dev->control_address = 0;

	const char *tpm_type = get_config_value_node(nvl, "type");
	struct tpm_device_emul **ppemul;
	SET_FOREACH(ppemul, tpm_device_emul_set)
	{
		struct tpm_device_emul *const pemul = *ppemul;
		if (strcmp(tpm_type, pemul->name))
			continue;
		dev->emul = pemul;
		break;
	}
	if (dev->emul == NULL) {
		tpm_device_destroy(dev);
		return (EINVAL);
	}

	if (dev->emul->init) {
		error = dev->emul->init(dev, vm_ctx, nvl);
		if (error) {
			tpm_device_destroy(dev);
			return (error);
		}
	}

	*new_dev = dev;

	return (0);
}

void
tpm_device_destroy(struct tpm_device *const dev)
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
_tpm_device_get_control_address(const struct tpm_device *const dev)
{
	return (dev->control_address);
}

vm_paddr_t
tpm_device_get_control_address(const struct tpm_device *const dev)
{
	if (dev == NULL || dev->emul == NULL) {
		return (0);
	}

	if (dev->emul->get_control_address) {
		return dev->emul->get_control_address(dev);
	}

	return _tpm_device_get_control_address(dev);
}

int
_tpm_device_set_control_address(struct tpm_device *const dev,
    const vm_paddr_t control_address)
{
	dev->control_address = control_address;

	return (0);
}

int
tpm_device_set_control_address(struct tpm_device *const dev,
    const vm_paddr_t control_address)
{
	if (dev == NULL || dev->emul == NULL) {
		return (EINVAL);
	}

	if (dev->emul->set_control_address) {
		dev->emul->set_control_address(dev, control_address);
	}

	return _tpm_device_set_control_address(dev, control_address);
}
