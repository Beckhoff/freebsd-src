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
#include "tpm_emul.h"
#include "tpm_intf.h"
#include "tpm_ppi.h"

#define TPM_ACPI_DEVICE_NAME "TPM"
#define TPM_ACPI_HARDWARE_ID "MSFT0101"

SET_DECLARE(tpm_emul_set, struct tpm_emul);
SET_DECLARE(tpm_intf_set, struct tpm_intf);
SET_DECLARE(tpm_ppi_set, struct tpm_ppi);

static int
tpm_build_acpi_table(const struct acpi_device *const dev)
{
	const struct tpm_device *const tpm = acpi_device_get_softc(dev);

	if (tpm->intf->build_acpi_table == NULL) {
		return (0);
	}

	return (tpm->intf->build_acpi_table(tpm));
}

static int
tpm_write_dsdt(const struct acpi_device *const dev)
{
	int error;

	const struct tpm_device *const tpm = acpi_device_get_softc(dev);
	const struct tpm_ppi *const ppi = tpm->ppi;

	/*
	 * packages for returns
	 */
	dsdt_line("Name(TPM2, Package(2) {0, 0})");
	dsdt_line("Name(TPM3, Package(3) {0, 0, 0})");

	if (ppi->write_dsdt_regions) {
		error = ppi->write_dsdt_regions(tpm);
		if (error) {
			warnx("%s: failed to write ppi dsdt regions\n",
			    __func__);
			return (error);
		}
	}

	/*
	 * Device Specific Method
	 * Arg0: UUID
	 * Arg1: Revision ID
	 * Arg2: Function Index
	 * Arg3: Arguments
	 */
	dsdt_line("Method(_DSM, 4, Serialized)");
	dsdt_line("{");
	dsdt_indent(1);
	if (ppi->write_dsdt_dsm) {
		error = ppi->write_dsdt_dsm(tpm);
		if (error) {
			warnx("%s: failed to write ppi dsdt dsm\n", __func__);
			return (error);
		}
	}
	dsdt_unindent(1);
	dsdt_line("}");

	return (0);
}

static const struct acpi_device_emul tpm_acpi_device_emul = {
	.name = TPM_ACPI_DEVICE_NAME,
	.hid = TPM_ACPI_HARDWARE_ID,
	.build_table = tpm_build_acpi_table,
	.write_dsdt = tpm_write_dsdt,
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
	*new_dev = dev;
	if (dev == NULL) {
		return (ENOMEM);
	}

	dev->ctx = vm_ctx;

	int error = acpi_device_create(&dev->acpi_dev, dev, vm_ctx,
	    &tpm_acpi_device_emul);
	if (error) {
		return (error);
	}

	set_config_value_node_if_unset(nvl, "intf", "crb");
	set_config_value_node_if_unset(nvl, "ppi", "qemu");

	const char *tpm_type = get_config_value_node(nvl, "type");
	struct tpm_emul **ppemul;
	SET_FOREACH(ppemul, tpm_emul_set)
	{
		struct tpm_emul *const pemul = *ppemul;
		if (strcmp(tpm_type, pemul->name)) {
			continue;
		}
		dev->emul = pemul;
		break;
	}
	const char *tpm_intf = get_config_value_node(nvl, "intf");
	struct tpm_intf **ppintf;
	SET_FOREACH(ppintf, tpm_intf_set)
	{
		if (strcmp(tpm_intf, (*ppintf)->name)) {
			continue;
		}
		dev->intf = *ppintf;
		break;
	}
	const char *tpm_ppi = get_config_value_node(nvl, "ppi");
	struct tpm_ppi **pp_ppi;
	SET_FOREACH(pp_ppi, tpm_ppi_set)
	{
		if (strcmp(tpm_ppi, (*pp_ppi)->name)) {
			continue;
		}
		dev->ppi = *pp_ppi;
		break;
	}

	if (dev->emul == NULL || dev->intf == NULL || dev->ppi == NULL) {
		return (EINVAL);
	}

	if (dev->emul->init) {
		error = dev->emul->init(dev);
		if (error) {
			return (error);
		}
	}
	if (dev->intf->init) {
		error = dev->intf->init(dev);
		if (error) {
			return (error);
		}
	}
	if (dev->ppi->init) {
		error = dev->ppi->init(dev);
		if (error) {
			return (error);
		}
	}

	return (0);
}

void
tpm_device_destroy(struct tpm_device *const dev)
{
	if (dev == NULL) {
		return;
	}

	if (dev->ppi != NULL && dev->ppi->deinit != NULL) {
		dev->ppi->deinit(dev);
	}
	if (dev->intf != NULL && dev->intf->deinit != NULL) {
		dev->intf->deinit(dev);
	}
	if (dev->emul != NULL && dev->emul->deinit != NULL) {
		dev->emul->deinit(dev);
	}

	acpi_device_destroy((struct acpi_device *)dev);
	free(dev);
}
