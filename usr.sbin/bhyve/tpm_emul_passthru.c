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

static int
tpm_passthru_init(struct tpm_device *const dev)
{
	ACPI_BUFFER crs;
	int error = acpi_device_get_physical_crs(dev->acpi_dev, &crs);
	if (error) {
		warnx("%s: failed to get current resources of TPM device",
		    __func__);
		return (error);
	}
	error = acpi_device_add_res_acpi_buffer(dev->acpi_dev, crs);
	if (error) {
		warnx("%s: failed to set current resources for TPM device",
		    __func__);
		return (error);
	}
	/*
	 * TPM should use the address 0xFED40000. This address shouldn't
	 * conflict with any other device, yet. However, it could change in
	 * future. It may be a good idea to check whether we can dynamically
	 * allocate the TPM mmio address or not.
	 */
	error = acpi_device_map_crs(dev->acpi_dev);
	if (error) {
		warnx(
		    "%s: failed to map current resources into guest memory space",
		    __func__);
		return (error);
	}

	return (0);
}

static struct tpm_emul tpm_emul_passthru = {
	.name = "passthru",
	.init = tpm_passthru_init,
};
TPM_EMUL_SET(tpm_emul_passthru);
