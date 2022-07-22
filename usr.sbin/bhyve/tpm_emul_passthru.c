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

static int
tpm_passthru_device_init(struct tpm_device *const dev,
    struct vmctx *const vm_ctx, nvlist_t *const nvl)
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

	vm_paddr_t control_address;
	error = vm_get_memory_region_info(vm_ctx, &control_address, NULL,
	    MEMORY_REGION_TPM_CONTROL_ADDRESS);
	if (error) {
		warnx("%s: failed to get control address of TPM device",
		    __func__);
		return (error);
	}

	error = _tpm_device_set_control_address(dev, control_address);
	if (error) {
		warnx("%s: unable to set control address of TPM device",
		    __func__);
		return (error);
	}

	return (0);
}

struct tpm_device_emul tpm_passthru_device_emul = {
	.name = "passthru",
	.init = tpm_passthru_device_init,
};
TPM_DEVICE_EMUL_SET(tpm_passthru_device_emul);
