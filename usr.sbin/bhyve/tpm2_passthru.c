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

static int
tpm2_passthru_device_init(struct tpm2_device *const dev,
    struct vmctx *const vm_ctx, const char *const opts)
{
	ACPI_BUFFER crs;
	int error = acpi_device_get_physical_crs(dev->acpi_dev, &crs);
	if (error) {
		warnx("%s: failed to get current resources of TPM2 device",
		    __func__);
		return (error);
	}
	error = acpi_device_add_res_acpi_buffer(dev->acpi_dev, crs);
	if (error) {
		warnx("%s: failed to set current resources for TPM2 device",
		    __func__);
		return (error);
	}
	/*
	 * TPM2 should use the address 0xFED40000. This address shouldn't
	 * conflict with any other device, yet. However, it could change in
	 * future. It may be a good idea to check whether we can dynamically
	 * allocate the TPM2 mmio address or not.
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
		warnx("%s: failed to get control address of TPM2 device",
		    __func__);
		return (error);
	}

	error = _tpm2_device_set_control_address(dev, control_address);
	if (error) {
		warnx("%s: unable to set control address of TPM2 device",
		    __func__);
		return (error);
	}

	return (0);
}

struct tpm2_device_emul tpm2_passthru_device_emul = {
	.name = "passthru",
	.init = tpm2_passthru_device_init,
};
TPM2_DEVICE_EMUL_SET(tpm2_passthru_device_emul);
