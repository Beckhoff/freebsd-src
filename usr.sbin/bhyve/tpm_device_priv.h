/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 - 2022 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#pragma once

#include <sys/linker_set.h>

#include <vmmapi.h>

#include "acpi_device.h"
#include "tpm_device.h"

struct tpm_device_emul {
	const char *name;

	int (*init)(struct tpm_device *const dev, struct vmctx *const vm_ctx,
	    nvlist_t *const nvl);
	void (*deinit)(struct tpm_device *const dev);
	vm_paddr_t (*get_control_address)(const struct tpm_device *const dev);
	int (*set_control_address)(struct tpm_device *const dev,
	    const vm_paddr_t control_address);
};
#define TPM_DEVICE_EMUL_SET(x) DATA_SET(tpm_device_emul_set, x)

/**
 * This struct represents a TPM device.
 *
 * @param acpi_dev        A TPM device is an ACPI device.
 * @param emul            Emulation functions for different types of TPM
 *                        devices.
 * @param control_address Control address of the TPM device.
 * @param dev_data        Device specific data for a specific TPM device type.
 */
struct tpm_device {
	struct acpi_device *acpi_dev;
	struct tpm_device_emul *emul;
	vm_paddr_t control_address;
	void *dev_data;
};

/* default emulation functions */
vm_paddr_t _tpm_device_get_control_address(
    const struct tpm_device *const dev);
int _tpm_device_set_control_address(struct tpm_device *const dev,
    const vm_paddr_t control_address);
