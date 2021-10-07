/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#pragma once

#include <sys/linker_set.h>

#include <vmmapi.h>

#include "acpi_device.h"
#include "tpm2_device.h"

struct tpm2_device_emul {
	const char *name;

	int (*init)(struct tpm2_device *const dev, struct vmctx *const vm_ctx,
	    const char *const opts);
	void (*deinit)(struct tpm2_device *const dev);
	vm_paddr_t (*get_control_address)(const struct tpm2_device *const dev);
	int (*set_control_address)(struct tpm2_device *const dev,
	    const vm_paddr_t control_address);
};
#define TPM2_DEVICE_EMUL_SET(x) DATA_SET(tpm2_device_emul_set, x)

/**
 * This struct represents a TPM2 device.
 *
 * @param acpi_dev        A TPM2 device is an ACPI device.
 * @param emul            Emulation functions for different types of TPM2
 *                        devices.
 * @param control_address Control address of the TPM device.
 * @param dev_data        Device specific data for a specific TPM2 device type.
 */
struct tpm2_device {
	struct acpi_device *acpi_dev;
	struct tpm2_device_emul *emul;
	vm_paddr_t control_address;
	void *dev_data;
};

/* default emulation functions */
vm_paddr_t _tpm2_device_get_control_address(
    const struct tpm2_device *const dev);
int _tpm2_device_set_control_address(struct tpm2_device *const dev,
    const vm_paddr_t control_address);
