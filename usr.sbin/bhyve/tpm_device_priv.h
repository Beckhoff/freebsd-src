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

struct tpm_emul;

/**
 * This struct represents a TPM device.
 *
 * @param acpi_dev        A TPM device is an ACPI device.
 * @param emul            Emulation functions for different types of TPM
 *                        devices.
 * @param dev_data        Device specific data for a specific TPM device type.
 */
struct tpm_device {
	struct vmctx *ctx;
	struct acpi_device *acpi_dev;
	struct tpm_emul *emul;
	void *dev_data;
	struct tpm_intf *intf;
	void *intf_data;
};
