/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 - 2022 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#pragma once

#include <vmmapi.h>

#include "acpi_device.h"
#include "config.h"

struct tpm_device;

/**
 * Creates a new TPM device. If the creation fails, no resources are freed. The
 * caller has to call the destroy function to free all resources.
 */
int tpm_device_create(struct tpm_device **const new_dev,
    struct vmctx *const vm_ctx, nvlist_t *const nvl);
void tpm_device_destroy(struct tpm_device *const dev);
