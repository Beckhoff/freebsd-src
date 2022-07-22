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

/* device creation and destruction */
int tpm_device_create(struct tpm_device **const new_dev,
    struct vmctx *const vm_ctx, nvlist_t *const nvl);
void tpm_device_destroy(struct tpm_device *const dev);
/* device methods */
vm_paddr_t tpm_device_get_control_address(const struct tpm_device *const dev);
int tpm_device_set_control_address(struct tpm_device *const dev,
    const vm_paddr_t control_address);
