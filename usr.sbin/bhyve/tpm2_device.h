/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#pragma once

#include <vmmapi.h>

#include "acpi_device.h"

struct tpm2_device;

/* device creation and destruction */
int tpm2_device_create(struct tpm2_device **const new_dev,
    struct vmctx *const vm_ctx, const char *const opts);
void tpm2_device_destroy(struct tpm2_device *const dev);
/* device methods */
vm_paddr_t tpm2_device_get_control_address(const struct tpm2_device *const dev);
int tpm2_device_set_control_address(struct tpm2_device *const dev,
    const vm_paddr_t control_address);
