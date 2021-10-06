/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#pragma once

#include <machine/vmm.h>
#include <machine/vmm_dev.h>

/*
 * Executes the CRS (Current Resources) method of an ACPI device.
 */
int vmm_acpi_get_crs(const char *const device_path, void *const buffer,
    size_t *const buffer_length);
int vmm_tpm2_get_control_address(vm_paddr_t *const base,
    vm_paddr_t *const size);
