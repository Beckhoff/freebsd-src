/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#pragma once

#include <contrib/dev/acpica/include/acpi.h>

struct vmctx;

struct acpi_device;

/**
 * Creates an ACPI device.
 *
 * @param[out] new_dev Returns the newly create ACPI device.
 * @param[in]  vm_ctx  VM context the ACPI device is created in.
 * @param[in]  name    Name of the ACPI device. Should always be a NULL
 *                     terminated string.
 * @param[in]  hid     Hardware ID of the ACPI device. Should always be a NULL
 *                     terminated string.
 */
int acpi_device_create(struct acpi_device **const new_dev,
    struct vmctx *const vm_ctx, const char *const name, const char *const hid);
void acpi_device_destroy(struct acpi_device *const dev);

/**
 * @note: acpi_device_add_res_acpi_buffer doesn't ensure that no resources are
 *        added on an error condition. On error the caller should assume that
 *        the ACPI_BUFFER is partially added to the ACPI device.
 */
int acpi_device_add_res_acpi_buffer(struct acpi_device *const dev,
    const ACPI_BUFFER resources);
int acpi_device_add_res_fixed_ioport(struct acpi_device *const dev,
    const UINT16 port, UINT8 length);
int acpi_device_add_res_fixed_memory32(struct acpi_device *const dev,
    const UINT8 write_protected, const UINT32 address, const UINT32 length);

int acpi_device_get_physical_crs(const struct acpi_device *const dev,
    ACPI_BUFFER *const crs);

/**
 * Maps the current resources (CRS) occupied by the ACPI device to the guest
 * memory space.
 */
int acpi_device_map_crs(const struct acpi_device *const dev);

void acpi_device_write_dsdt(const struct acpi_device *const dev);
