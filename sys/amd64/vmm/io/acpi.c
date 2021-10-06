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
#include <sys/systm.h>
#include <sys/malloc.h>

#include <contrib/dev/acpica/include/acpi.h>
#include <contrib/dev/acpica/include/acpixf.h>

#include "acpi.h"

int
vmm_acpi_get_crs(const char *const device_path, void *const buffer,
    size_t *const buffer_length)
{
	if (device_path == NULL || buffer_length == NULL) {
		return (EINVAL);
	}

	/* get device handle */
	ACPI_HANDLE acpi_device;
	ACPI_STRING const path = strdup(device_path, M_TEMP);
	ACPI_STATUS status = AcpiGetHandle(NULL, path, &acpi_device);
	if (!ACPI_SUCCESS(status)) {
		printf("%s: failed to get handle for ACPI device \"%s\" (%x)\n",
		    __func__, device_path, status);
		return (ENOENT);
	}

	/* get current resources */
	ACPI_BUFFER resources = { ACPI_ALLOCATE_BUFFER };
	status = AcpiGetCurrentResources(acpi_device, &resources);
	if (!ACPI_SUCCESS(status)) {
		printf(
		    "%s: failed to get current resources of ACPI device \"%s\" (%x)\n",
		    __func__, device_path, status);
		return (ENODEV);
	}

	/* copy data to user space buffer */
	int error = 0;
	if (buffer == NULL) {
		*buffer_length = resources.Length;
	} else {
		size_t bytes_to_write = MIN(*buffer_length, resources.Length);
		error = copyout(resources.Pointer, buffer, bytes_to_write);
	}

	AcpiOsFree(resources.Pointer);

	return (error);
}

int
vmm_tpm2_get_control_address(vm_paddr_t *const base, vm_paddr_t *const size)
{
	ACPI_TABLE_HEADER *tpm_header;
	if (!ACPI_SUCCESS(AcpiGetTable("TPM2", 1, &tpm_header))) {
		return (ENOENT);
	}

	if (base) {
		const ACPI_TABLE_TPM2 *const tpm_table = (ACPI_TABLE_TPM2 *)
		    tpm_header;
		*base = tpm_table->ControlAddress;
	}
	if (size) {
		*size = 0;
	}

	return (0);
}
