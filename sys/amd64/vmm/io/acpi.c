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

#include <contrib/dev/acpica/include/acpi.h>
#include <contrib/dev/acpica/include/acpixf.h>

#include "acpi.h"
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
