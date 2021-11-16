/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>

#include "intelgpu.h"

#define KB (1024UL)

int
vm_intelgpu_get_opregion(vm_paddr_t *const base, vm_paddr_t *const size)
{
	/* intel graphics device is always located at 0:2.0 */
	device_t dev = pci_find_bsf(0, 2, 0);
	if (dev == NULL) {
		return (ENOENT);
	}

	if ((pci_get_vendor(dev) != PCI_VENDOR_INTEL) ||
	    (pci_get_class(dev) != PCIC_DISPLAY) ||
	    (pci_get_subclass(dev) != PCIS_DISPLAY_VGA)) {
		return (ENODEV);
	}

	const uint64_t asls = pci_read_config(dev, PCIR_ASLS_CTL, 4);

	const struct igd_opregion_header *const opregion_header =
	    (struct igd_opregion_header *)pmap_map(NULL, asls,
		asls + sizeof(*opregion_header), VM_PROT_READ);
	if (opregion_header == NULL ||
	    memcmp(opregion_header->sign, IGD_OPREGION_HEADER_SIGN,
		sizeof(opregion_header->sign))) {
		return (ENODEV);
	}

	*base = asls;
	*size = opregion_header->size * KB;

	return (0);
}
