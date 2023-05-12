/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#include <sys/types.h>
#include <sys/sysctl.h>

#include <err.h>

#include "e820.h"
#include "pci_gvt-d-opregion.h"
#include "pci_gvt-d.h"
#include "pci_passthru.h"

#define KB (1024UL)
#define MB (1024 * KB)
#define GB (1024 * MB)

#define PCIM_BDSM_GSM_ALIGNMENT \
	0x00100000 /* Graphics Stolen Memory is 1 MB aligned */

#define GVT_D_MAP_GSM 0

static vm_paddr_t
gvt_d_alloc_mmio_memory(const vm_paddr_t host_address, const vm_paddr_t length,
    const vm_paddr_t alignment, const enum e820_memory_type type)
{
	vm_paddr_t address;

	/* Try to reuse host address. */
	address = e820_alloc(host_address, length, E820_ALIGNMENT_NONE, type,
	    E820_ALLOCATE_SPECIFIC);
	if (address != 0) {
		return (address);
	}

	/*
	 * We're not able to reuse the host address. Fall back to the highest usable
	 * address below 4 GB.
	 */
	return (
	    e820_alloc(4 * GB, length, alignment, type, E820_ALLOCATE_HIGHEST));
}

/*
 * Note that the graphics stolen memory is somehow confusing. On the one hand
 * the Intel Open Source HD Graphics Programmers' Reference Manual states that
 * it's only GPU accessible. As the CPU can't access the area, the guest
 * shouldn't need it. On the other hand, the Intel GOP driver refuses to work
 * properly, if it's not set to a proper address.
 *
 * Intel itself maps it into the guest by EPT [1]. At the moment, we're not
 * aware of any situation where this EPT mapping is required, so we don't do it
 * yet.
 *
 * Intel also states that the Windows driver for Tiger Lake reads the address of
 * the graphics stolen memory [2]. As the GVT-d code doesn't support Tiger Lake
 * in its first implementation, we can't check how it behaves. We should keep an
 * eye on it.
 *
 * [1]
 * https://github.com/projectacrn/acrn-hypervisor/blob/e28d6fbfdfd556ff1bc3ff330e41d4ddbaa0f897/devicemodel/hw/pci/passthrough.c#L655-L657
 * [2]
 * https://github.com/projectacrn/acrn-hypervisor/blob/e28d6fbfdfd556ff1bc3ff330e41d4ddbaa0f897/devicemodel/hw/pci/passthrough.c#L626-L629
 */
static int
gvt_d_setup_gsm(struct pci_devinst *const pi)
{
	struct passthru_softc *sc;
	struct passthru_mmio_mapping *gsm;
	size_t sysctl_len;
	int error;

	sc = pi->pi_arg;

	gsm = passthru_get_mmio(sc, GVT_D_MAP_GSM);
	if (gsm == NULL) {
		warnx("%s: Unable to access gsm", __func__);
		return (-1);
	}

	sysctl_len = sizeof(gsm->hpa);
	error = sysctlbyname("hw.intel_graphics_stolen_base", &gsm->hpa,
	    &sysctl_len, NULL, 0);
	if (error) {
		warn("%s: Unable to get graphics stolen memory base",
		    __func__);
		return (-1);
	}
	sysctl_len = sizeof(gsm->len);
	error = sysctlbyname("hw.intel_graphics_stolen_size", &gsm->len,
	    &sysctl_len, NULL, 0);
	if (error) {
		warn("%s: Unable to get graphics stolen memory length",
		    __func__);
		return (-1);
	}
	gsm->hva = NULL; /* unused */
	gsm->gva = NULL; /* unused */
	gsm->gpa = gvt_d_alloc_mmio_memory(gsm->hpa, gsm->len,
	    PCIM_BDSM_GSM_ALIGNMENT, E820_TYPE_RESERVED);
	if (gsm->gpa == 0) {
		warnx(
		    "%s: Unable to add Graphics Stolen Memory to E820 table (hpa 0x%lx len 0x%lx)",
		    __func__, gsm->hpa, gsm->len);
		e820_dump_table();
		return (-1);
	}
	if (gsm->gpa != gsm->hpa) {
		/*
		 * ACRN source code implies that graphics driver for newer Intel
		 * platforms like Tiger Lake will read the Graphics Stolen Memory
		 * address from an MMIO register. We have three options to solve this
		 * issue:
		 *    1. Patch the value in the MMIO register
		 *       This could have unintended side effects. Without any
		 *       documentation how this register is used by the GPU, don't do
		 *       it.
		 *    2. Trap the MMIO register
		 *       It's not possible to trap a single MMIO register. We need to
		 *       trap a whole page. Trapping a bunch of MMIO register could
		 *       degrade the performance noticeably. We have to test it.
		 *    3. Use an 1:1 host to guest mapping
		 *       Maybe not always possible. As far as we know, no supported
		 *       platform requires a 1:1 mapping. For that reason, just log a
		 *       warning.
		 */
		warnx(
		    "Warning: Unable to reuse host address of Graphics Stolen Memory. GPU passthrough might not work properly.");
	}

	return (0);
}

int
gvt_d_init(struct pci_devinst *const pi, nvlist_t *const nvl __unused)
{
	int error;

	if ((error = gvt_d_setup_gsm(pi)) != 0) {
		warnx("%s: Unable to setup Graphics Stolen Memory", __func__);
		goto done;
	}

done:
	return (error);
}

void
gvt_d_deinit(struct pci_devinst *const pi __unused)
{
}
