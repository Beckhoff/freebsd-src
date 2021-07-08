/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2020 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/param.h>
#include <sys/mman.h>

#include <machine/vmm.h>

#include <dev/pci/pcireg.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "e820.h"
#include "inout.h"
#include "pci_passthru.h"

#define MB (1024 * 1024UL)
#define GB (1024 * MB)

#ifndef _PATH_MEM
#define _PATH_MEM "/dev/mem"
#endif

/*
 * PCI definitions
 */
#define PCIM_BDSM_GSM_ALIGNMENT \
	0x00100000 /* Graphics Stolen Memory is 1 MB aligned */

/* GVT-d definitions */
#define GVT_D_MAP_OPREGION 0
#define GVT_D_MAP_GSM 1

static int
gvt_d_aslswrite(struct vmctx *const ctx, const int vcpu,
    struct pci_devinst *const pi, const int coff, const int bytes,
    const uint32_t val)
{
	struct passthru_softc *const sc = pi->pi_arg;

	struct passthru_mmio_mapping *const opregion =
	    &sc->psc_mmio_map[GVT_D_MAP_OPREGION];

	/* write new value to cfg space */
	if (bytes == 1) {
		pci_set_cfgdata8(pi, coff, val);
	} else if (bytes == 2) {
		pci_set_cfgdata16(pi, coff, val);
	} else {
		pci_set_cfgdata32(pi, coff, val);
	}

	/* get new address of opregion */
	opregion->gpa = pci_get_cfgdata32(pi, PCIR_ASLS_CTL);

	/* copy opregion into guest mem */
	opregion->gva = vm_map_gpa(ctx, opregion->gpa, opregion->len);
	if (opregion->gva == 0) {
		warnx("%s: Unable to map opregion (0x%016lx)", __func__,
		    opregion->gpa);
		/* return 0 to avoid emulation of ASLS register */
		return (0);
	}
	memcpy(opregion->gva, opregion->hva, opregion->len);

	return (0);
}

static vm_paddr_t
gvt_d_alloc_mmio_memory(const vm_paddr_t host_address, const vm_paddr_t length,
    const vm_paddr_t alignment, const enum e820_memory_type type)
{
	/* try to use host address */
	const vm_paddr_t address = e820_alloc(host_address, length,
	    E820_ALIGNMENT_NONE, type, E820_ALLOCATE_SPECIFIC);
	if (address != 0) {
		return address;
	}

	/* try to use highest address below 4 GB */
	return e820_alloc(4 * GB, length, alignment, type,
	    E820_ALLOCATE_HIGHEST);
}

static int
gvt_d_setup_gsm(struct vmctx *const ctx, struct pci_devinst *const pi)
{
	struct passthru_softc *const sc = pi->pi_arg;

	struct passthru_mmio_mapping *const gsm =
	    &sc->psc_mmio_map[GVT_D_MAP_GSM];

	const int error = vm_get_memory_region_info(ctx, &gsm->hpa, &gsm->len,
	    MEMORY_REGION_INTEL_GSM);
	if (error) {
		warnx(
		    "%s: Unable to get Graphics Stolen Memory base and length",
		    __func__);
		return (error);
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
		 * platforms like Tiger Lake will read the Graphics Stolen
		 * Memory address from an MMIO register. We have three options
		 * to solve this issue:
		 * 	1. Patch the value in the MMIO register
		 * 		This could have unintended side effects. Without
		 * 		any documentation how this register is used by
		 *		the GPU, don't do it.
		 * 	2. Trap the MMIO register
		 * 		It's not possible to trap a single MMIO
		 *		register. We need to trap a whole page. Trapping
		 *		a bunch of MMIO register could degrade the
		 *		performance noticeably.
		 * 	3. Use an 1:1 host to guest mapping
		 *		Maybe not always possible.
		 * As far as we know, no supported platform requires a 1:1
		 * mapping. For that reason, just log a warning.
		 */
		warnx(
		    "Warning: Unable to reuse host address of Graphics Stolen Memory. GPU passthrough might not work properly.");
	}

	const uint64_t bdsm = read_config(&sc->psc_sel, PCIR_BDSM, 4);
	pci_set_cfgdata32(pi, PCIR_BDSM,
	    gsm->gpa | (bdsm & (PCIM_BDSM_GSM_ALIGNMENT - 1)));

	return (0);
}

static int
gvt_d_setup_opregion(struct vmctx *const ctx, struct pci_devinst *const pi,
    const int memfd)
{
	struct passthru_softc *const sc = pi->pi_arg;

	struct passthru_mmio_mapping *const opregion =
	    &sc->psc_mmio_map[GVT_D_MAP_OPREGION];

	const int error = vm_get_memory_region_info(ctx, &opregion->hpa,
	    &opregion->len, MEMORY_REGION_INTEL_OPREGION);
	if (error) {
		warnx("%s: Unable to get OpRegion base and length", __func__);
		return (error);
	}
	opregion->hva = mmap(NULL, opregion->len, PROT_READ, MAP_SHARED, memfd,
	    opregion->hpa);
	if (opregion->hva == MAP_FAILED) {
		warnx("%s: Unable to map host OpRegion", __func__);
		return (-1);
	}
	opregion->gpa = gvt_d_alloc_mmio_memory(opregion->hpa, opregion->len,
	    E820_ALIGNMENT_NONE, E820_TYPE_NVS);
	if (opregion->gpa == 0) {
		warnx(
		    "%s: Unable to add OpRegion to E820 table (hpa 0x%lx len 0x%lx)",
		    __func__, opregion->hpa, opregion->len);
		e820_dump_table();
		return (-1);
	}
	opregion->gva = vm_map_gpa(ctx, opregion->gpa, opregion->len);
	if (opregion->gva == NULL) {
		warnx("%s: Unable to map guest OpRegion", __func__);
		return (-1);
	}
	if (opregion->gpa != opregion->hpa) {
		/*
		 * A 1:1 host to guest mapping is not required but this could
		 * change in the future.
		 */
		warnx(
		    "Warning: Unable to reuse host address of OpRegion. GPU passthrough might not work properly.");
	}

	memcpy(opregion->gva, opregion->hva, opregion->len);

	pci_set_cfgdata32(pi, PCIR_ASLS_CTL, opregion->gpa);

	return (0);
}

int
gvt_d_init(struct vmctx *const ctx, struct pci_devinst *const pi,
    const char *const opts)
{
	int error;

	struct passthru_softc *const sc = pi->pi_arg;

	/* get memory descriptor */
	const int memfd = open(_PATH_MEM, O_RDWR, 0);
	if (memfd < 0) {
		warn("%s: Failed to open %s", __func__, _PATH_MEM);
		return (-1);
	}

	if ((error = gvt_d_setup_gsm(ctx, pi)) != 0) {
		warnx("%s: Unable to setup Graphics Stolen Memory", __func__);
		goto done;
	}

	if ((error = gvt_d_setup_opregion(ctx, pi, memfd)) != 0) {
		warnx("%s: Unable to setup OpRegion", __func__);
		goto done;
	}

	/* protect Graphics Stolen Memory register */
	if ((error = set_pcir_handler(sc, PCIR_BDSM, 4,
		 passthru_cfgread_emulate, passthru_cfgwrite_emulate)) != 0) {
		warnx("%s: Unable to protect opregion", __func__);
		goto done;
	}
	/* protect opregion register */
	if ((error = set_pcir_handler(sc, PCIR_ASLS_CTL, 4,
		 passthru_cfgread_emulate, gvt_d_aslswrite)) != 0) {
		warnx("%s: Unable to protect opregion", __func__);
		goto done;
	}

done:
	return (error);
}

void
gvt_d_deinit(struct vmctx *const ctx, struct pci_devinst *const pi)
{
	struct passthru_softc *const sc = pi->pi_arg;

	struct passthru_mmio_mapping *const opregion =
	    &sc->psc_mmio_map[GVT_D_MAP_OPREGION];

	/* HVA is only set, if it's initialized */
	if (opregion->hva)
		munmap((void *)opregion->hva, opregion->len);
}
