/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/pciio.h>
#include <sys/ioctl.h>

#include <dev/io/iodev.h>
#include <dev/pci/pcireg.h>

#include <machine/iodev.h>

#ifndef WITHOUT_CAPSICUM
#include <capsicum_helpers.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sysexits.h>
#include <unistd.h>

#include <machine/vmm.h>
#include "mem.h"
#include "pci_passthru.h"

#ifndef _PATH_DEVPCI
#define	_PATH_DEVPCI	"/dev/pci"
#endif

#ifndef	_PATH_DEVIO
#define	_PATH_DEVIO	"/dev/io"
#endif

#ifndef _PATH_MEM
#define	_PATH_MEM	"/dev/mem"
#endif

#define	LEGACY_SUPPORT	1

#define MSIX_TABLE_COUNT(ctrl) (((ctrl) & PCIM_MSIXCTRL_TABLE_SIZE) + 1)
#define MSIX_CAPLEN 12

#define PCI_CAP_START_OFFSET 0x40

static int pcifd = -1;
static int iofd = -1;
static int memfd = -1;

static int
msi_caplen(int msgctrl)
{
	int len;
	
	len = 10;		/* minimum length of msi capability */

	if (msgctrl & PCIM_MSICTRL_64BIT)
		len += 4;

#if 0
	/*
	 * Ignore the 'mask' and 'pending' bits in the MSI capability.
	 * We'll let the guest manipulate them directly.
	 */
	if (msgctrl & PCIM_MSICTRL_VECTOR)
		len += 10;
#endif

	return (len);
}

uint32_t
read_config(const struct pcisel *sel, long reg, int width)
{
	struct pci_io pi;

	bzero(&pi, sizeof(pi));
	pi.pi_sel = *sel;
	pi.pi_reg = reg;
	pi.pi_width = width;

	if (ioctl(pcifd, PCIOCREAD, &pi) < 0)
		return (0);				/* XXX */
	else
		return (pi.pi_data);
}

void
write_config(const struct pcisel *sel, long reg, int width, uint32_t data)
{
	struct pci_io pi;

	bzero(&pi, sizeof(pi));
	pi.pi_sel = *sel;
	pi.pi_reg = reg;
	pi.pi_width = width;
	pi.pi_data = data;

	(void)ioctl(pcifd, PCIOCWRITE, &pi);		/* XXX */
}

#ifdef LEGACY_SUPPORT
static int
passthru_add_msicap(struct pci_devinst *pi, int msgnum, int nextptr)
{
	int capoff, i;
	struct msicap msicap;
	u_char *capdata;

	pci_populate_msicap(&msicap, msgnum, nextptr);

	/*
	 * XXX
	 * Copy the msi capability structure in the last 16 bytes of the
	 * config space. This is wrong because it could shadow something
	 * useful to the device.
	 */
	capoff = 256 - roundup(sizeof(msicap), 4);
	capdata = (u_char *)&msicap;
	for (i = 0; i < sizeof(msicap); i++)
		pci_set_cfgdata8(pi, capoff + i, capdata[i]);

	return (capoff);
}
#endif	/* LEGACY_SUPPORT */

static int
cfginitmsi(struct passthru_softc *sc)
{
	int i, ptr, capptr, cap, sts, caplen, table_size;
	uint32_t u32;
	struct pcisel sel;
	struct pci_devinst *pi;
	struct msixcap msixcap;
	uint32_t *msixcap_ptr;

	pi = sc->psc_pi;
	sel = sc->psc_sel;

	/*
	 * Parse the capabilities and cache the location of the MSI
	 * and MSI-X capabilities.
	 */
	sts = read_config(&sel, PCIR_STATUS, 2);
	if (sts & PCIM_STATUS_CAPPRESENT) {
		ptr = read_config(&sel, PCIR_CAP_PTR, 1);
		while (ptr != 0 && ptr != 0xff) {
			cap = read_config(&sel, ptr + PCICAP_ID, 1);
			if (cap == PCIY_MSI) {
				/*
				 * Copy the MSI capability into the config
				 * space of the emulated pci device
				 */
				sc->psc_msi.capoff = ptr;
				sc->psc_msi.msgctrl = read_config(&sel,
								  ptr + 2, 2);
				sc->psc_msi.emulated = 0;
				caplen = msi_caplen(sc->psc_msi.msgctrl);
				capptr = ptr;
				while (caplen > 0) {
					u32 = read_config(&sel, capptr, 4);
					pci_set_cfgdata32(pi, capptr, u32);
					caplen -= 4;
					capptr += 4;
				}
			} else if (cap == PCIY_MSIX) {
				/*
				 * Copy the MSI-X capability 
				 */
				sc->psc_msix.capoff = ptr;
				caplen = 12;
				msixcap_ptr = (uint32_t*) &msixcap;
				capptr = ptr;
				while (caplen > 0) {
					u32 = read_config(&sel, capptr, 4);
					*msixcap_ptr = u32;
					pci_set_cfgdata32(pi, capptr, u32);
					caplen -= 4;
					capptr += 4;
					msixcap_ptr++;
				}
			}
			ptr = read_config(&sel, ptr + PCICAP_NEXTPTR, 1);
		}
	}

	if (sc->psc_msix.capoff != 0) {
		pi->pi_msix.pba_bar =
		    msixcap.pba_info & PCIM_MSIX_BIR_MASK;
		pi->pi_msix.pba_offset =
		    msixcap.pba_info & ~PCIM_MSIX_BIR_MASK;
		pi->pi_msix.table_bar =
		    msixcap.table_info & PCIM_MSIX_BIR_MASK;
		pi->pi_msix.table_offset =
		    msixcap.table_info & ~PCIM_MSIX_BIR_MASK;
		pi->pi_msix.table_count = MSIX_TABLE_COUNT(msixcap.msgctrl);
		pi->pi_msix.pba_size = PBA_SIZE(pi->pi_msix.table_count);

		/* Allocate the emulated MSI-X table array */
		table_size = pi->pi_msix.table_count * MSIX_TABLE_ENTRY_SIZE;
		pi->pi_msix.table = calloc(1, table_size);

		/* Mask all table entries */
		for (i = 0; i < pi->pi_msix.table_count; i++) {
			pi->pi_msix.table[i].vector_control |=
						PCIM_MSIX_VCTRL_MASK;
		}
	}

#ifdef LEGACY_SUPPORT
	/*
	 * If the passthrough device does not support MSI then craft a
	 * MSI capability for it. We link the new MSI capability at the
	 * head of the list of capabilities.
	 */
	if ((sts & PCIM_STATUS_CAPPRESENT) != 0 && sc->psc_msi.capoff == 0) {
		int origptr, msiptr;
		origptr = read_config(&sel, PCIR_CAP_PTR, 1);
		msiptr = passthru_add_msicap(pi, 1, origptr);
		sc->psc_msi.capoff = msiptr;
		sc->psc_msi.msgctrl = pci_get_cfgdata16(pi, msiptr + 2);
		sc->psc_msi.emulated = 1;
		pci_set_cfgdata8(pi, PCIR_CAP_PTR, msiptr);
	}
#endif

	/* Make sure one of the capabilities is present */
	if (sc->psc_msi.capoff == 0 && sc->psc_msix.capoff == 0) 
		return (-1);
	else
		return (0);
}

static uint64_t
msix_table_read(struct passthru_softc *sc, uint64_t offset, int size)
{
	struct pci_devinst *pi;
	struct msix_table_entry *entry;
	uint8_t *src8;
	uint16_t *src16;
	uint32_t *src32;
	uint64_t *src64;
	uint64_t data;
	size_t entry_offset;
	int index;

	pi = sc->psc_pi;
	if (pi->pi_msix.pba_page != NULL && offset >= pi->pi_msix.pba_offset &&
	    offset < pi->pi_msix.pba_offset + pi->pi_msix.pba_size) {
		switch(size) {
		case 1:
			src8 = (uint8_t *)(pi->pi_msix.pba_page + offset -
			    pi->pi_msix.pba_page_offset);
			data = *src8;
			break;
		case 2:
			src16 = (uint16_t *)(pi->pi_msix.pba_page + offset -
			    pi->pi_msix.pba_page_offset);
			data = *src16;
			break;
		case 4:
			src32 = (uint32_t *)(pi->pi_msix.pba_page + offset -
			    pi->pi_msix.pba_page_offset);
			data = *src32;
			break;
		case 8:
			src64 = (uint64_t *)(pi->pi_msix.pba_page + offset -
			    pi->pi_msix.pba_page_offset);
			data = *src64;
			break;
		default:
			return (-1);
		}
		return (data);
	}

	if (offset < pi->pi_msix.table_offset)
		return (-1);

	offset -= pi->pi_msix.table_offset;
	index = offset / MSIX_TABLE_ENTRY_SIZE;
	if (index >= pi->pi_msix.table_count)
		return (-1);

	entry = &pi->pi_msix.table[index];
	entry_offset = offset % MSIX_TABLE_ENTRY_SIZE;

	switch(size) {
	case 1:
		src8 = (uint8_t *)((void *)entry + entry_offset);
		data = *src8;
		break;
	case 2:
		src16 = (uint16_t *)((void *)entry + entry_offset);
		data = *src16;
		break;
	case 4:
		src32 = (uint32_t *)((void *)entry + entry_offset);
		data = *src32;
		break;
	case 8:
		src64 = (uint64_t *)((void *)entry + entry_offset);
		data = *src64;
		break;
	default:
		return (-1);
	}

	return (data);
}

static void
msix_table_write(struct vmctx *ctx, int vcpu, struct passthru_softc *sc,
		 uint64_t offset, int size, uint64_t data)
{
	struct pci_devinst *pi;
	struct msix_table_entry *entry;
	uint8_t *dest8;
	uint16_t *dest16;
	uint32_t *dest32;
	uint64_t *dest64;
	size_t entry_offset;
	uint32_t vector_control;
	int index;

	pi = sc->psc_pi;
	if (pi->pi_msix.pba_page != NULL && offset >= pi->pi_msix.pba_offset &&
	    offset < pi->pi_msix.pba_offset + pi->pi_msix.pba_size) {
		switch(size) {
		case 1:
			dest8 = (uint8_t *)(pi->pi_msix.pba_page + offset -
			    pi->pi_msix.pba_page_offset);
			*dest8 = data;
			break;
		case 2:
			dest16 = (uint16_t *)(pi->pi_msix.pba_page + offset -
			    pi->pi_msix.pba_page_offset);
			*dest16 = data;
			break;
		case 4:
			dest32 = (uint32_t *)(pi->pi_msix.pba_page + offset -
			    pi->pi_msix.pba_page_offset);
			*dest32 = data;
			break;
		case 8:
			dest64 = (uint64_t *)(pi->pi_msix.pba_page + offset -
			    pi->pi_msix.pba_page_offset);
			*dest64 = data;
			break;
		default:
			break;
		}
		return;
	}

	if (offset < pi->pi_msix.table_offset)
		return;

	offset -= pi->pi_msix.table_offset;
	index = offset / MSIX_TABLE_ENTRY_SIZE;
	if (index >= pi->pi_msix.table_count)
		return;

	entry = &pi->pi_msix.table[index];
	entry_offset = offset % MSIX_TABLE_ENTRY_SIZE;

	/* Only 4 byte naturally-aligned writes are supported */
	assert(size == 4);
	assert(entry_offset % 4 == 0);

	vector_control = entry->vector_control;
	dest32 = (uint32_t *)((void *)entry + entry_offset);
	*dest32 = data;
	/* If MSI-X hasn't been enabled, do nothing */
	if (pi->pi_msix.enabled) {
		/* If the entry is masked, don't set it up */
		if ((entry->vector_control & PCIM_MSIX_VCTRL_MASK) == 0 ||
		    (vector_control & PCIM_MSIX_VCTRL_MASK) == 0) {
			(void)vm_setup_pptdev_msix(ctx, vcpu,
			    sc->psc_sel.pc_bus, sc->psc_sel.pc_dev,
			    sc->psc_sel.pc_func, index, entry->addr,
			    entry->msg_data, entry->vector_control);
		}
	}
}

static int
init_msix_table(struct vmctx *ctx, struct passthru_softc *sc, uint64_t base)
{
	int b, s, f;
	int idx;
	size_t remaining;
	uint32_t table_size, table_offset;
	uint32_t pba_size, pba_offset;
	vm_paddr_t start;
	struct pci_devinst *pi = sc->psc_pi;

	assert(pci_msix_table_bar(pi) >= 0 && pci_msix_pba_bar(pi) >= 0);

	b = sc->psc_sel.pc_bus;
	s = sc->psc_sel.pc_dev;
	f = sc->psc_sel.pc_func;

	/* 
	 * If the MSI-X table BAR maps memory intended for
	 * other uses, it is at least assured that the table 
	 * either resides in its own page within the region, 
	 * or it resides in a page shared with only the PBA.
	 */
	table_offset = rounddown2(pi->pi_msix.table_offset, 4096);

	table_size = pi->pi_msix.table_offset - table_offset;
	table_size += pi->pi_msix.table_count * MSIX_TABLE_ENTRY_SIZE;
	table_size = roundup2(table_size, 4096);

	idx = pi->pi_msix.table_bar;
	start = pi->pi_bar[idx].addr;
	remaining = pi->pi_bar[idx].size;

	if (pi->pi_msix.pba_bar == pi->pi_msix.table_bar) {
		pba_offset = pi->pi_msix.pba_offset;
		pba_size = pi->pi_msix.pba_size;
		if (pba_offset >= table_offset + table_size ||
		    table_offset >= pba_offset + pba_size) {
			/*
			 * If the PBA does not share a page with the MSI-x
			 * tables, no PBA emulation is required.
			 */
			pi->pi_msix.pba_page = NULL;
			pi->pi_msix.pba_page_offset = 0;
		} else {
			/*
			 * The PBA overlaps with either the first or last
			 * page of the MSI-X table region.  Map the
			 * appropriate page.
			 */
			if (pba_offset <= table_offset)
				pi->pi_msix.pba_page_offset = table_offset;
			else
				pi->pi_msix.pba_page_offset = table_offset +
				    table_size - 4096;
			pi->pi_msix.pba_page = mmap(NULL, 4096, PROT_READ |
			    PROT_WRITE, MAP_SHARED, memfd, start +
			    pi->pi_msix.pba_page_offset);
			if (pi->pi_msix.pba_page == MAP_FAILED) {
				warn(
			    "Failed to map PBA page for MSI-X on %d/%d/%d",
				    b, s, f);
				return (-1);
			}
		}
	}

	return (0);
}

static int
cfginitbar(struct vmctx *ctx, struct passthru_softc *sc)
{
	int i, error;
	struct pci_devinst *pi;
	struct pci_bar_io bar;
	enum pcibar_type bartype;
	uint64_t base, size;

	pi = sc->psc_pi;

	/*
	 * Initialize BAR registers
	 */
	for (i = 0; i <= PCI_BARMAX; i++) {
		bzero(&bar, sizeof(bar));
		bar.pbi_sel = sc->psc_sel;
		bar.pbi_reg = PCIR_BAR(i);

		if (ioctl(pcifd, PCIOCGETBAR, &bar) < 0)
			continue;

		if (PCI_BAR_IO(bar.pbi_base)) {
			bartype = PCIBAR_IO;
			base = bar.pbi_base & PCIM_BAR_IO_BASE;
		} else {
			switch (bar.pbi_base & PCIM_BAR_MEM_TYPE) {
			case PCIM_BAR_MEM_64:
				bartype = PCIBAR_MEM64;
				break;
			default:
				bartype = PCIBAR_MEM32;
				break;
			}
			base = bar.pbi_base & PCIM_BAR_MEM_BASE;
		}
		size = bar.pbi_length;

		if (bartype != PCIBAR_IO) {
			if (((base | size) & PAGE_MASK) != 0) {
				warnx("passthru device %d/%d/%d BAR %d: "
				    "base %#lx or size %#lx not page aligned\n",
				    sc->psc_sel.pc_bus, sc->psc_sel.pc_dev,
				    sc->psc_sel.pc_func, i, base, size);
				return (-1);
			}
		}

		/* Cache information about the "real" BAR */
		sc->psc_bar[i].type = bartype;
		sc->psc_bar[i].size = size;
		sc->psc_bar[i].addr = base;
		sc->psc_bar[i].lobits = 0;

		/* Allocate the BAR in the guest I/O or MMIO space */
		error = pci_emul_alloc_bar(pi, i, bartype, size);
		if (error)
			return (-1);

		/* Use same lobits as physical bar */
		uint8_t lobits = read_config(&sc->psc_sel, PCIR_BAR(i), 0x01);
		if (bartype == PCIBAR_MEM32 || bartype == PCIBAR_MEM64) {
			lobits &= ~PCIM_BAR_MEM_BASE;
		} else {
			lobits &= ~PCIM_BAR_IO_BASE;
		}
		sc->psc_bar[i].lobits = lobits;
		pi->pi_bar[i].lobits = lobits;

		/* The MSI-X table needs special handling */
		if (i == pci_msix_table_bar(pi)) {
			error = init_msix_table(ctx, sc, base);
			if (error) 
				return (-1);
		}

		/*
		 * 64-bit BAR takes up two slots so skip the next one.
		 */
		if (bartype == PCIBAR_MEM64) {
			i++;
			assert(i <= PCI_BARMAX);
			sc->psc_bar[i].type = PCIBAR_MEMHI64;
		}
	}
	return (0);
}

static int
cfginit(struct vmctx *ctx, struct pci_devinst *pi, int bus, int slot, int func)
{
	int error;
	struct passthru_softc *sc;

	error = 1;
	sc = pi->pi_arg;

	bzero(&sc->psc_sel, sizeof(struct pcisel));
	sc->psc_sel.pc_bus = bus;
	sc->psc_sel.pc_dev = slot;
	sc->psc_sel.pc_func = func;

	/* copy physical PCI header to virtual cfgspace */
	for (uint32_t i = 0; i < PCI_CAP_START_OFFSET; ++i) {
		/*
		 * INTLINE and INTPIN shouldn't be aligned with it's physical
		 * value. They are already set by pci_emul_init.
		 */
		if (i == PCIR_INTLINE || i == PCIR_INTPIN)
			continue;
		pci_set_cfgdata8(pi, i, read_config(&sc->psc_sel, i, 1));
	}

	if (cfginitmsi(sc) != 0) {
		warnx("failed to initialize MSI for PCI %d/%d/%d",
		    bus, slot, func);
		goto done;
	}

	if (cfginitbar(ctx, sc) != 0) {
		warnx("failed to initialize BARs for PCI %d/%d/%d",
		    bus, slot, func);
		goto done;
	}

	write_config(
	    &sc->psc_sel, PCIR_COMMAND, 2, pci_get_cfgdata16(pi, PCIR_COMMAND));

	error = 0;				/* success */
done:
	return (error);
}

int
set_pcir_handler(struct passthru_softc *const sc, const uint32_t reg,
    const uint32_t len, const cfgread_handler rhandler,
    const cfgwrite_handler whandler)
{
	if (reg > PCI_REGMAX || reg + len > PCI_REGMAX + 1)
		return (-1);

	for (uint32_t i = reg; i < reg + len; ++i) {
		sc->psc_pcir_rhandler[i] = rhandler;
		sc->psc_pcir_whandler[i] = whandler;
	}

	return 0;
}

static int
passthru_init_quirks(struct vmctx *const ctx, struct pci_devinst *const pi,
    const char *const opts)
{
	struct passthru_softc *const sc = pi->pi_arg;

	const uint16_t vendor = read_config(&sc->psc_sel, PCIR_VENDOR, 0x02);
	const uint8_t class = read_config(&sc->psc_sel, PCIR_CLASS, 0x01);

	/* currently only display devices have quirks */
	if (class != PCIC_DISPLAY)
		return (0);

	if (vendor == PCI_VENDOR_INTEL)
		return gvt_d_init(ctx, pi, opts);

	return (0);
}

static void
passthru_deinit_quirks(struct vmctx *const ctx, struct pci_devinst *const pi)
{
	struct passthru_softc *const sc = pi->pi_arg;

	if (sc == NULL)
		return;

	const uint16_t vendor = read_config(&sc->psc_sel, PCIR_VENDOR, 0x02);
	const uint8_t class = read_config(&sc->psc_sel, PCIR_CLASS, 0x01);

	/* currently only display devices have quirks */
	if (class != PCIC_DISPLAY)
		return;

	if (vendor == PCI_VENDOR_INTEL)
		return gvt_d_deinit(ctx, pi);

	return;
}

static void
passthru_usage(const char *const opt)
{
	warnx("Invalid passthru option \"%s\"", opt);
	warnx("passthru,<bus>/<dev>/<func>,{rom=rom_file}");
}

static int
passthru_parse_opts(struct passthru_softc *const sc, const char *const opts)
{
	int error = 0;
	char *const uopts = strdup(opts);
	const char *xopt = strtok(uopts, ",");
	for (xopt = strtok(NULL, ","); xopt != NULL; xopt = strtok(NULL, ",")) {
		char *config = strchr(xopt, '=');
		if (config == NULL) {
			error = -1;
			break;
		}
		*config = '\0';
		++config;
		if (strcmp(xopt, "rom") == 0) {
			const int fd = open(config, O_RDONLY);
			if (fd < 0) {
				warnx("%s: can't open romfile \"%s\"", __func__,
				    config);
				error = -1;
				break;
			}
			/* determine file size */
			const uint64_t rom_size = lseek(fd, 0, SEEK_END);
			lseek(fd, 0, SEEK_SET);
			/* read bios */
			void *const rom_addr = malloc(rom_size);
			if (rom_addr == NULL) {
				warnx(
				    "%s: an't malloc rom \"%s\" (size: 0x%8lx)",
				    __func__, config, rom_size);
				error = -ENOMEM;
				close(fd);
				break;
			}
			if (read(fd, rom_addr, rom_size) != rom_size) {
				warnx(
				    "%s: unable to read whole rom \"%s\" (size: 0x%8lx)",
				    __func__, config, rom_size);
				error = -EIO;
				close(fd);
				break;
			}
			close(fd);

			/* save physical values of ROM */
			sc->psc_bar[PCI_ROM_IDX].type = PCIBAR_ROM;
			sc->psc_bar[PCI_ROM_IDX].addr = (uint64_t)rom_addr;
			sc->psc_bar[PCI_ROM_IDX].size = rom_size;

			continue;
		} else {
			/* unknown option */
			error = -1;
		}
		/* option wasn't processed */
		passthru_usage(xopt);
		break;
	}

	return (error);
}

static int
passthru_init_rom(struct vmctx *const ctx, struct passthru_softc *const sc)
{
	/* check if this device has a rom */
	if (sc->psc_bar[PCI_ROM_IDX].size == 0)
		return (0);

	/* allocate ROM */
	uint64_t rom_addr;
	int error = pci_emul_alloc_rom(sc->psc_pi,
	    sc->psc_bar[PCI_ROM_IDX].size, &rom_addr);
	if (error) {
		warnx("Failed to alloc ROM");
		goto done;
	}

	/* copy ROM to guest */
	memcpy((void *)rom_addr, (void *)sc->psc_bar[PCI_ROM_IDX].addr,
	    sc->psc_bar[PCI_ROM_IDX].size);
	/* free ROM */
	free((void *)sc->psc_bar[PCI_ROM_IDX].addr);
	/* save new address of ROM */
	sc->psc_bar[PCI_ROM_IDX].addr = rom_addr;

done:
	return error;
}

static int
passthru_init(struct vmctx *ctx, struct pci_devinst *pi, char *opts)
{
	int bus, slot, func, error, memflags;
	struct passthru_softc *sc;
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
	cap_ioctl_t pci_ioctls[] = { PCIOCREAD, PCIOCWRITE, PCIOCGETBAR };
	cap_ioctl_t io_ioctls[] = { IODEV_PIO };
#endif

	sc = NULL;
	error = 1;

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_IOCTL, CAP_READ, CAP_WRITE);
#endif

	memflags = vm_get_memflags(ctx);
	if (!(memflags & VM_MEM_F_WIRED)) {
		warnx("passthru requires guest memory to be wired");
		return (error);
	}

	if (pcifd < 0) {
		pcifd = open(_PATH_DEVPCI, O_RDWR, 0);
		if (pcifd < 0) {
			warn("failed to open %s", _PATH_DEVPCI);
			return (error);
		}
	}

#ifndef WITHOUT_CAPSICUM
	if (caph_rights_limit(pcifd, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
	if (caph_ioctls_limit(pcifd, pci_ioctls, nitems(pci_ioctls)) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

	if (iofd < 0) {
		iofd = open(_PATH_DEVIO, O_RDWR, 0);
		if (iofd < 0) {
			warn("failed to open %s", _PATH_DEVIO);
			return (error);
		}
	}

#ifndef WITHOUT_CAPSICUM
	if (caph_rights_limit(iofd, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
	if (caph_ioctls_limit(iofd, io_ioctls, nitems(io_ioctls)) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

	if (memfd < 0) {
		memfd = open(_PATH_MEM, O_RDWR, 0);
		if (memfd < 0) {
			warn("failed to open %s", _PATH_MEM);
			return (error);
		}
	}

#ifndef WITHOUT_CAPSICUM
	cap_rights_clear(&rights, CAP_IOCTL);
	cap_rights_set(&rights, CAP_MMAP_RW);
	if (caph_rights_limit(memfd, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

	if (opts == NULL ||
	    sscanf(opts, "%d/%d/%d", &bus, &slot, &func) != 3) {
		warnx("invalid passthru options");
		return (error);
	}

	if (vm_assign_pptdev(ctx, bus, slot, func) != 0) {
		warnx("PCI device at %d/%d/%d is not using the ppt(4) driver",
		    bus, slot, func);
		goto done;
	}

	sc = calloc(1, sizeof(struct passthru_softc));

	pi->pi_arg = sc;
	sc->psc_pi = pi;

	/* parse opts */
	if ((error = passthru_parse_opts(sc, opts)) != 0) {
		warnx("invalid passthru options");
		goto done;
	}

	/* initialize config space */
	if ((error = cfginit(ctx, pi, bus, slot, func)) != 0)
		goto done;

	/* set default handler for all PCI registers */
	if ((error = set_pcir_handler(sc, 0, PCI_REGMAX + 1,
		 passthru_cfgread_default, passthru_cfgwrite_default)) != 0)
		goto done;
	/* protect PCI header */
	if ((error = set_pcir_handler(sc, 0, PCI_CAP_START_OFFSET,
		 passthru_cfgread_emulate, passthru_cfgwrite_emulate)) != 0)
		goto done;
	/* allow access to command and status register */
	if ((error = set_pcir_handler(sc, PCIR_COMMAND, 0x04,
		 passthru_cfgread_default, passthru_cfgwrite_default)) != 0)
		goto done;

	/*
	 * init_quirks may modify PCI register protection. Additionally, it may
	 * fetch a ROM for a device.
	 *
	 * Therefore, keep following order!!
	 * Before init_quirks:
	 * 	set protection for PCI register
	 * After init_quirks:
	 * 	init ROM
	 */
	if ((error = passthru_init_quirks(ctx, pi, opts)) != 0)
		goto done;

	/* initialize ROM */
	if ((error = passthru_init_rom(ctx, sc)) != 0)
		goto done;

	error = 0;		/* success */
done:
	if (error) {
		passthru_deinit_quirks(ctx, pi);
		free(sc);
		vm_unassign_pptdev(ctx, bus, slot, func);
	}
	return (error);
}

static int
bar_access(int coff)
{
	if (coff >= PCIR_BAR(0) && coff < PCIR_BAR(PCI_BARMAX + 1))
		return (1);
	else
		return (0);
}

static int
msicap_access(struct passthru_softc *sc, int coff)
{
	int caplen;

	if (sc->psc_msi.capoff == 0)
		return (0);

	caplen = msi_caplen(sc->psc_msi.msgctrl);

	if (coff >= sc->psc_msi.capoff && coff < sc->psc_msi.capoff + caplen)
		return (1);
	else
		return (0);
}

static int 
msixcap_access(struct passthru_softc *sc, int coff)
{
	if (sc->psc_msix.capoff == 0) 
		return (0);

	return (coff >= sc->psc_msix.capoff && 
	        coff < sc->psc_msix.capoff + MSIX_CAPLEN);
}

static int
passthru_cfgread(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
		 int coff, int bytes, uint32_t *rv)
{
	struct passthru_softc *const sc = pi->pi_arg;

	return sc->psc_pcir_rhandler[coff](ctx, vcpu, pi, coff, bytes, rv);
}

int
passthru_cfgread_default(struct vmctx *const ctx, const int vcpu,
    struct pci_devinst *const pi, const int coff, const int bytes,
    uint32_t *const rv)
{
	struct passthru_softc *sc;

	sc = pi->pi_arg;

	/*
	 * MSI capability is emulated.
	 */
	if (msicap_access(sc, coff) || msixcap_access(sc, coff))
		return (-1);

	/*
	 * Emulate the command register.  If a single read reads both the
	 * command and status registers, read the status register from the
	 * device's config space.
	 */
	if (coff == PCIR_COMMAND) {
		if (bytes <= 2)
			return (-1);
		*rv = read_config(&sc->psc_sel, PCIR_STATUS, 2) << 16 |
		    pci_get_cfgdata16(pi, PCIR_COMMAND);
		return (0);
	}

	/* Everything else just read from the device's config space */
	*rv = read_config(&sc->psc_sel, coff, bytes);

	return (0);
}

int
passthru_cfgread_emulate(struct vmctx *const ctx, const int vcpu,
    struct pci_devinst *const pi, const int coff, const int bytes,
    uint32_t *const rv)
{
	return (-1);
}

static int
passthru_cfgwrite(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
		  int coff, int bytes, uint32_t val)
{
	struct passthru_softc *const sc = pi->pi_arg;

	return sc->psc_pcir_whandler[coff](ctx, vcpu, pi, coff, bytes, val);
}

int
passthru_cfgwrite_default(struct vmctx *const ctx, const int vcpu,
    struct pci_devinst *const pi, const int coff, const int bytes,
    const uint32_t val)
{
	int error, msix_table_entries, i;
	struct passthru_softc *sc;
	uint16_t cmd_old;

	sc = pi->pi_arg;

	/*
	 * MSI capability is emulated
	 */
	if (msicap_access(sc, coff)) {
		pci_emul_capwrite(pi, coff, bytes, val, sc->psc_msi.capoff,
		    PCIY_MSI);
		error = vm_setup_pptdev_msi(ctx, vcpu, sc->psc_sel.pc_bus,
			sc->psc_sel.pc_dev, sc->psc_sel.pc_func,
			pi->pi_msi.addr, pi->pi_msi.msg_data,
			pi->pi_msi.maxmsgnum);
		if (error != 0)
			err(1, "vm_setup_pptdev_msi");
		return (0);
	}

	if (msixcap_access(sc, coff)) {
		pci_emul_capwrite(pi, coff, bytes, val, sc->psc_msix.capoff,
		    PCIY_MSIX);
		if (pi->pi_msix.enabled) {
			msix_table_entries = pi->pi_msix.table_count;
			for (i = 0; i < msix_table_entries; i++) {
				error = vm_setup_pptdev_msix(ctx, vcpu,
				    sc->psc_sel.pc_bus, sc->psc_sel.pc_dev, 
				    sc->psc_sel.pc_func, i, 
				    pi->pi_msix.table[i].addr,
				    pi->pi_msix.table[i].msg_data,
				    pi->pi_msix.table[i].vector_control);
		
				if (error)
					err(1, "vm_setup_pptdev_msix");
			}
		} else {
			error = vm_disable_pptdev_msix(ctx, sc->psc_sel.pc_bus,
			    sc->psc_sel.pc_dev, sc->psc_sel.pc_func);
			if (error)
				err(1, "vm_disable_pptdev_msix");
		}
		return (0);
	}

	uint32_t write_val = val;
#ifdef LEGACY_SUPPORT
	/*
	 * If this device does not support MSI natively then we cannot let
	 * the guest disable legacy interrupts from the device. It is the
	 * legacy interrupt that is triggering the virtual MSI to the guest.
	 */
	if (sc->psc_msi.emulated && pci_msi_enabled(pi)) {
		if (coff == PCIR_COMMAND && bytes == 2)
			write_val &= ~PCIM_CMD_INTxDIS;
	}
#endif

	write_config(&sc->psc_sel, coff, bytes, write_val);
	if (coff == PCIR_COMMAND) {
		cmd_old = pci_get_cfgdata16(pi, PCIR_COMMAND);
		if (bytes == 1)
			pci_set_cfgdata8(pi, PCIR_COMMAND, write_val);
		else if (bytes == 2)
			pci_set_cfgdata16(pi, PCIR_COMMAND, write_val);
		pci_emul_cmd_changed(pi, cmd_old);
	}

	return (0);
}

int
passthru_cfgwrite_emulate(struct vmctx *const ctx, const int vcpu,
    struct pci_devinst *const pi, const int coff, const int bytes,
    const uint32_t val)
{
	return (-1);
}

static void
passthru_write(struct vmctx *ctx, int vcpu, struct pci_devinst *pi, int baridx,
	       uint64_t offset, int size, uint64_t value)
{
	struct passthru_softc *sc;
	struct iodev_pio_req pio;

	sc = pi->pi_arg;

	if (baridx == pci_msix_table_bar(pi)) {
		msix_table_write(ctx, vcpu, sc, offset, size, value);
	} else {
		assert(pi->pi_bar[baridx].type == PCIBAR_IO);
		bzero(&pio, sizeof(struct iodev_pio_req));
		pio.access = IODEV_PIO_WRITE;
		pio.port = sc->psc_bar[baridx].addr + offset;
		pio.width = size;
		pio.val = value;
		
		(void)ioctl(iofd, IODEV_PIO, &pio);
	}
}

static uint64_t
passthru_read(struct vmctx *ctx, int vcpu, struct pci_devinst *pi, int baridx,
	      uint64_t offset, int size)
{
	struct passthru_softc *sc;
	struct iodev_pio_req pio;
	uint64_t val;

	sc = pi->pi_arg;

	if (baridx == pci_msix_table_bar(pi)) {
		val = msix_table_read(sc, offset, size);
	} else {
		assert(pi->pi_bar[baridx].type == PCIBAR_IO);
		bzero(&pio, sizeof(struct iodev_pio_req));
		pio.access = IODEV_PIO_READ;
		pio.port = sc->psc_bar[baridx].addr + offset;
		pio.width = size;
		pio.val = 0;

		(void)ioctl(iofd, IODEV_PIO, &pio);

		val = pio.val;
	}

	return (val);
}

static void
passthru_msix_addr(struct vmctx *ctx, struct pci_devinst *pi, int baridx,
		   int enabled, uint64_t address)
{
	struct passthru_softc *sc;
	size_t remaining;
	uint32_t table_size, table_offset;

	sc = pi->pi_arg;
	table_offset = rounddown2(pi->pi_msix.table_offset, 4096);
	if (table_offset > 0) {
		if (!enabled) {
			if (vm_unmap_pptdev_mmio(ctx, sc->psc_sel.pc_bus,
						 sc->psc_sel.pc_dev,
						 sc->psc_sel.pc_func, address,
						 table_offset) != 0)
				warnx("pci_passthru: unmap_pptdev_mmio failed");
		} else {
			if (vm_map_pptdev_mmio(ctx, sc->psc_sel.pc_bus,
					       sc->psc_sel.pc_dev,
					       sc->psc_sel.pc_func, address,
					       table_offset,
					       sc->psc_bar[baridx].addr) != 0)
				warnx("pci_passthru: map_pptdev_mmio failed");
		}
	}
	table_size = pi->pi_msix.table_offset - table_offset;
	table_size += pi->pi_msix.table_count * MSIX_TABLE_ENTRY_SIZE;
	table_size = roundup2(table_size, 4096);
	remaining = pi->pi_bar[baridx].size - table_offset - table_size;
	if (remaining > 0) {
		address += table_offset + table_size;
		if (!enabled) {
			if (vm_unmap_pptdev_mmio(ctx, sc->psc_sel.pc_bus,
						 sc->psc_sel.pc_dev,
						 sc->psc_sel.pc_func, address,
						 remaining) != 0)
				warnx("pci_passthru: unmap_pptdev_mmio failed");
		} else {
			if (vm_map_pptdev_mmio(ctx, sc->psc_sel.pc_bus,
					       sc->psc_sel.pc_dev,
					       sc->psc_sel.pc_func, address,
					       remaining,
					       sc->psc_bar[baridx].addr +
					       table_offset + table_size) != 0)
				warnx("pci_passthru: map_pptdev_mmio failed");
		}
	}
}

static void
passthru_mmio_addr(struct vmctx *ctx, struct pci_devinst *pi, int baridx,
		   int enabled, uint64_t address)
{
	struct passthru_softc *sc;

	sc = pi->pi_arg;
	if (!enabled) {
		if (vm_unmap_pptdev_mmio(ctx, sc->psc_sel.pc_bus,
					 sc->psc_sel.pc_dev,
					 sc->psc_sel.pc_func, address,
					 sc->psc_bar[baridx].size) != 0)
			warnx("pci_passthru: unmap_pptdev_mmio failed");
	} else {
		if (vm_map_pptdev_mmio(ctx, sc->psc_sel.pc_bus,
				       sc->psc_sel.pc_dev,
				       sc->psc_sel.pc_func, address,
				       sc->psc_bar[baridx].size,
				       sc->psc_bar[baridx].addr) != 0)
			warnx("pci_passthru: map_pptdev_mmio failed");
	}
}

static void
passthru_addr_rom(struct pci_devinst *const pi, const int idx,
    const int enabled)
{
	if (!enabled)
		vm_munmap_memseg(pi->pi_vmctx, pi->pi_bar[idx].addr,
		    pi->pi_bar[idx].size);
	else
		vm_mmap_memseg(pi->pi_vmctx, pi->pi_bar[idx].addr, VM_PCIROM,
		    pi->pi_romoffset, pi->pi_bar[idx].size,
		    PROT_READ | PROT_EXEC);
}

static void
passthru_addr(struct vmctx *ctx, struct pci_devinst *pi, int baridx,
	      int enabled, uint64_t address)
{
	switch (pi->pi_bar[baridx].type) {
	case PCIBAR_IO:
		/* IO BARs are emulated */
		break;
	case PCIBAR_ROM:
		passthru_addr_rom(pi, baridx, enabled);
		break;
	case PCIBAR_MEM32:
	case PCIBAR_MEM64:
		if (baridx == pci_msix_table_bar(pi))
			passthru_msix_addr(ctx, pi, baridx, enabled, address);
		else
			passthru_mmio_addr(ctx, pi, baridx, enabled, address);
		break;
	default:
		errx(4, "%s: invalid BAR type %d", __func__, pi->pi_bar[baridx].type);
	}
}

struct pci_devemu passthru = {
	.pe_emu		= "passthru",
	.pe_init	= passthru_init,
	.pe_cfgwrite	= passthru_cfgwrite,
	.pe_cfgread	= passthru_cfgread,
	.pe_barwrite 	= passthru_write,
	.pe_barread    	= passthru_read,
	.pe_baraddr	= passthru_addr,
};
PCI_EMUL_SET(passthru);
