/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2020 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#pragma once

#include <sys/pciio.h>

#include <vmmapi.h>

#include "pci_emul.h"

struct passthru_mmio_mapping {
	vm_paddr_t gpa; /* guest physical address */
	void *gva;	/* guest virtual address */
	vm_paddr_t hpa; /* host physical address */
	void *hva;	/* guest virtual address */
	vm_paddr_t len;
};

typedef int (*cfgread_handler)(struct vmctx *const ctx, const int vcpu,
    struct pci_devinst *const pi, const int coff, const int bytes,
    uint32_t *const rv);
typedef int (*cfgwrite_handler)(struct vmctx *const ctx, const int vcpu,
    struct pci_devinst *const pi, const int coff, const int bytes,
    const uint32_t val);

struct passthru_softc {
	struct pci_devinst *psc_pi;
	struct pcibar psc_bar[PCI_BARMAX + 1];
	struct {
		int capoff;
		int msgctrl;
		int emulated;
	} psc_msi;
	struct {
		int capoff;
	} psc_msix;
	struct pcisel psc_sel;

	struct passthru_mmio_mapping psc_mmio_map[2];
	cfgread_handler psc_pcir_rhandler[PCI_REGMAX + 1];
	cfgwrite_handler psc_pcir_whandler[PCI_REGMAX + 1];
};

uint32_t read_config(const struct pcisel *sel, long reg, int width);
void write_config(const struct pcisel *sel, long reg, int width, uint32_t data);
int passthru_cfgread_default(struct vmctx *const ctx, const int vcpu,
    struct pci_devinst *const pi, const int coff, const int bytes,
    uint32_t *const rv);
int passthru_cfgread_emulate(struct vmctx *const ctx, const int vcpu,
    struct pci_devinst *const pi, const int coff, const int bytes,
    uint32_t *const rv);
int passthru_cfgwrite_default(struct vmctx *const ctx, const int vcpu,
    struct pci_devinst *const pi, const int coff, const int bytes,
    const uint32_t val);
int passthru_cfgwrite_emulate(struct vmctx *const ctx, const int vcpu,
    struct pci_devinst *const pi, const int coff, const int bytes,
    const uint32_t val);
int set_pcir_handler(struct passthru_softc *const sc, const uint32_t reg,
    const uint32_t len, const cfgread_handler rhandler,
    const cfgwrite_handler whandler);
int gvt_d_init(struct vmctx *const ctx, struct pci_devinst *const pi, const char *const opts);
void gvt_d_deinit(struct vmctx *const ctx, struct pci_devinst *const pi);
