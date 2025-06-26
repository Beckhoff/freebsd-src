/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#include <dev/pci/pcireg.h>

#include <err.h>
#include <errno.h>

#include "pci_passthru.h"

#define PCI_VENDOR_NVIDIA 0x10DE

static int
pci_config_mirror_read(struct pci_devinst *const pi, uint64_t off, uint64_t size, uint64_t *rv)
{
	assert(size == 1 || size == 2 || size == 4);
	passthru_read_host(pi, 0, off, size);
	return (passthru_cfgread_default(pi->pi_arg, pi, off, size, (uint32_t *)rv);
}

static int
pci_config_mirror_write(struct pci_devinst *const pi, uint64_t off, uint64_t size, uint64_t val)
{
	assert(size == 1 || size == 2 || size == 4);
	passthru_cfgwrite_default(pi->pi_arg, pi, off, size, val);

	return (0);
}

static int
nvidia_gpu_probe(struct pci_devinst *const pi)
{
	struct passthru_softc *sc;
	uint16_t vendor;
	uint8_t class;

	sc = pi->pi_arg;

	vendor = pci_host_read_config(passthru_get_sel(sc), PCIR_VENDOR, 0x02);
	if (vendor != PCI_VENDOR_NVIDIA)
		return (ENXIO);

	class = pci_host_read_config(passthru_get_sel(sc), PCIR_CLASS, 0x01);
	if (class != PCIC_DISPLAY)
		return (ENXIO);

	return (0);
}

static int
nvidia_gpu_init(struct pci_devinst *const pi, nvlist_t *const nvl __unused)
{
	struct passthru_softc *sc;
	int error = 0;

	sc = pi->pi_arg;

	error = passthru_set_bar_handler(sc, 0, 0x88000, PCIE_REGMAX, pci_config_mirror_read, pci_config_mirror_write);
	if (error) {
		warnx("%s: failed to setup handler for PCI config space mirror!", __func__);
		return (error);
	}

	return (0);
}

static struct passthru_dev nvidia_gpu = {
	.probe = nvidia_gpu_probe,
	.init = nvidia_gpu_init,
};
PASSTHRU_DEV_SET(nvidia_gpu);
