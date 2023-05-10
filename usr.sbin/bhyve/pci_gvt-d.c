/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#include <sys/types.h>

#include "pci_gvt-d.h"
#include "pci_passthru.h"

int
gvt_d_init(struct pci_devinst *const pi __unused, nvlist_t *const nvl __unused)
{
	return (0);
}

void
gvt_d_deinit(struct pci_devinst *const pi __unused)
{
}
