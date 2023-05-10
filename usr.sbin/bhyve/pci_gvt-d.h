/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <corvink@FreeBSD.org>
 */

#pragma once

#include "config.h"
#include "pci_emul.h"

int gvt_d_init(struct pci_devinst *const pi, nvlist_t *const nvl);
void gvt_d_deinit(struct pci_devinst *const pi);
