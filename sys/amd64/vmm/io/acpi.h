/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#pragma once

#include <machine/vmm.h>
#include <machine/vmm_dev.h>

int vmm_tpm2_get_control_address(vm_paddr_t *const base,
    vm_paddr_t *const size);
