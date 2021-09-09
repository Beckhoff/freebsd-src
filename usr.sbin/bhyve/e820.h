/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#pragma once

#include <vmmapi.h>

#include "qemu_fwcfg.h"

#pragma pack(push, 1)

enum e820_memory_type {
	E820_TYPE_MEMORY = 1,
	E820_TYPE_RESERVED = 2,
	E820_TYPE_ACPI = 3,
	E820_TYPE_NVS = 4
};

struct e820_entry {
	uint64_t base;
	uint64_t length;
	enum e820_memory_type type;
};

#pragma pack(pop)

struct qemu_fwcfg_item *e820_get_fwcfg_item();
int e820_init(struct vmctx *const ctx);
