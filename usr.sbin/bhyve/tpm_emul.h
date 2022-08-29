/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2022 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#pragma once

#include <sys/types.h>

#include <vmmapi.h>

#include "config.h"

struct tpm_device;

struct tpm_emul {
	const char *name;

	int (*init)(struct tpm_device *dev);
	void (*deinit)(struct tpm_device *dev);
	int (*execute_cmd)(struct tpm_device *dev, void *cmd, uint32_t cmd_size,
	    void *rsp, uint32_t rsp_size);
};
#define TPM_EMUL_SET(x) DATA_SET(tpm_emul_set, x)
