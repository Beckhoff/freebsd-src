/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2022 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#pragma once

struct tpm_ppi {
	const char *name;

	int (*init)(struct tpm_device *dev);
	void (*deinit)(struct tpm_device *dev);
	int (*write_dsdt_regions)(const struct tpm_device *dev);
	int (*write_dsdt_dsm)(const struct tpm_device *dev);
};
#define TPM_PPI_SET(x) DATA_SET(tpm_ppi_set, x)
