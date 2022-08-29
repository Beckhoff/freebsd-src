/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 - 2022 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/param.h>

#include <machine/vmm.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <vmmapi.h>

#include "acpi.h"
#include "tpm_device_priv.h"
#include "tpm_emul.h"

struct tpm_passthru {
	int fd;
};

struct tpm_resp_hdr {
	uint16_t tag;
	uint32_t len;
	uint32_t errcode;
} __packed;

static int
tpm_passthru_init(struct tpm_device *const dev)
{
	ACPI_BUFFER crs;
	int error = acpi_device_get_physical_crs(dev->acpi_dev, &crs);
	if (error) {
		warnx("%s: failed to get current resources of TPM device",
		    __func__);
		return (error);
	}
	error = acpi_device_add_res_acpi_buffer(dev->acpi_dev, crs);
	if (error) {
		warnx("%s: failed to set current resources for TPM device",
		    __func__);
		return (error);
	}
	/*
	 * TPM should use the address 0xFED40000. This address shouldn't
	 * conflict with any other device, yet. However, it could change in
	 * future. It may be a good idea to check whether we can dynamically
	 * allocate the TPM mmio address or not.
	 */
	error = acpi_device_map_crs(dev->acpi_dev);
	if (error) {
		warnx(
		    "%s: failed to map current resources into guest memory space",
		    __func__);
		return (error);
	}

	struct tpm_passthru *const tpm = calloc(1, sizeof(struct tpm_passthru));
	dev->emul_data = tpm;
	if (tpm == NULL) {
		warnx("%s: failed to allocate tpm passthru\n", __func__);
		return (ENOMEM);
	}

	tpm->fd = open("/dev/tpm0", O_RDWR);
	if (tpm->fd < 0) {
		warnx("%s: unable to open tpm device (/dev/tpm0)\n", __func__);
		return (ENOENT);
	}

	return (0);
}

static void
tpm_passthru_deinit(struct tpm_device *const dev)
{
	if (dev == NULL) {
		return;
	}

	struct tpm_passthru *const tpm = dev->emul_data;
	if (tpm == NULL) {
		return;
	}

	if (tpm->fd > 0) {
		close(tpm->fd);
	}

	dev->emul_data = NULL;
	free(tpm);
}

static int
tpm_passthru_execute_cmd(struct tpm_device *const dev, void *cmd,
    uint32_t cmd_size, void *rsp, uint32_t rsp_size)
{
	struct tpm_passthru *tpm = dev->emul_data;

	ssize_t len = write(tpm->fd, cmd, cmd_size);
	if (len != cmd_size) {
		warn("%s: cmd write failed (bytes written: %ld / %d)\n",
		    __func__, len, cmd_size);
		return (EFAULT);
	}

	len = read(tpm->fd, rsp, rsp_size);
	if (len < (ssize_t)sizeof(struct tpm_resp_hdr)) {
		warn("%s: rsp read failed (bytes read: %ld / %d)\n", __func__,
		    len, rsp_size);
		return (EFAULT);
	}

	return (0);
}

static struct tpm_emul tpm_emul_passthru = {
	.name = "passthru",
	.init = tpm_passthru_init,
	.deinit = tpm_passthru_deinit,
	.execute_cmd = tpm_passthru_execute_cmd,
};
TPM_EMUL_SET(tpm_emul_passthru);
