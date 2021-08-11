/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/param.h>

#include <machine/vmm.h>

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "acpi_device.h"
#include "inout.h"
#include "qemu_fwcfg.h"

#define QEMU_FWCFG_ACPI_DEVICE_NAME "FWCF"
#define QEMU_FWCFG_ACPI_HARDWARE_ID "QEMU0002"

#define QEMU_FWCFG_SELECTOR_PORT_NUMBER 0x510
#define QEMU_FWCFG_SELECTOR_PORT_SIZE 1
#define QEMU_FWCFG_SELECTOR_PORT_FLAGS IOPORT_F_INOUT
#define QEMU_FWCFG_DATA_PORT_NUMBER 0x511
#define QEMU_FWCFG_DATA_PORT_SIZE 1
#define QEMU_FWCFG_DATA_PORT_FLAGS \
	IOPORT_F_INOUT /* QEMU v2.4+ ignores writes */

#define QEMU_FWCFG_ARCHITECTURE_MASK 0x0001
#define QEMU_FWCFG_INDEX_MASK 0x3FFF

#define QEMU_FWCFG_SELECT_READ 0
#define QEMU_FWCFG_SELECT_WRITE 1

#define QEMU_FWCFG_ARCHITECTURE_GENERIC 0
#define QEMU_FWCFG_ARCHITECTURE_SPECIFIC 1

#pragma pack(1)

union qemu_fwcfg_selector {
	struct {
		uint16_t index : 14;
		uint16_t writeable : 1;
		/*
		 * 0 = generic  | for all architectures
		 * 1 = specific | only for current architecture
		 */
		uint16_t architecture : 1;
	};
	uint16_t bits;
};

struct qemu_fwcfg_softc {
	struct acpi_device *acpi_dev;

	uint32_t data_offset;
	union qemu_fwcfg_selector selector;
	struct qemu_fwcfg_item items[QEMU_FWCFG_MAX_ARCHS]
				    [QEMU_FWCFG_MAX_ENTRIES];
};

#pragma pack()

static struct qemu_fwcfg_softc sc;

static int
qemu_fwcfg_selector_port_handler(struct vmctx *const ctx, const int vcpu,
    const int in, const int port, const int bytes, uint32_t *const eax,
    void *const arg)
{
	if (in) {
		*eax = *(uint16_t *)&sc.selector;
		return (0);
	}

	sc.data_offset = 0;
	sc.selector.bits = *eax;

	return (0);
}

static int
qemu_fwcfg_data_port_handler(struct vmctx *const ctx, const int vcpu,
    const int in, const int port, const int bytes, uint32_t *const eax,
    void *const arg)
{
	if (!in) {
		warnx("%s: Writes to qemu fwcfg data port aren't allowed",
		    __func__);
		return (-1);
	}

	/* get fwcfg item */
	struct qemu_fwcfg_item *const item =
	    &sc.items[sc.selector.architecture][sc.selector.index];
	if (item->data == NULL) {
		warnx(
		    "%s: qemu fwcfg item doesn't exist (architecture %s index 0x%x)",
		    __func__, sc.selector.architecture ? "specific" : "generic",
		    sc.selector.index);
		*eax = 0x00;
		return (0);
	} else if (sc.data_offset >= item->size) {
		warnx(
		    "%s: qemu fwcfg item read exceeds size (architecture %s index 0x%x size 0x%x offset 0x%x)",
		    __func__, sc.selector.architecture ? "specific" : "generic",
		    sc.selector.index, item->size, sc.data_offset);
		*eax = 0x00;
		return (0);
	}

	/* return item data */
	*eax = item->data[sc.data_offset];
	sc.data_offset++;

	return (0);
}

static int
qemu_fwcfg_register_port(const char *const name, const int port, const int size,
    const int flags, const inout_func_t handler)
{
	struct inout_port iop;

	bzero(&iop, sizeof(iop));
	iop.name = name;
	iop.port = port;
	iop.size = size;
	iop.flags = flags;
	iop.handler = handler;

	return register_inout(&iop);
}

int
qemu_fwcfg_init(struct vmctx *const ctx)
{
	int error;

	error = acpi_device_create(&sc.acpi_dev, ctx,
	    QEMU_FWCFG_ACPI_DEVICE_NAME, QEMU_FWCFG_ACPI_HARDWARE_ID);
	if (error) {
		warnx("%s: failed to create ACPI device for QEMU FwCfg",
		    __func__);
		goto done;
	}

	error = acpi_device_add_res_fixed_ioport(sc.acpi_dev,
	    QEMU_FWCFG_SELECTOR_PORT_NUMBER, 2);
	if (error) {
		warnx("%s: failed to add fixed IO port for QEMU FwCfg",
		    __func__);
		goto done;
	}

	/* add handlers for fwcfg ports */
	if ((error = qemu_fwcfg_register_port("qemu_fwcfg_selector",
		 QEMU_FWCFG_SELECTOR_PORT_NUMBER, QEMU_FWCFG_SELECTOR_PORT_SIZE,
		 QEMU_FWCFG_SELECTOR_PORT_FLAGS,
		 qemu_fwcfg_selector_port_handler)) != 0) {
		warnx("%s: Unable to register qemu fwcfg selector port 0x%x",
		    __func__, QEMU_FWCFG_SELECTOR_PORT_NUMBER);
		goto done;
	}
	if ((error = qemu_fwcfg_register_port("qemu_fwcfg_data",
		 QEMU_FWCFG_DATA_PORT_NUMBER, QEMU_FWCFG_DATA_PORT_SIZE,
		 QEMU_FWCFG_DATA_PORT_FLAGS, qemu_fwcfg_data_port_handler)) !=
	    0) {
		warnx("%s: Unable to register qemu fwcfg data port 0x%x",
		    __func__, QEMU_FWCFG_DATA_PORT_NUMBER);
		goto done;
	}

done:
	if (error) {
		acpi_device_destroy(sc.acpi_dev);
	}

	return (error);
}
