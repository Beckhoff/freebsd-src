/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2022 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include <machine/vmm.h>

#include <assert.h>
#include <err.h>
#include <stddef.h>
#include <stdio.h>
#include <vmmapi.h>

#include "basl.h"
#include "qemu_loader.h"

struct basl_table {
	STAILQ_ENTRY(basl_table) chain;
	struct vmctx *ctx;
	uint8_t fwcfg_name[QEMU_FWCFG_MAX_NAME];
	void *data;
	uint32_t len;
	uint32_t off;
	uint32_t alignment;
};
STAILQ_HEAD(basl_table_list, basl_table) basl_tables = STAILQ_HEAD_INITIALIZER(
    basl_tables);

struct basl_table_length {
	STAILQ_ENTRY(basl_table_length) chain;
	struct basl_table *table;
	uint32_t off;
	uint8_t size;
};
STAILQ_HEAD(basl_table_length_list,
    basl_table_length) basl_lengths = STAILQ_HEAD_INITIALIZER(basl_lengths);

struct qemu_loader *basl_loader;

static int
basl_dump_table(const struct basl_table *const table, const int mem)
{
	const ACPI_TABLE_HEADER *const header = table->data;
	const uint8_t *data;

	if (!mem) {
		data = table->data;
	} else {
		data = (uint8_t *)vm_map_gpa(table->ctx,
		    BHYVE_ACPI_BASE + table->off, table->len);
		if (data == NULL) {
			return (ENOMEM);
		}
	}

	printf("%c%c%c%c @ %8x (%s)\n\r", header->Signature[0],
	    header->Signature[1], header->Signature[2], header->Signature[3],
	    BHYVE_ACPI_BASE + table->off, mem ? "Memory" : "FwCfg");
	for (uint32_t i = 0; i < table->len; i += 0x10) {
		printf("%08x: ", i);
		for (uint32_t n = 0; n < 0x10; ++n) {
			if (table->len <= i + n) {
				printf("   ");
				continue;
			}
			printf("%02x ", data[i + n]);
		}
		printf("| ");
		for (uint32_t n = 0; n < 0x10; ++n) {
			if (table->len <= i + n) {
				printf(" ");
				continue;
			}
			const uint8_t c = data[i + n];
			if (c < 0x20 || c >= 0x7F) {
				printf(".");
			} else {
				printf("%c", c);
			}
		}
		printf("\n\r");
	}

	return (0);
}

static int
basl_dump(const int mem)
{
	struct basl_table *table;
	STAILQ_FOREACH (table, &basl_tables, chain) {
		BASL_EXEC(basl_dump_table(table, mem));
	}

	return (0);
}

static int
basl_finish_alloc()
{
	struct basl_table *table;
	STAILQ_FOREACH (table, &basl_tables, chain) {
		/*
		 * Old guest bios versions search for ACPI tables in the guest
		 * memory and install them as is. Therefore, copy the tables
		 * into the guest memory.
		 */
		void *gva = vm_map_gpa(table->ctx, BHYVE_ACPI_BASE + table->off,
		    table->len);
		if (gva == NULL) {
			warnx("%s: could not map gpa [ 0x%16lx, 0x%16lx ]",
			    __func__, (uint64_t)BHYVE_ACPI_BASE + table->off,
			    (uint64_t)BHYVE_ACPI_BASE + table->off +
				table->len);
			return (ENOMEM);
		}
		memcpy(gva, table->data, table->len);

		/* Cause guest bios to copy the ACPI table into guest memory. */
		BASL_EXEC(qemu_fwcfg_add_file(table->fwcfg_name, table->len,
		    table->data));
		BASL_EXEC(qemu_loader_alloc(basl_loader, table->fwcfg_name,
		    table->alignment, QEMU_LOADER_ALLOC_HIGH));
	}

	return (0);
}

static int
basl_finish_set_length()
{
	struct basl_table_length *length;
	STAILQ_FOREACH (length, &basl_lengths, chain) {
		const struct basl_table *const table = length->table;

		uint32_t len_le = htole32(table->len);

		memcpy(table->data + length->off, &len_le, length->size);
	}

	return (0);
}

int
basl_finish()
{
	if (STAILQ_EMPTY(&basl_tables)) {
		warnx("%s: no ACPI tables found", __func__);
		return (EINVAL);
	}

	BASL_EXEC(basl_finish_set_length());
	BASL_EXEC(basl_finish_alloc());
	BASL_EXEC(qemu_loader_finish(basl_loader));

	return (0);
}

int
basl_init()
{
	return (qemu_loader_create(&basl_loader, QEMU_FWCFG_FILE_TABLE_LOADER));
}

static int
basl_table_add_length(struct basl_table *const table, const uint32_t off,
    const uint8_t size)
{
	struct basl_table_length *const length = calloc(1,
	    sizeof(struct basl_table_length));
	if (length == NULL) {
		warnx("%s: failed to allocate length", __func__);
		return (ENOMEM);
	}

	length->table = table;
	length->off = off;
	length->size = size;

	STAILQ_INSERT_TAIL(&basl_lengths, length, chain);

	return (0);
}

int
basl_table_append_bytes(struct basl_table *const table, const void *const bytes,
    const uint32_t len)
{
	if (table == NULL || bytes == NULL) {
		return (EINVAL);
	}
	if (table->len + len <= table->len) {
		warnx("%s: table too large (table->len 0x%8x len 0x%8x)",
		    __func__, table->len, len);
		return (EFAULT);
	}

	table->data = reallocf(table->data, table->len + len);
	if (table->data == NULL) {
		warnx("%s: failed to realloc table to length 0x%8x", __func__,
		    table->len + len);
		table->len = 0;
		return (ENOMEM);
	}
	void *const end = (uint8_t *)table->data + table->len;
	table->len += len;

	memcpy(end, bytes, len);

	return (0);
}

int
basl_table_append_gas(struct basl_table *const table, const uint8_t space_id,
    const uint8_t bit_width, const uint8_t bit_offset,
    const uint8_t access_width, const uint64_t address)
{
	ACPI_GENERIC_ADDRESS gas_le = {
		.SpaceId = space_id,
		.BitWidth = bit_width,
		.BitOffset = bit_offset,
		.AccessWidth = access_width,
		.Address = htole64(address),
	};

	return (basl_table_append_bytes(table, &gas_le, sizeof(gas_le)));
}

int
basl_table_append_int(struct basl_table *const table, const uint64_t val,
    const uint8_t size)
{
	if (size > sizeof(val)) {
		return (EINVAL);
	}

	const uint64_t val_le = htole64(val);
	return (basl_table_append_bytes(table, &val_le, size));
}

int
basl_table_append_length(struct basl_table *const table, const uint8_t size)
{
	if (table == NULL || size > sizeof(table->len)) {
		return (EINVAL);
	}

	BASL_EXEC(basl_table_add_length(table, table->len, size));
	BASL_EXEC(basl_table_append_int(table, 0, size));

	return (0);
}

int
basl_table_create(struct basl_table **const table, struct vmctx *ctx,
    const uint8_t name[QEMU_FWCFG_MAX_NAME], const uint32_t alignment,
    const uint32_t off)
{
	if (table == NULL) {
		return (EINVAL);
	}

	struct basl_table *const new_table = (struct basl_table *)calloc(1,
	    sizeof(struct basl_table));
	if (new_table == NULL) {
		warnx("%s: failed to allocate table", __func__);
		return (ENOMEM);
	}

	new_table->ctx = ctx;

	snprintf(new_table->fwcfg_name, sizeof(new_table->fwcfg_name),
	    "etc/acpi/%s", name);

	new_table->alignment = alignment;
	new_table->off = off;

	STAILQ_INSERT_TAIL(&basl_tables, new_table, chain);

	*table = new_table;

	return (0);
}
