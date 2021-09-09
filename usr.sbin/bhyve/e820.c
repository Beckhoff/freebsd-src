/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/queue.h>

#include <machine/vmm.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "e820.h"
#include "qemu_fwcfg.h"

/*
 * E820 always uses 64 bit entries. Emulation code will use vm_paddr_t since it
 * works on physical addresses. If vm_paddr_t is larger than uint64_t E820 can't
 * hold all possible physical addresses and we can get into trouble.
 */
static_assert(sizeof(vm_paddr_t) <= sizeof(uint64_t),
    "Unable to represent physical memory by E820 table");

#define E820_FWCFG_FILE_NAME "etc/e820"

#define KB (1024UL)
#define MB (1024 * KB)
#define GB (1024 * MB)

/*
 * Fix E820 memory holes:
 * [    A0000,    C0000) VGA
 * [    C0000,   100000) ROM
 */
#define E820_VGA_MEM_BASE 0xA0000
#define E820_VGA_MEM_END 0xC0000
#define E820_ROM_MEM_BASE 0xC0000
#define E820_ROM_MEM_END 0x100000

struct e820_element {
	TAILQ_ENTRY(e820_element) chain;
	uint64_t base;
	uint64_t end;
	enum e820_memory_type type;
};
TAILQ_HEAD(e820_table, e820_element) e820_table = TAILQ_HEAD_INITIALIZER(
    e820_table);

static const char *
e820_get_type_name(const enum e820_memory_type type)
{
	switch (type) {
	case E820_TYPE_MEMORY:
		return "RAM     ";
	case E820_TYPE_RESERVED:
		return "Reserved";
	case E820_TYPE_ACPI:
		return "ACPI    ";
	case E820_TYPE_NVS:
		return "NVS     ";
	default:
		return "Unknown ";
	}
}

void
e820_dump_table()
{
	fprintf(stderr, "E820 map:\n\r");
	uint64_t i = 0;
	struct e820_element *element;
	TAILQ_FOREACH (element, &e820_table, chain) {
		fprintf(stderr, "  (%4lu) [ %16lx, %16lx] %s\n\r", i,
		    element->base, element->end,
		    e820_get_type_name(element->type));
		++i;
	}
}

struct qemu_fwcfg_item *
e820_get_fwcfg_item()
{
	uint64_t count = 0;
	struct e820_element *element;
	TAILQ_FOREACH (element, &e820_table, chain) {
		++count;
	}
	if (count == 0) {
		warnx("%s: E820 table empty", __func__);
		return (NULL);
	}

	struct qemu_fwcfg_item *const fwcfg_item = malloc(
	    sizeof(struct qemu_fwcfg_item));
	if (fwcfg_item == NULL) {
		return (NULL);
	}
	fwcfg_item->size = count * sizeof(struct e820_entry);
	fwcfg_item->data = malloc(fwcfg_item->size);
	if (fwcfg_item->data == NULL) {
		free(fwcfg_item);
		return (NULL);
	}
	uint64_t i = 0;
	struct e820_entry *entries = (struct e820_entry *)fwcfg_item->data;
	TAILQ_FOREACH (element, &e820_table, chain) {
		struct e820_entry *entry = &entries[i];
		entry->base = element->base;
		entry->length = element->end - element->base;
		entry->type = element->type;
		++i;
	}

	return fwcfg_item;
}

int
e820_add_entry(const uint64_t base, const uint64_t end,
    const enum e820_memory_type type)
{
	if (end < base) {
		return (-1);
	}

	struct e820_element *const new_element = malloc(
	    sizeof(struct e820_element));
	if (new_element == NULL) {
		return (-ENOMEM);
	}

	new_element->base = base;
	new_element->end = end;
	new_element->type = type;

	/*
	 * E820 table should be always sorted in ascending order. Therefore,
	 * search for an element which end is larger than the base parameter.
	 */
	struct e820_element *element;
	TAILQ_FOREACH (element, &e820_table, chain) {
		if (element->end > base) {
			break;
		}
	}

	/*
	 * System memory requires special handling.
	 */
	if (type == E820_TYPE_MEMORY) {
		/*
		 * base is larger than of any existing element. Add new system
		 * memory at the end of the table.
		 */
		if (element == NULL) {
			TAILQ_INSERT_TAIL(&e820_table, new_element, chain);
			return (0);
		}

		/*
		 * System memory shouldn't overlap with any existing element.
		 */
		if (end > element->base) {
			return (-1);
		}
		TAILQ_INSERT_BEFORE(element, new_element, chain);
		return (0);
	}

	if (element == NULL) {
		/* No suitable element found */
		return (-1);
	}

	/*
	 * Non system memory should be allocated inside system memory.
	 */
	if (element->type != E820_TYPE_MEMORY) {
		return (-1);
	}
	/*
	 * New element should fit into existing system memory element.
	 */
	if (base < element->base || end > element->end) {
		return (-1);
	}

	if (base == element->base) {
		/*
		 * New element at system memory base boundary. Add new
		 * element before current and adjust the base of the old
		 * element.
		 *
		 * Old table:
		 * 	[ 0x1000, 0x4000] RAM		<-- element
		 * New table:
		 * 	[ 0x1000, 0x2000] Reserved
		 * 	[ 0x2000, 0x4000] RAM		<-- element
		 */
		TAILQ_INSERT_BEFORE(element, new_element, chain);
		element->base = end;
	} else if (end == element->end) {
		/*
		 * New element at system memory end boundary. Add new
		 * element after current and adjust the end of the
		 * current element.
		 *
		 * Old table:
		 * 	[ 0x1000, 0x4000] RAM		<-- element
		 * New table:
		 * 	[ 0x1000, 0x3000] RAM		<-- element
		 * 	[ 0x3000, 0x4000] Reserved
		 */
		TAILQ_INSERT_AFTER(&e820_table, element, new_element, chain);
		element->end = base;
	} else {
		/*
		 * New element inside system memory entry. Split it by
		 * adding a system memory element and the new element
		 * before current.
		 *
		 * Old table:
		 * 	[ 0x1000, 0x4000] RAM		<-- element
		 * New table:
		 * 	[ 0x1000, 0x2000] RAM
		 * 	[ 0x2000, 0x3000] Reserved
		 * 	[ 0x3000, 0x4000] RAM		<-- element
		 */
		struct e820_element *ram_element = malloc(
		    sizeof(struct e820_element));
		if (ram_element == NULL) {
			return (-ENOMEM);
		}
		ram_element->base = element->base;
		ram_element->end = base;
		ram_element->type = E820_TYPE_MEMORY;
		TAILQ_INSERT_BEFORE(element, ram_element, chain);
		TAILQ_INSERT_BEFORE(element, new_element, chain);
		element->base = end;
	}

	return (0);
}

static int
e820_add_memory_hole(const uint64_t base, const uint64_t end)
{
	if (end < base) {
		return (-1);
	}

	/*
	 * E820 table should be always sorted in ascending order. Therefore,
	 * search for an element which end is larger than the base parameter.
	 */
	struct e820_element *element;
	TAILQ_FOREACH (element, &e820_table, chain) {
		if (element->end > base) {
			break;
		}
	}

	if (element == NULL || end <= element->base) {
		/* Nothing to do. Hole already exists */
		return (0);
	}

	if (element->type != E820_TYPE_MEMORY) {
		/* Memory holes are only allowed in system memory */
		return (-1);
	}

	if (base == element->base) {
		/*
		 * New hole at system memory base boundary.
		 *
		 * Old table:
		 * 	[ 0x1000, 0x4000] RAM
		 * New table:
		 * 	[ 0x2000, 0x4000] RAM
		 */
		element->base = end;

	} else if (end == element->end) {
		/*
		 * New hole at system memory end boundary.
		 *
		 * Old table:
		 * 	[ 0x1000, 0x4000] RAM
		 * New table:
		 * 	[ 0x1000, 0x3000] RAM
		 */
		element->end = base;

	} else {
		/*
		 * New hole inside system memory entry. Split the system memory.
		 *
		 * Old table:
		 * 	[ 0x1000, 0x4000] RAM		<-- element
		 * New table:
		 * 	[ 0x1000, 0x2000] RAM
		 * 	[ 0x3000, 0x4000] RAM		<-- element
		 */
		struct e820_element *const ram_element = malloc(
		    sizeof(struct e820_element));
		if (ram_element == NULL) {
			return (-ENOMEM);
		}
		ram_element->base = element->base;
		ram_element->end = base;
		ram_element->type = E820_TYPE_MEMORY;
		TAILQ_INSERT_BEFORE(element, ram_element, chain);
		element->base = end;
	}

	return (0);
}

static uint64_t
e820_alloc_highest(const uint64_t max_address, const uint64_t length,
    const uint64_t alignment, const enum e820_memory_type type)
{
	struct e820_element *element;
	TAILQ_FOREACH_REVERSE (element, &e820_table, e820_table, chain) {
		const uint64_t end = MIN(max_address, element->end);
		const uint64_t base = roundup2(element->base, alignment);

		if (element->type != E820_TYPE_MEMORY || end < base ||
		    end - base < length || end - length == 0) {
			continue;
		}

		const uint64_t address = rounddown2(end - length, alignment);

		if (e820_add_entry(address, address + length, type) != 0) {
			return 0;
		}

		return address;
	}

	return 0;
}

static uint64_t
e820_alloc_lowest(const uint64_t min_address, const uint64_t length,
    const uint64_t alignment, const enum e820_memory_type type)
{
	struct e820_element *element;
	TAILQ_FOREACH (element, &e820_table, chain) {
		const uint64_t end = element->end;
		const uint64_t base = MAX(min_address,
		    roundup2(element->base, alignment));

		if (element->type != E820_TYPE_MEMORY || end < base ||
		    end - base < length || base == 0) {
			continue;
		}

		if (e820_add_entry(base, base + length, type) != 0) {
			return 0;
		}

		return base;
	}

	return 0;
}

uint64_t
e820_alloc(const uint64_t address, const uint64_t length,
    const uint64_t alignment, const enum e820_memory_type type,
    const enum e820_allocation_strategy strategy)
{
	/* address should be aligned */
	if (!powerof2(alignment) || (address & (alignment - 1)) != 0) {
		return 0;
	}

	switch (strategy) {
	case E820_ALLOCATE_ANY:
		/*
		 * Allocate any address. Therefore, ignore the address parameter
		 * and reuse the code path for allocating the lowest address.
		 */
		return e820_alloc_lowest(0, length, alignment, type);
	case E820_ALLOCATE_LOWEST:
		return e820_alloc_lowest(address, length, alignment, type);
	case E820_ALLOCATE_HIGHEST:
		return e820_alloc_highest(address, length, alignment, type);
	case E820_ALLOCATE_SPECIFIC:
		if (e820_add_entry(address, address + length, type) != 0) {
			return 0;
		}

		return address;
	}

	return 0;
}

int
e820_init(struct vmctx *const ctx)
{
	int error;

	TAILQ_INIT(&e820_table);

	/* add memory below 4 GB to E820 table */
	const uint64_t lowmem_length = vm_get_lowmem_size(ctx);
	error = e820_add_entry(0, lowmem_length, E820_TYPE_MEMORY);
	if (error) {
		warnx("%s: Could not add lowmem", __func__);
		return (error);
	}

	/* add memory above 4 GB to E820 table */
	const uint64_t highmem_length = vm_get_highmem_size(ctx);
	if (highmem_length != 0) {
		error = e820_add_entry(4 * GB, 4 * GB + highmem_length,
		    E820_TYPE_MEMORY);
		if (error) {
			warnx("%s: Could not add highmem", __func__);
			return (error);
		}
	}

	/* add memory holes to E820 table */
	error = e820_add_memory_hole(E820_VGA_MEM_BASE, E820_VGA_MEM_END);
	if (error) {
		warnx("%s: Could not add VGA memory", __func__);
		return (error);
	}

	error = e820_add_memory_hole(E820_ROM_MEM_BASE, E820_ROM_MEM_END);
	if (error) {
		warnx("%s: Could not add ROM area", __func__);
		return (error);
	}

	return (0);
}
