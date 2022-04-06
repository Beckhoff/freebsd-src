/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2012 NetApp, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/*
 * bhyve ACPI table generator.
 *
 * Create the minimal set of ACPI tables required to boot FreeBSD (and
 * hopefully other o/s's) by writing out ASL template files for each of
 * the tables and the compiling them to AML with the Intel iasl compiler.
 * The AML files are then read into guest memory.
 *
 *  The tables are placed in the guest's ROM area just below 1MB physical,
 * above the MPTable.
 *
 *  Layout (No longer correct at FADT and beyond due to properly
 *  calculating the size of the MADT to allow for changes to
 *  VM_MAXCPU above 21 which overflows this layout.)
 *  ------
 *   RSDP  ->   0xf2400    (36 bytes fixed)
 *     RSDT  ->   0xf2440    (36 bytes + 4*7 table addrs, 4 used)
 *     XSDT  ->   0xf2480    (36 bytes + 8*7 table addrs, 4 used)
 *       MADT  ->   0xf2500  (depends on #CPUs)
 *       FADT  ->   0xf2600  (268 bytes)
 *       HPET  ->   0xf2740  (56 bytes)
 *       MCFG  ->   0xf2780  (60 bytes)
 *         FACS  ->   0xf27C0 (64 bytes)
 *         DSDT  ->   0xf2800 (variable - can go up to 0x100000)
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/stat.h>

#include <err.h>
#include <paths.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <machine/vmm.h>
#include <vmmapi.h>

#include "bhyverun.h"
#include "acpi.h"
#include "basl.h"
#include "pci_emul.h"
#include "pci_lpc.h"
#include "vmgenc.h"

/*
 * Define the base address of the ACPI tables, the sizes of some tables, 
 * and the offsets to the individual tables,
 */
#define RSDT_OFFSET		0x040
#define XSDT_OFFSET		0x080
#define MADT_OFFSET		0x100
/*
 * The MADT consists of:
 *	44		Fixed Header
 *	8 * maxcpu	Processor Local APIC entries
 *	12		I/O APIC entry
 *	2 * 10		Interrupt Source Override entries
 *	6		Local APIC NMI entry
 */
#define	MADT_SIZE		roundup2((44 + basl_ncpu*8 + 12 + 2*10 + 6), 0x100)
#define	FADT_OFFSET		(MADT_OFFSET + MADT_SIZE)
#define	FADT_SIZE		0x140
#define	HPET_OFFSET		(FADT_OFFSET + FADT_SIZE)
#define	HPET_SIZE		0x40
#define	MCFG_OFFSET		(HPET_OFFSET + HPET_SIZE)
#define	MCFG_SIZE		0x40
#define	FACS_OFFSET		(MCFG_OFFSET + MCFG_SIZE)
#define	FACS_SIZE		0x40
#define TPM2_OFFSET		(FACS_OFFSET + FACS_SIZE)
#define TPM2_SIZE		0x80
#define	DSDT_OFFSET		(TPM2_OFFSET + TPM2_SIZE)

#define	BHYVE_ASL_TEMPLATE	"bhyve.XXXXXXX"
#define BHYVE_ASL_SUFFIX	".aml"
#define BHYVE_ASL_COMPILER	"/usr/sbin/iasl"

#define BHYVE_ADDRESS_IOAPIC 0xFEC00000
#define BHYVE_ADDRESS_HPET 0xFED00000
#define BHYVE_ADDRESS_LAPIC 0xFEE00000

static int basl_keep_temps;
static int basl_verbose_iasl;
static int basl_ncpu;
static uint32_t basl_acpi_base = BHYVE_ACPI_BASE;
static uint32_t hpet_capabilities;

/*
 * Contains the full pathname of the template to be passed
 * to mkstemp/mktemps(3)
 */
static char basl_template[MAXPATHLEN];
static char basl_stemplate[MAXPATHLEN];

/*
 * State for dsdt_line(), dsdt_indent(), and dsdt_unindent().
 */
static FILE *dsdt_fp;
static int dsdt_indent_level;
static int dsdt_error;

struct basl_table *xsdt;

struct basl_fio {
	int	fd;
	FILE	*fp;
	char	f_name[MAXPATHLEN];
};

#define EFPRINTF(...) \
	if (fprintf(__VA_ARGS__) < 0) goto err_exit;

#define EFFLUSH(x) \
	if (fflush(x) != 0) goto err_exit;

/*
 * A list for additional ACPI devices like a TPM.
 */
struct acpi_device_list_entry {
	SLIST_ENTRY(acpi_device_list_entry) chain;
	const struct acpi_device *dev;
};
SLIST_HEAD(acpi_device_list,
    acpi_device_list_entry) acpi_devices = SLIST_HEAD_INITIALIZER(acpi_devices);

int
acpi_tables_add_device(const struct acpi_device *const dev)
{
	struct acpi_device_list_entry *const entry = calloc(1, sizeof(*entry));
	if (entry == NULL) {
		return (ENOMEM);
	}

	entry->dev = dev;
	SLIST_INSERT_HEAD(&acpi_devices, entry, chain);

	return (0);
}

static int
basl_fwrite_rsdp(FILE *fp)
{
	EFPRINTF(fp, "/*\n");
	EFPRINTF(fp, " * bhyve RSDP template\n");
	EFPRINTF(fp, " */\n");
	EFPRINTF(fp, "[0008]\t\tSignature : \"RSD PTR \"\n");
	EFPRINTF(fp, "[0001]\t\tChecksum : 43\n");
	EFPRINTF(fp, "[0006]\t\tOem ID : \"BHYVE \"\n");
	EFPRINTF(fp, "[0001]\t\tRevision : 02\n");
	EFPRINTF(fp, "[0004]\t\tRSDT Address : %08X\n",
	    basl_acpi_base + RSDT_OFFSET);
	EFPRINTF(fp, "[0004]\t\tLength : 00000024\n");
	EFPRINTF(fp, "[0008]\t\tXSDT Address : 00000000%08X\n",
	    basl_acpi_base + XSDT_OFFSET);
	EFPRINTF(fp, "[0001]\t\tExtended Checksum : 00\n");
	EFPRINTF(fp, "[0003]\t\tReserved : 000000\n");

	EFFLUSH(fp);

	return (0);

err_exit:
	return (errno);
}

static int
basl_fwrite_rsdt(FILE *fp)
{
	EFPRINTF(fp, "/*\n");
	EFPRINTF(fp, " * bhyve RSDT template\n");
	EFPRINTF(fp, " */\n");
	EFPRINTF(fp, "[0004]\t\tSignature : \"RSDT\"\n");
	EFPRINTF(fp, "[0004]\t\tTable Length : 00000000\n");
	EFPRINTF(fp, "[0001]\t\tRevision : 01\n");
	EFPRINTF(fp, "[0001]\t\tChecksum : 00\n");
	EFPRINTF(fp, "[0006]\t\tOem ID : \"BHYVE \"\n");
	EFPRINTF(fp, "[0008]\t\tOem Table ID : \"BVRSDT  \"\n");
	EFPRINTF(fp, "[0004]\t\tOem Revision : 00000001\n");
	/* iasl will fill in the compiler ID/revision fields */
	EFPRINTF(fp, "[0004]\t\tAsl Compiler ID : \"xxxx\"\n");
	EFPRINTF(fp, "[0004]\t\tAsl Compiler Revision : 00000000\n");
	EFPRINTF(fp, "\n");

	/* Add in pointers to the MADT, FADT and HPET */
	uint32_t table = 0;
	EFPRINTF(fp, "[0004]\t\tACPI Table Address %u : %08X\n", table++,
	    basl_acpi_base + MADT_OFFSET);
	EFPRINTF(fp, "[0004]\t\tACPI Table Address %u : %08X\n", table++,
	    basl_acpi_base + FADT_OFFSET);
	EFPRINTF(fp, "[0004]\t\tACPI Table Address %u : %08X\n", table++,
	    basl_acpi_base + HPET_OFFSET);
	EFPRINTF(fp, "[0004]\t\tACPI Table Address %u : %08X\n", table++,
	    basl_acpi_base + MCFG_OFFSET);

	/* Add pointer for miscellaneous tables */
	if (lpc_tpm2_in_use()) {
		EFPRINTF(fp, "[0004]\t\tACPI Table Address %u : %08X\n",
		    table++, basl_acpi_base + TPM2_OFFSET);
	}

	EFFLUSH(fp);

	return (0);

err_exit:
	return (errno);
}

/*
 * Helper routines for writing to the DSDT from other modules.
 */
void
dsdt_line(const char *fmt, ...)
{
	va_list ap;

	if (dsdt_error != 0)
		return;

	if (strcmp(fmt, "") != 0) {
		if (dsdt_indent_level != 0)
			EFPRINTF(dsdt_fp, "%*c", dsdt_indent_level * 2, ' ');
		va_start(ap, fmt);
		if (vfprintf(dsdt_fp, fmt, ap) < 0) {
			va_end(ap);
			goto err_exit;
		}
		va_end(ap);
	}
	EFPRINTF(dsdt_fp, "\n");
	return;

err_exit:
	dsdt_error = errno;
}

void
dsdt_indent(int levels)
{

	dsdt_indent_level += levels;
	assert(dsdt_indent_level >= 0);
}

void
dsdt_unindent(int levels)
{

	assert(dsdt_indent_level >= levels);
	dsdt_indent_level -= levels;
}

void
dsdt_fixed_ioport(uint16_t iobase, uint16_t length)
{

	dsdt_line("IO (Decode16,");
	dsdt_line("  0x%04X,             // Range Minimum", iobase);
	dsdt_line("  0x%04X,             // Range Maximum", iobase);
	dsdt_line("  0x01,               // Alignment");
	dsdt_line("  0x%02X,               // Length", length);
	dsdt_line("  )");
}

void
dsdt_fixed_irq(uint8_t irq)
{

	dsdt_line("IRQNoFlags ()");
	dsdt_line("  {%d}", irq);
}

void
dsdt_fixed_mem32(uint32_t base, uint32_t length)
{

	dsdt_line("Memory32Fixed (ReadWrite,");
	dsdt_line("  0x%08X,         // Address Base", base);
	dsdt_line("  0x%08X,         // Address Length", length);
	dsdt_line("  )");
}

static int
basl_fwrite_dsdt(FILE *fp)
{
	dsdt_fp = fp;
	dsdt_error = 0;
	dsdt_indent_level = 0;

	dsdt_line("/*");
	dsdt_line(" * bhyve DSDT template");
	dsdt_line(" */");
	dsdt_line("DefinitionBlock (\"bhyve_dsdt.aml\", \"%s\", 0x%02x,"
		 "\"%s\", \"%s\", 0x%08x)",
	    ACPI_SIG_DSDT, BASL_REVISION_DSDT, BASL_OEM_ID,
	    BASL_OEM_TABLE_ID_DSDT, BASL_OEM_REVISION_DSDT);
	dsdt_line("{");
	dsdt_line("  Name (_S5, Package ()");
	dsdt_line("  {");
	dsdt_line("      0x05,");
	dsdt_line("      Zero,");
	dsdt_line("  })");

	pci_write_dsdt();

	dsdt_line("");
	dsdt_line("  Scope (_SB.PC00)");
	dsdt_line("  {");
	dsdt_line("    Device (HPET)");
	dsdt_line("    {");
	dsdt_line("      Name (_HID, EISAID(\"PNP0103\"))");
	dsdt_line("      Name (_UID, 0)");
	dsdt_line("      Name (_CRS, ResourceTemplate ()");
	dsdt_line("      {");
	dsdt_indent(4);
	dsdt_fixed_mem32(0xFED00000, 0x400);
	dsdt_unindent(4);
	dsdt_line("      })");
	dsdt_line("    }");
	dsdt_line("  }");

	vmgenc_write_dsdt();

	const struct acpi_device_list_entry *entry;
	SLIST_FOREACH(entry, &acpi_devices, chain) {
		acpi_device_write_dsdt(entry->dev);
	}

	dsdt_line("}");

	if (dsdt_error != 0)
		return (dsdt_error);

	EFFLUSH(fp);

	return (0);

err_exit:
	return (errno);
}

static int
basl_open(struct basl_fio *bf, int suffix)
{
	int err;

	err = 0;

	if (suffix) {
		strlcpy(bf->f_name, basl_stemplate, MAXPATHLEN);
		bf->fd = mkstemps(bf->f_name, strlen(BHYVE_ASL_SUFFIX));
	} else {
		strlcpy(bf->f_name, basl_template, MAXPATHLEN);
		bf->fd = mkstemp(bf->f_name);
	}

	if (bf->fd > 0) {
		bf->fp = fdopen(bf->fd, "w+");
		if (bf->fp == NULL) {
			unlink(bf->f_name);
			close(bf->fd);
		}
	} else {
		err = 1;
	}

	return (err);
}

static void
basl_close(struct basl_fio *bf)
{

	if (!basl_keep_temps)
		unlink(bf->f_name);
	fclose(bf->fp);
}

static int
basl_start(struct basl_fio *in, struct basl_fio *out)
{
	int err;

	err = basl_open(in, 0);
	if (!err) {
		err = basl_open(out, 1);
		if (err) {
			basl_close(in);
		}
	}

	return (err);
}

static void
basl_end(struct basl_fio *in, struct basl_fio *out)
{

	basl_close(in);
	basl_close(out);
}

static int
basl_load(struct vmctx *ctx, int fd, uint64_t off)
{
	struct stat sb;
	void *addr;

	if (fstat(fd, &sb) < 0)
		return (errno);

	addr = calloc(1, sb.st_size);
	if (addr == NULL)
		return (EFAULT);

	if (read(fd, addr, sb.st_size) < 0)
		return (errno);

	struct basl_table *table;

	uint8_t name[ACPI_NAMESEG_SIZE + 1] = { 0 };
	memcpy(name, addr, sizeof(name) - 1 /* last char is '\0' */);
	BASL_EXEC(
	    basl_table_create(&table, ctx, name, BASL_TABLE_ALIGNMENT, off));
	BASL_EXEC(basl_table_append_bytes(table, addr, sb.st_size));

	return (0);
}

static int
basl_compile(struct vmctx *ctx, int (*fwrite_section)(FILE *), uint64_t offset)
{
	struct basl_fio io[2];
	static char iaslbuf[3*MAXPATHLEN + 10];
	char *fmt;
	int err;

	err = basl_start(&io[0], &io[1]);
	if (!err) {
		err = (*fwrite_section)(io[0].fp);

		if (!err) {
			/*
			 * iasl sends the results of the compilation to
			 * stdout. Shut this down by using the shell to
			 * redirect stdout to /dev/null, unless the user
			 * has requested verbose output for debugging
			 * purposes
			 */
			fmt = basl_verbose_iasl ?
				"%s -p %s %s" :
				"/bin/sh -c \"%s -p %s %s\" 1> /dev/null";
				
			snprintf(iaslbuf, sizeof(iaslbuf),
				 fmt,
				 BHYVE_ASL_COMPILER,
				 io[1].f_name, io[0].f_name);
			err = system(iaslbuf);

			if (!err) {
				/*
				 * Copy the aml output file into guest
				 * memory at the specified location
				 */
				err = basl_load(ctx, io[1].fd, offset);
			}
		}
		basl_end(&io[0], &io[1]);
	}

	return (err);
}

static int
basl_make_templates(void)
{
	const char *tmpdir;
	int err;
	int len;

	err = 0;

	/*
	 * 
	 */
	if ((tmpdir = getenv("BHYVE_TMPDIR")) == NULL || *tmpdir == '\0' ||
	    (tmpdir = getenv("TMPDIR")) == NULL || *tmpdir == '\0') {
		tmpdir = _PATH_TMP;
	}

	len = strlen(tmpdir);

	if ((len + sizeof(BHYVE_ASL_TEMPLATE) + 1) < MAXPATHLEN) {
		strcpy(basl_template, tmpdir);
		while (len > 0 && basl_template[len - 1] == '/')
			len--;
		basl_template[len] = '/';
		strcpy(&basl_template[len + 1], BHYVE_ASL_TEMPLATE);
	} else
		err = E2BIG;

	if (!err) {
		/*
		 * len has been intialized (and maybe adjusted) above
		 */
		if ((len + sizeof(BHYVE_ASL_TEMPLATE) + 1 +
		     sizeof(BHYVE_ASL_SUFFIX)) < MAXPATHLEN) {
			strcpy(basl_stemplate, tmpdir);
			basl_stemplate[len] = '/';
			strcpy(&basl_stemplate[len + 1], BHYVE_ASL_TEMPLATE);
			len = strlen(basl_stemplate);
			strcpy(&basl_stemplate[len], BHYVE_ASL_SUFFIX);
		} else
			err = E2BIG;
	}

	return (err);
}

static int
build_dsdt(struct vmctx *const ctx)
{
	BASL_EXEC(basl_compile(ctx, basl_fwrite_dsdt));

	return (0);
}

static int
build_facs(struct vmctx *const ctx)
{
	struct basl_table *facs;

	BASL_EXEC(basl_table_create(&facs, ctx, ACPI_SIG_FACS,
	    BASL_TABLE_ALIGNMENT_FACS, FACS_OFFSET));

	/* Signature */
	BASL_EXEC(
	    basl_table_append_bytes(facs, ACPI_SIG_FACS, ACPI_NAMESEG_SIZE));
	/* Length */
	BASL_EXEC(basl_table_append_length(facs, 4));
	/* Hardware Signature */
	BASL_EXEC(basl_table_append_int(facs, 0, 4));
	/* Firmware Waking Vector */
	BASL_EXEC(basl_table_append_int(facs, 0, 4));
	/* Global Lock */
	BASL_EXEC(basl_table_append_int(facs, 0, 4));
	/* Flags */
	BASL_EXEC(basl_table_append_int(facs, 0, 4));
	/* Extended Firmware Waking Vector */
	BASL_EXEC(basl_table_append_int(facs, 0, 8));
	/* Version */
	BASL_EXEC(basl_table_append_int(facs, 2, 1));
	/* Reserved */
	BASL_EXEC(basl_table_append_int(facs, 0, 3));
	/* OSPM Flags */
	BASL_EXEC(basl_table_append_int(facs, 0, 4));
	/* Reserved */
	const uint8_t reserved[24] = { 0 };
	BASL_EXEC(basl_table_append_bytes(facs, reserved, 24));

	return (0);
}

static int
build_fadt(struct vmctx *const ctx)
{
	struct basl_table *fadt;

	BASL_EXEC(basl_table_create(&fadt, ctx, ACPI_SIG_FADT,
	    BASL_TABLE_ALIGNMENT, FADT_OFFSET));

	/* Header */
	BASL_EXEC(
	    basl_table_append_header(fadt, ACPI_SIG_FADT, BASL_REVISION_FADT,
		BASL_OEM_ID, BASL_OEM_TABLE_ID_FADT, BASL_OEM_REVISION_FADT));
	/* FACS Address */
	BASL_EXEC(basl_table_append_pointer(fadt, ACPI_SIG_FACS,
	    ACPI_RSDT_ENTRY_SIZE));
	/* DSDT Address */
	BASL_EXEC(basl_table_append_pointer(fadt, ACPI_SIG_DSDT,
	    ACPI_RSDT_ENTRY_SIZE));
	/* Eeserved */
	BASL_EXEC(basl_table_append_int(fadt, 0, 1));
	/* Preferred_PM_Profile [Unspecified] */
	BASL_EXEC(basl_table_append_int(fadt, 0, 1));
	/* SCI Interrupt */
	BASL_EXEC(basl_table_append_int(fadt, SCI_INT, 2));
	/* SMI Command Port */
	BASL_EXEC(basl_table_append_int(fadt, SMI_CMD, 4));
	/* ACPI Enable Value */
	BASL_EXEC(basl_table_append_int(fadt, BHYVE_ACPI_ENABLE, 1));
	/* ACPI Disable Value */
	BASL_EXEC(basl_table_append_int(fadt, BHYVE_ACPI_DISABLE, 1));
	/* S4BIOS Command */
	BASL_EXEC(basl_table_append_int(fadt, 0, 1));
	/* P-State Control */
	BASL_EXEC(basl_table_append_int(fadt, 0, 1));
	/* PM1A Event Block Address */
	BASL_EXEC(basl_table_append_int(fadt, PM1A_EVT_ADDR, 4));
	/* PM1B Event Block Address */
	BASL_EXEC(basl_table_append_int(fadt, 0, 4));
	/* PM1A Control Block Address */
	BASL_EXEC(basl_table_append_int(fadt, PM1A_CNT_ADDR, 4));
	/* PM1B Control Block Address */
	BASL_EXEC(basl_table_append_int(fadt, 0, 4));
	/* PM2 Control Block Address */
	BASL_EXEC(basl_table_append_int(fadt, 0, 4));
	/* PM Timer Block Address */
	BASL_EXEC(basl_table_append_int(fadt, IO_PMTMR, 4));
	/* GPE0 Block Address */
	BASL_EXEC(basl_table_append_int(fadt, IO_GPE0_BLK, 4));
	/* GPE1 Block Address */
	BASL_EXEC(basl_table_append_int(fadt, 0, 4));
	/* PM1 Event Block Length */
	BASL_EXEC(basl_table_append_int(fadt, 4, 1));
	/* PM1 Control Block Length */
	BASL_EXEC(basl_table_append_int(fadt, 2, 1));
	/* PM2 Control Block Length */
	BASL_EXEC(basl_table_append_int(fadt, 0, 1));
	/* PM Timer Block Length */
	BASL_EXEC(basl_table_append_int(fadt, 4, 1));
	/* GPE0 Block Length */
	BASL_EXEC(basl_table_append_int(fadt, IO_GPE0_LEN, 1));
	/* GPE1 Block Length */
	BASL_EXEC(basl_table_append_int(fadt, 0, 1));
	/* GPE1 Base Offset */
	BASL_EXEC(basl_table_append_int(fadt, 0, 1));
	/* _CST Support */
	BASL_EXEC(basl_table_append_int(fadt, 0, 1));
	/* C2 Latency */
	BASL_EXEC(basl_table_append_int(fadt, 0, 2));
	/* C3 Latency */
	BASL_EXEC(basl_table_append_int(fadt, 0, 2));
	/* CPU Cache Size */
	BASL_EXEC(basl_table_append_int(fadt, 0, 2));
	/* Cache Flush Stride */
	BASL_EXEC(basl_table_append_int(fadt, 0, 2));
	/* Duty Cycle Offset */
	BASL_EXEC(basl_table_append_int(fadt, 0, 1));
	/* Duty Cycle Width */
	BASL_EXEC(basl_table_append_int(fadt, 0, 1));
	/* RTC Day Alarm Index */
	BASL_EXEC(basl_table_append_int(fadt, 0, 1));
	/* RTC Month Alarm Index */
	BASL_EXEC(basl_table_append_int(fadt, 0, 1));
	/* RTC Centyr Index */
	BASL_EXEC(basl_table_append_int(fadt, 32, 1));
	/* Boot Flags */
	BASL_EXEC(basl_table_append_int(fadt,
	    ACPI_FADT_NO_VGA | ACPI_FADT_NO_ASPM, 2));
	/* Reserved */
	BASL_EXEC(basl_table_append_int(fadt, 0, 1));
	/* Flags */
	BASL_EXEC(basl_table_append_int(fadt,
	    ACPI_FADT_WBINVD | ACPI_FADT_C1_SUPPORTED | ACPI_FADT_SLEEP_BUTTON |
		ACPI_FADT_32BIT_TIMER | ACPI_FADT_RESET_REGISTER |
		ACPI_FADT_HEADLESS | ACPI_FADT_APIC_PHYSICAL,
	    4));
	/* Reset Register */
	BASL_EXEC(basl_table_append_gas(fadt, ACPI_ADR_SPACE_SYSTEM_IO, 8, 0,
	    ACPI_GAS_ACCESS_WIDTH_BYTE, 0xCF9));
	/* Reset Value */
	BASL_EXEC(basl_table_append_int(fadt, 6, 1));
	/* ARM Boot Architecture Flags */
	BASL_EXEC(basl_table_append_int(fadt, 0, 2));
	/* FADT Minor Version */
	BASL_EXEC(basl_table_append_int(fadt, 1, 1));
	/* Extended FACS Address */
	BASL_EXEC(basl_table_append_pointer(fadt, ACPI_SIG_FACS,
	    ACPI_XSDT_ENTRY_SIZE));
	/* Extended DSDT Address */
	BASL_EXEC(basl_table_append_pointer(fadt, ACPI_SIG_DSDT,
	    ACPI_XSDT_ENTRY_SIZE));
	/* Extended PM1A Event Block Address */
	BASL_EXEC(basl_table_append_gas(fadt, ACPI_ADR_SPACE_SYSTEM_IO, 0x20, 0,
	    ACPI_GAS_ACCESS_WIDTH_WORD, PM1A_EVT_ADDR));
	/* Extended PM1B Event Block Address */
	BASL_EXEC(basl_table_append_gas(fadt, ACPI_ADR_SPACE_SYSTEM_IO, 0, 0,
	    ACPI_GAS_ACCESS_WIDTH_UNDEFINED, 0));
	/* Extended PM1A Control Block Address */
	BASL_EXEC(basl_table_append_gas(fadt, ACPI_ADR_SPACE_SYSTEM_IO, 0x10, 0,
	    ACPI_GAS_ACCESS_WIDTH_WORD, PM1A_CNT_ADDR));
	/* Extended PM1B Control Block Address */
	BASL_EXEC(basl_table_append_gas(fadt, ACPI_ADR_SPACE_SYSTEM_IO, 0, 0,
	    ACPI_GAS_ACCESS_WIDTH_UNDEFINED, 0));
	/* Extended PM2 Control Block Address */
	BASL_EXEC(basl_table_append_gas(fadt, ACPI_ADR_SPACE_SYSTEM_IO, 8, 0,
	    ACPI_GAS_ACCESS_WIDTH_UNDEFINED, 0));
	/* Extended PM Timer Block Address */
	BASL_EXEC(basl_table_append_gas(fadt, ACPI_ADR_SPACE_SYSTEM_IO, 0x20, 0,
	    ACPI_GAS_ACCESS_WIDTH_DWORD, IO_PMTMR));
	/* Extended GPE0 Block Address */
	BASL_EXEC(basl_table_append_gas(fadt, ACPI_ADR_SPACE_SYSTEM_IO,
	    IO_GPE0_LEN * 8, 0, ACPI_GAS_ACCESS_WIDTH_BYTE, IO_GPE0_BLK));
	/* Extended GPE1 Block Address */
	BASL_EXEC(basl_table_append_gas(fadt, ACPI_ADR_SPACE_SYSTEM_IO, 0, 0,
	    ACPI_GAS_ACCESS_WIDTH_UNDEFINED, 0));
	/* Sleep Control Register Address */
	BASL_EXEC(basl_table_append_gas(fadt, ACPI_ADR_SPACE_SYSTEM_IO, 8, 0,
	    ACPI_GAS_ACCESS_WIDTH_BYTE, 0));
	/* Sleep Status Register Address */
	BASL_EXEC(basl_table_append_gas(fadt, ACPI_ADR_SPACE_SYSTEM_IO, 8, 0,
	    ACPI_GAS_ACCESS_WIDTH_BYTE, 0));
	/* Hypervisor Vendor Identity */
	BASL_EXEC(basl_table_append_int(fadt, 0, 8));

	BASL_EXEC(basl_table_append_pointer(xsdt, ACPI_SIG_FADT,
	    ACPI_XSDT_ENTRY_SIZE));

	return (0);
}

static int
build_hpet(struct vmctx *const ctx)
{
	struct basl_table *hpet;

	BASL_EXEC(basl_table_create(&hpet, ctx, ACPI_SIG_HPET,
	    BASL_TABLE_ALIGNMENT, HPET_OFFSET));

	/* Header */
	BASL_EXEC(
	    basl_table_append_header(hpet, ACPI_SIG_HPET, BASL_REVISION_HPET,
		BASL_OEM_ID, BASL_OEM_TABLE_ID_HPET, BASL_OEM_REVISION_HPET));
	/* Hardware Block ID */
	BASL_EXEC(basl_table_append_int(hpet, hpet_capabilities, 4));
	/* Timer Block Register */
	BASL_EXEC(basl_table_append_gas(hpet, ACPI_ADR_SPACE_SYSTEM_MEMORY, 0,
	    0, 0, BHYVE_ADDRESS_HPET));
	/* Sequence Number */
	BASL_EXEC(basl_table_append_int(hpet, 0, 1));
	/* Minimum Clock Ticks */
	BASL_EXEC(basl_table_append_int(hpet, 0, 2));
	/* Flags */
	BASL_EXEC(basl_table_append_int(hpet, ACPI_HPET_PAGE_PROTECT4, 4));

	BASL_EXEC(basl_table_append_pointer(xsdt, ACPI_SIG_HPET,
	    ACPI_XSDT_ENTRY_SIZE));

	return (0);
}

static int
build_madt(struct vmctx *const ctx)
{
	struct basl_table *madt;

	BASL_EXEC(basl_table_create(&madt, ctx, ACPI_SIG_MADT,
	    BASL_TABLE_ALIGNMENT, MADT_OFFSET));

	/* Header */
	BASL_EXEC(
	    basl_table_append_header(madt, ACPI_SIG_MADT, BASL_REVISION_MADT,
		BASL_OEM_ID, BASL_OEM_TABLE_ID_MADT, BASL_OEM_REVISION_MADT));
	/* Local Apic Address */
	BASL_EXEC(basl_table_append_int(madt, BHYVE_ADDRESS_LAPIC, 4));
	/* Flags */
	BASL_EXEC(basl_table_append_int(madt, ACPI_MADT_PCAT_COMPAT, 4));

	/* Local APIC for each CPU */
	for (int i = 0; i < basl_ncpu; ++i) {
		/* Type */
		BASL_EXEC(
		    basl_table_append_int(madt, ACPI_MADT_TYPE_LOCAL_APIC, 1));
		/* Length */
		BASL_EXEC(basl_table_append_int(madt, 8, 1));
		/* ACPI Processor UID */
		BASL_EXEC(basl_table_append_int(madt, i, 1));
		/* APIC ID */
		BASL_EXEC(basl_table_append_int(madt, i, 1));
		/* Flags */
		BASL_EXEC(basl_table_append_int(madt, ACPI_MADT_ENABLED, 4));
	}

	/* I/O APIC */
	/* Type */
	BASL_EXEC(basl_table_append_int(madt, ACPI_MADT_TYPE_IO_APIC, 1));
	/* Length */
	BASL_EXEC(basl_table_append_int(madt, 12, 1));
	/* I/O APIC ID */
	BASL_EXEC(basl_table_append_int(madt, 0, 1));
	/* Reserved */
	BASL_EXEC(basl_table_append_int(madt, 0, 1));
	/* I/O APIC Address */
	BASL_EXEC(basl_table_append_int(madt, BHYVE_ADDRESS_IOAPIC, 4));
	/* Interrupt Base */
	BASL_EXEC(basl_table_append_int(madt, 0, 4));

	/* Legacy IRQ0 is connected to pin 2 of the I/O APIC */
	/* Type */
	BASL_EXEC(
	    basl_table_append_int(madt, ACPI_MADT_TYPE_INTERRUPT_OVERRIDE, 1));
	/* Length */
	BASL_EXEC(basl_table_append_int(madt, 10, 1));
	/* Bus */
	BASL_EXEC(basl_table_append_int(madt, 0, 1));
	/* Source */
	BASL_EXEC(basl_table_append_int(madt, 0, 1));
	/* Interrupt */
	BASL_EXEC(basl_table_append_int(madt, 2, 4));
	/* Flags */
	BASL_EXEC(basl_table_append_int(madt,
	    ACPI_MADT_POLARITY_ACTIVE_LOW | ACPI_MADT_TRIGGER_LEVEL, 2));

	/* Type */
	BASL_EXEC(
	    basl_table_append_int(madt, ACPI_MADT_TYPE_INTERRUPT_OVERRIDE, 1));
	/* Length */
	BASL_EXEC(basl_table_append_int(madt, 10, 1));
	/* Bus */
	BASL_EXEC(basl_table_append_int(madt, 0, 1));
	/* Source */
	BASL_EXEC(basl_table_append_int(madt, SCI_INT, 1));
	/* Interrupt */
	BASL_EXEC(basl_table_append_int(madt, SCI_INT, 4));
	/* Flags */
	BASL_EXEC(basl_table_append_int(madt,
	    ACPI_MADT_POLARITY_ACTIVE_LOW | ACPI_MADT_TRIGGER_LEVEL, 2));

	/* Local APIC NMI is conntected to LINT 1 on all CPUs */
	/* Type */
	BASL_EXEC(
	    basl_table_append_int(madt, ACPI_MADT_TYPE_LOCAL_APIC_NMI, 1));
	/* Length */
	BASL_EXEC(basl_table_append_int(madt, 6, 1));
	/* Processor UID */
	BASL_EXEC(basl_table_append_int(madt, 0xFF, 1));
	/* Flags */
	BASL_EXEC(basl_table_append_int(madt,
	    ACPI_MADT_POLARITY_ACTIVE_HIGH | ACPI_MADT_TRIGGER_EDGE, 2));
	/* Local APIC LINT */
	BASL_EXEC(basl_table_append_int(madt, 1, 1));

	BASL_EXEC(basl_table_append_pointer(xsdt, ACPI_SIG_MADT,
	    ACPI_XSDT_ENTRY_SIZE));

	return (0);
}

static int
build_mcfg(struct vmctx *const ctx)
{
	struct basl_table *mcfg;

	BASL_EXEC(basl_table_create(&mcfg, ctx, ACPI_SIG_MCFG,
	    BASL_TABLE_ALIGNMENT, MCFG_OFFSET));

	/* Header */
	BASL_EXEC(
	    basl_table_append_header(mcfg, ACPI_SIG_MCFG, BASL_REVISION_MCFG,
		BASL_OEM_ID, BASL_OEM_TABLE_ID_MCFG, BASL_OEM_REVISION_MCFG));
	/* Reserved */
	BASL_EXEC(basl_table_append_int(mcfg, 0, 8));
	/* Base Address */
	BASL_EXEC(basl_table_append_int(mcfg, pci_ecfg_base(), 8));
	/* Segment Group Number */
	BASL_EXEC(basl_table_append_int(mcfg, 0, 2));
	/* Start Bus Number */
	BASL_EXEC(basl_table_append_int(mcfg, 0, 1));
	/* End Bus Number */
	BASL_EXEC(basl_table_append_int(mcfg, 0xFF, 1));
	/* Reserved */
	BASL_EXEC(basl_table_append_int(mcfg, 0, 4));

	BASL_EXEC(basl_table_append_pointer(xsdt, ACPI_SIG_MCFG,
	    ACPI_XSDT_ENTRY_SIZE));

	return (0);
}

static int
build_tpm2(struct vmctx *const ctx)
{
	struct basl_table *tpm2;

	BASL_EXEC(basl_table_create(&tpm2, ctx, ACPI_SIG_TPM2,
	    BASL_TABLE_ALIGNMENT, TPM2_OFFSET));

	/* Header */
	BASL_EXEC(
	    basl_table_append_header(tpm2, ACPI_SIG_TPM2, BASL_REVISION_TPM2,
		BASL_OEM_ID, BASL_OEM_TABLE_ID_TPM2, BASL_OEM_REVISION_TPM2));
	/* Platform Class */
	BASL_EXEC(basl_table_append_int(tpm2, 0, 2));
	/* Reserved */
	BASL_EXEC(basl_table_append_int(tpm2, 0, 2));
	/* Control Address */
	BASL_EXEC(
	    basl_table_append_int(tpm2, lpc_tpm2_get_control_address(), 8));
	/* Start Method */
	BASL_EXEC(basl_table_append_int(tpm2, 7, 4));
	/* Start Method Specific Parameters */
	uint8_t parameters[12] = { 0 };
	BASL_EXEC(basl_table_append_bytes(tpm2, parameters, 12));
	/* Log Area Minimum Length */
	BASL_EXEC(basl_table_append_int(tpm2, 0, 4));
	/* Log Area Start Address */
	BASL_EXEC(basl_table_append_int(tpm2, 0, 8));

	BASL_EXEC(basl_table_append_pointer(xsdt, ACPI_SIG_TPM2,
	    ACPI_XSDT_ENTRY_SIZE));

	return (0);
}

static int
build_xsdt(struct vmctx *const ctx)
{
	BASL_EXEC(basl_table_create(&xsdt, ctx, ACPI_SIG_XSDT,
	    BASL_TABLE_ALIGNMENT, XSDT_OFFSET));

	/* Header */
	BASL_EXEC(
	    basl_table_append_header(xsdt, ACPI_SIG_XSDT, BASL_REVISION_XSDT,
		BASL_OEM_ID, BASL_OEM_TABLE_ID_XSDT, BASL_OEM_REVISION_XSDT));
	/* Pointers (added by other build_XXX funcs) */

	return (0);
}

int
acpi_build(struct vmctx *ctx, int ncpu)
{
	int err;

	basl_ncpu = ncpu;

	err = vm_get_hpet_capabilities(ctx, &hpet_capabilities);
	if (err != 0)
		return (err);

	/*
	 * For debug, allow the user to have iasl compiler output sent
	 * to stdout rather than /dev/null
	 */
	if (getenv("BHYVE_ACPI_VERBOSE_IASL"))
		basl_verbose_iasl = 1;

	/*
	 * Allow the user to keep the generated ASL files for debugging
	 * instead of deleting them following use
	 */
	if (getenv("BHYVE_ACPI_KEEPTMPS"))
		basl_keep_temps = 1;

	BASL_EXEC(basl_init());

	BASL_EXEC(basl_make_templates());

	/*
	 * Run through all the ASL files, compiling them and
	 * copying them into guest memory
	 * 
	 * According to UEFI Specification v6.3 chapter 5.1 the FADT should be
	 * the first table pointed to by XSDT. For that reason, build it as
	 * first table after XSDT.
	 */
	BASL_EXEC(basl_compile(ctx, basl_fwrite_rsdp, 0));
	BASL_EXEC(basl_compile(ctx, basl_fwrite_rsdt, RSDT_OFFSET));
	BASL_EXEC(build_xsdt(ctx));
	BASL_EXEC(build_fadt(ctx));
	BASL_EXEC(build_madt(ctx));
	BASL_EXEC(build_hpet(ctx));
	BASL_EXEC(build_mcfg(ctx));
	BASL_EXEC(build_facs(ctx));
	if (lpc_tpm2_in_use()) {
		BASL_EXEC(build_tpm2(ctx));
	}
	BASL_EXEC(build_dsdt(ctx));

	BASL_EXEC(basl_finish());

	return (0);
}
