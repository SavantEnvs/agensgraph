/*
 * Shared in-process backend setup for the AgensGraph fuzz harnesses.
 *
 * The harnesses call backend functions directly, outside a postmaster, so a
 * memory-context tree, a server encoding and a stack base have to exist first.
 * Errors raised by the backend with ereport(ERROR) are caught with
 * PG_TRY()/PG_CATCH(), which is how every backend caller handles them.
 */
#ifndef PG_FUZZ_COMMON_H
#define PG_FUZZ_COMMON_H

#include "postgres.h"

#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "catalog/pg_collation.h"
#include "mb/pg_wchar.h"
#include "miscadmin.h"
#include "postmaster/postmaster.h"
#include "tcop/dest.h"
#include "tcop/tcopprot.h"
#include "utils/catcache.h"
#include "utils/guc.h"
#include "utils/guc_hooks.h"
#include "utils/memutils.h"
#include "utils/pg_locale.h"

/*
 * pg_locale.c's static database default locale; build.sh exports the symbol
 * (objcopy --globalize-symbol) so it can be set up here without a catalog.
 */
extern pg_locale_t default_locale;

#define FUZZ_REJECT (-1)

static void
pgfuzz_init(void)
{
	progname = "postgres";
	MyProcPid = getpid();
	MemoryContextInit();
	whereToSendOutput = DestNone;
	log_min_messages = PANIC;
	client_min_messages = PANIC;
	SetDatabaseEncoding(PG_UTF8);
	set_stack_base();
	assign_max_stack_depth(1024, NULL);
	/* cached regexes live here and must outlive the per-input context */
	CreateCacheMemoryContext();

	/*
	 * InitPostgres() -> init_database_collation() sets the default locale from the
	 * pg_database row before any query runs; without it every locale-dependent call
	 * (varstr_cmp, str_tolower, regex compilation, ...) dereferences NULL. Set what
	 * create_pg_locale_libc() builds for a database created with the "C" locale.
	 */
	default_locale = MemoryContextAllocZero(TopMemoryContext, sizeof(struct pg_locale_struct));
	default_locale->provider = COLLPROVIDER_LIBC;
	default_locale->deterministic = true;
	default_locale->collate_is_c = true;
	default_locale->ctype_is_c = true;
	default_locale->is_default = true;
}

/* Copy the input into a NUL-terminated palloc'd string in the current context. */
static char *
pgfuzz_cstring(const uint8_t *data, size_t size)
{
	char	   *s = palloc(size + 1);

	memcpy(s, data, size);
	s[size] = '\0';
	return s;
}

/*
 * Server-encoding precondition: backend text-input functions and the parser
 * receive strings already validated against the server encoding (client input
 * goes through pg_client_to_server -> pg_verify_mbstr).
 */
static bool
pgfuzz_valid_text(const char *s, size_t len)
{
	return strlen(s) == len && pg_verify_mbstr(PG_UTF8, s, (int) len, true);
}

#define PGFUZZ_BEGIN() \
	MemoryContext pgfuzz_old = CurrentMemoryContext; \
	MemoryContext pgfuzz_ctx = AllocSetContextCreate(TopMemoryContext, "fuzz input", ALLOCSET_DEFAULT_SIZES); \
	volatile int pgfuzz_rc = 0; \
	MemoryContextSwitchTo(pgfuzz_ctx)

/* After PG_CATCH the error is flushed and the input counts as rejected (or ok if on_err is 0). */
#define PGFUZZ_CATCH(on_err) \
	PG_CATCH(); \
	{ \
		MemoryContextSwitchTo(pgfuzz_ctx); \
		FlushErrorState(); \
		pgfuzz_rc = (on_err); \
	} \
	PG_END_TRY()

#define PGFUZZ_END() \
	MemoryContextSwitchTo(pgfuzz_old); \
	MemoryContextDelete(pgfuzz_ctx); \
	return pgfuzz_rc

#endif
