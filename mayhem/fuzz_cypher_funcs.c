/*
 * Fuzz AgensGraph's jsonb-based openCypher scalar functions and operators
 * (head, tail, toStringList, substring, +, -, ... in cypher_funcs.c and
 * cypher_ops.c) by calling them the way the executor does. The first input
 * byte selects the function; the remaining bytes are its jsonb arguments,
 * separated by NUL bytes.
 */
#include "pg_fuzz_common.h"

#include "catalog/pg_collation_d.h"
#include "fmgr.h"
#include "utils/fmgrprotos.h"
#include "utils/jsonb.h"

typedef struct
{
	PGFunction	fn;
	int			nargs;
} CypherFunc;

static const CypherFunc funcs[] = {
	{ jsonb_head, 1 },
	{ jsonb_last, 1 },
	{ jsonb_length, 1 },
	{ jsonb_cardinality, 1 },
	{ jsonb_toboolean, 1 },
	{ jsonb_keys, 1 },
	{ jsonb_tail, 1 },
	{ jsonb_abs, 1 },
	{ jsonb_ceil, 1 },
	{ jsonb_floor, 1 },
	{ jsonb_round, 1 },
	{ jsonb_sign, 1 },
	{ jsonb_exp, 1 },
	{ jsonb_log, 1 },
	{ jsonb_sqrt, 1 },
	{ jsonb_acos, 1 },
	{ jsonb_asin, 1 },
	{ jsonb_atan, 1 },
	{ jsonb_cos, 1 },
	{ jsonb_cot, 1 },
	{ jsonb_degrees, 1 },
	{ jsonb_radians, 1 },
	{ jsonb_sin, 1 },
	{ jsonb_tan, 1 },
	{ jsonb_ltrim, 1 },
	{ jsonb_reverse, 1 },
	{ jsonb_rtrim, 1 },
	{ jsonb_tolower, 1 },
	{ jsonb_tostring, 1 },
	{ jsonb_toupper, 1 },
	{ jsonb_trim, 1 },
	{ jsonb_tostringlist, 1 },
	{ jsonb_array_reverse, 1 },
	{ jsonb_tointegerlist, 1 },
	{ jsonb_tofloatlist, 1 },
	{ jsonb_uplus, 1 },
	{ jsonb_uminus, 1 },
	{ jsonb_atan2, 2 },
	{ jsonb_left, 2 },
	{ jsonb_right, 2 },
	{ jsonb_substr_no_len, 2 },
	{ jsonb_string_starts_with, 2 },
	{ jsonb_string_ends_with, 2 },
	{ jsonb_string_contains, 2 },
	{ jsonb_string_regex, 2 },
	{ jsonb_larger, 2 },
	{ jsonb_smaller, 2 },
	{ jsonb_add, 2 },
	{ jsonb_sub, 2 },
	{ jsonb_mul, 2 },
	{ jsonb_div, 2 },
	{ jsonb_mod, 2 },
	{ jsonb_pow, 2 },
	{ jsonb_replace, 3 },
	{ jsonb_substr, 3 },
};

#define NFUNCS (sizeof(funcs) / sizeof(funcs[0]))

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	pgfuzz_init();
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 1)
		return FUZZ_REJECT;

	PGFUZZ_BEGIN();
	const CypherFunc *f = &funcs[data[0] % NFUNCS];
	const uint8_t *p = data + 1;
	const uint8_t *end = data + size;
	Datum		args[3];
	int			i;
	volatile bool args_ok = false;

	PG_TRY();
	{
		for (i = 0; i < f->nargs; i++)
		{
			const uint8_t *nul = p < end ? memchr(p, 0, end - p) : NULL;
			size_t		len = (nul ? nul : end) - p;
			char	   *s = pgfuzz_cstring(p, len);

			if (!pgfuzz_valid_text(s, len))
				elog(ERROR, "invalid text");
			args[i] = DirectFunctionCall1(jsonb_in, CStringGetDatum(s));
			p = nul ? nul + 1 : end;
		}

		args_ok = true;

		/* C collation: the regex-based functions need one that needs no catalog */
		switch (f->nargs)
		{
			case 1:
				(void) DirectFunctionCall1Coll(f->fn, DEFAULT_COLLATION_OID, args[0]);
				break;
			case 2:
				(void) DirectFunctionCall2Coll(f->fn, DEFAULT_COLLATION_OID, args[0], args[1]);
				break;
			default:
				(void) DirectFunctionCall3Coll(f->fn, DEFAULT_COLLATION_OID, args[0], args[1], args[2]);
				break;
		}
	}
	PGFUZZ_CATCH(args_ok ? 0 : FUZZ_REJECT);

	PGFUZZ_END();
}
