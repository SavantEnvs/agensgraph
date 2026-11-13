/*
 * Fuzz the JSON family of type input/output functions: jsonb, json, jsonpath,
 * and jsonpath evaluation over a jsonb document. The first input byte selects
 * the function; the rest is the text (for the path case: document NUL path).
 */
#include "pg_fuzz_common.h"

#include "fmgr.h"
#include "utils/fmgrprotos.h"
#include "utils/jsonb.h"
#include "utils/jsonpath.h"

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
	uint8_t		sel = data[0] % 4;
	char	   *text = pgfuzz_cstring(data + 1, size - 1);

	if (!pgfuzz_valid_text(text, size - 1) && sel != 3)
	{
		MemoryContextSwitchTo(pgfuzz_old);
		MemoryContextDelete(pgfuzz_ctx);
		return FUZZ_REJECT;
	}

	PG_TRY();
	{
		switch (sel)
		{
			case 0:
				{
					Datum		jb = DirectFunctionCall1(jsonb_in, CStringGetDatum(text));

					(void) DirectFunctionCall1(jsonb_out, jb);
					(void) DirectFunctionCall1(jsonb_pretty, jb);
					(void) DirectFunctionCall1(jsonb_strip_nulls, jb);
					(void) DirectFunctionCall1(jsonb_typeof, jb);
					break;
				}
			case 1:
				{
					Datum		js = DirectFunctionCall1(json_in, CStringGetDatum(text));

					(void) DirectFunctionCall1(json_out, js);
					(void) DirectFunctionCall1(json_typeof, js);
					break;
				}
			case 2:
				{
					Datum		jp = DirectFunctionCall1(jsonpath_in, CStringGetDatum(text));

					(void) DirectFunctionCall1(jsonpath_out, jp);
					break;
				}
			default:
				{
					/* document NUL path */
					const char *doc = text;
					size_t		doclen = strlen(doc);
					const char *path = doc + doclen < text + size - 1 ? doc + doclen + 1 : "";
					Datum		jb,
								jp,
								vars;

					if (!pgfuzz_valid_text(doc, doclen) ||
						!pgfuzz_valid_text(path, strlen(path)))
						elog(ERROR, "invalid text");
					jb = DirectFunctionCall1(jsonb_in, CStringGetDatum(doc));
					jp = DirectFunctionCall1(jsonpath_in, CStringGetDatum(path));
					vars = DirectFunctionCall1(jsonb_in, CStringGetDatum("{}"));
					(void) DirectFunctionCall4(jsonb_path_query_array, jb, jp, vars, BoolGetDatum(false));
					(void) DirectFunctionCall4(jsonb_path_exists, jb, jp, vars, BoolGetDatum(true));
					break;
				}
		}
	}
	PGFUZZ_CATCH(FUZZ_REJECT);

	PGFUZZ_END();
}
