/* Fuzz the SQL + openCypher raw parser (gram.y / scan.l) and the node-tree support code. */
#include "pg_fuzz_common.h"

#include "nodes/nodes.h"
#include "nodes/pg_list.h"
#include "parser/parser.h"

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	pgfuzz_init();
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	PGFUZZ_BEGIN();
	char	   *sql = pgfuzz_cstring(data, size);

	if (!pgfuzz_valid_text(sql, size))
	{
		MemoryContextSwitchTo(pgfuzz_old);
		MemoryContextDelete(pgfuzz_ctx);
		return FUZZ_REJECT;
	}

	PG_TRY();
	{
		List	   *tree = raw_parser(sql, RAW_PARSE_DEFAULT);

		(void) nodeToString(tree);
		(void) copyObject(tree);
	}
	PGFUZZ_CATCH(FUZZ_REJECT);

	PGFUZZ_END();
}
