/*
 * Fuzz the kamailio.cfg grammar (src/core/cfg.y -> cfg.tab.c + cfg.lex ->
 * lex.yy.c): the input is parsed as a complete configuration file through the
 * real bison parser (yyparse), after the same minimal setup main.c performs
 * before parsing. The config parser was entirely uncovered before (cfg.tab.c
 * 0/7360, lex.yy.c 0/4262 in production coverage).
 *
 * Directives with file-system or dlopen side effects at parse time
 * (loadmodule / loadmodulex / include_file / import_file) are skipped: they
 * would make the fuzzed process depend on the build host contents.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose is freely granted, provided this notice is preserved.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "../config.h"

#include "../route.h"
#include "../flags.h"
#include "../globals.h"
#include "../ppcfg.h"
#include "../shm_init.h"


extern int yyparse(void);
extern FILE *yyin;
extern void yyrestart(FILE *);

static int _fuzz_cfg_inited = 0;

/*
 * The config grammar has by-design fatal-error paths that terminate the
 * process (ksr_exit() -> _exit(-1)): e.g. a function call nested inside
 * another function's parameters, or listen-socket attribute blocks that
 * fail to install. For the daemon the config file is admin-controlled and
 * this is intended behaviour; for fuzzing, such an input must only end the
 * current parse. Interpose _exit(): while a parse is running on this
 * thread, convert it into a rejection longjmp; any other caller (fuzzer
 * runtime, other threads) gets the real exit_group.
 */
static __thread int _fuzz_in_parse = 0;
static jmp_buf _fuzz_parse_env;

void _exit(int status)
{
	if(_fuzz_in_parse) {
		_fuzz_in_parse = 0;
		longjmp(_fuzz_parse_env, 1);
	}
	syscall(SYS_exit_group, status);
	for(;;) {
		pause();
	}
}

/* small memmem replacement, to avoid depending on _GNU_SOURCE */
static void *fuzz_memfind(const void *hay, size_t haylen,
		const char *needle, size_t nlen)
{
	size_t i;

	if(nlen == 0 || haylen < nlen) {
		return NULL;
	}
	for(i = 0; i + nlen <= haylen; i++) {
		if(memcmp((const char *)hay + i, needle, nlen) == 0) {
			return (void *)((const char *)hay + i);
		}
	}
	return NULL;
}

static int input_has_side_effects(const char *buf, size_t len)
{
	static const char *skip[] = {
		"loadmodule", "loadmodulex", "include_file", "import_file",
		NULL,
	};
	int i;

	for(i = 0; skip[i] != NULL; i++) {
		if(fuzz_memfind(buf, len, skip[i], strlen(skip[i])) != NULL) {
			return 1;
		}
	}
	return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	/* The config parser exits the process from yyerror() on the first
	 * error unless "all errors" mode is enabled (the same behaviour the
	 * daemon exposes with all_errors=1): enable it so a fuzzed config
	 * reports every error through cfg_errors instead of exiting. */
	ksr_all_errors = 1;

	/* Same pre-parse setup main.c performs: the default shared-memory
	 * manager name must be installed before yyparse() so that config
	 * modparam() statements can lazily initialize shm exactly like the
	 * daemon does (init_shm() would otherwise strcmp() a NULL name). */
	shm_set_mname("qm");

	/* main.c sizes the shared-memory pool before parsing (command line
	 * -m / build default); without a size, config modparam() statements
	 * fail their lazy init_shm() and abort the parse early. */
	shm_mem_size = 1 * 1024 * 1024;

	/* named flags hash: allocated once, then re-allocated after every
	 * destroy_routes() (the grammar fills it with flag definitions). */
	init_named_flags();

	/* route blocks land in main_rt/failure_rt/onreply_rt rlist[] tables,
	 * which main.c allocates via init_routes() before parsing. */
	if(init_routes() < 0) {
		return 1;
	}

	_fuzz_cfg_inited = 1;
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *buf;
	FILE *f;

	if(size < 4 || size > 128 * 1024) {
		return 0;
	}

	buf = (char *)malloc(size + 1);
	if(buf == NULL) {
		return 0;
	}
	memcpy(buf, data, size);
	buf[size] = '\0';

	if(input_has_side_effects(buf, size)) {
		free(buf);
		return 0;
	}

	if(_fuzz_cfg_inited == 0) {
		init_named_flags();
		_fuzz_cfg_inited = 1;
	}

	cfg_errors = 0;
	cfg_warnings = 0;

	f = fmemopen(buf, size, "r");
	if(f == NULL) {
		free(buf);
		return 0;
	}
	yyin = f;
	yyrestart(yyin);

	_fuzz_in_parse = 1;
	if(setjmp(_fuzz_parse_env) == 0) {
		yyparse();
	}
	_fuzz_in_parse = 0;

	fclose(f);

	/* Free the routes built by this parse and re-create the route-list
	 * tables and the flag hash, so the next iteration starts from the
	 * same clean state destroy_routes() left behind (it frees rlist[]). */
	destroy_routes();
	init_routes();
	init_named_flags();

	free(buf);
	return 0;
}
