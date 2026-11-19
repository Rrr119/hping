/*
 * Unit tests for the TCP option builder. Built and run by
 * tests/run_tests.sh; no network access is required.
 */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "tcp_options.h"

static int failures;

#define CHECK(cond, msg) do {						\
	if (!(cond)) {							\
		printf("FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__);	\
		failures++;						\
	} else {							\
		printf("ok: %s\n", msg);				\
	}								\
} while (0)

static void test_raw_option_padding(void)
{
	struct tcp_options opts;

	memset(&opts, 0, sizeof(opts));
	/* window scale: kind 3, len 3, shift 7 -> 3 bytes, needs 1 EOL */
	tcp_options_add_raw(&opts, "030307");
	CHECK(opts.len == 3, "raw option stored with given length");
	CHECK(tcp_options_finalize(&opts) == 4,
	      "option block padded to a 32 bit boundary");
	CHECK(opts.data[0] == 3 && opts.data[1] == 3 &&
	      opts.data[2] == 7 && opts.data[3] == TCPOPT_EOL,
	      "raw bytes preserved and EOL padding appended");
}

static void test_separators_and_repeated_options(void)
{
	struct tcp_options opts;

	memset(&opts, 0, sizeof(opts));
	tcp_options_add_raw(&opts, "02 04 05,b4"); /* MSS 1460 */
	tcp_options_add_raw(&opts, "03-03-07");    /* wscale 7 */
	CHECK(opts.len == 7, "two options concatenate to 7 bytes");
	CHECK(opts.data[2] == 0x05 && opts.data[3] == 0xb4,
	      "spaces/commas/dashes accepted as separators");
	CHECK(tcp_options_finalize(&opts) == 8,
	      "combined block padded to 8 bytes");
}

static void test_timestamp_layout(void)
{
	struct tcp_options opts;
	unsigned int sent;

	memset(&opts, 0, sizeof(opts));
	tcp_options_add_raw(&opts, "030307");
	sent = tcp_options_add_timestamp(&opts, 0x11223344);
	CHECK(opts.len == 3 + 12, "timestamp adds NOP,NOP + 10 option bytes");
	CHECK(opts.data[3] == TCPOPT_NOP && opts.data[4] == TCPOPT_NOP,
	      "timestamp prefixed by two NOPs for alignment");
	CHECK(opts.data[5] == TCPOPT_TIMESTAMP && opts.data[6] == 10,
	      "timestamp kind/length are 8/10");
	CHECK(opts.data[7] == 0x11 && opts.data[10] == 0x44,
	      "TSval converted to network byte order");
	CHECK(opts.data[11] == 0 && opts.data[14] == 0,
	      "TSecr initialized to zero");
	CHECK(tcp_options_finalize(&opts) == 16,
	      "mixed option block padded to 16 bytes");
	CHECK(sent == 0x11223344, "builder returns the stored TSval");
}

static void test_tsecr_history(void)
{
	tcp_tsecr_reset();
	CHECK(tcp_tsecr_check(htonl(1234)) == 0,
	      "no history means no echo match");
	tcp_tsecr_record(htonl(1234));
	tcp_tsecr_record(htonl(5678));
	CHECK(tcp_tsecr_check(htonl(1234)) == 1,
	      "echo matching a recorded TSval is accepted");
	CHECK(tcp_tsecr_check(htonl(5678)) == 1,
	      "second recorded TSval is accepted");
	CHECK(tcp_tsecr_check(htonl(9999)) == 0,
	      "unknown echo is rejected");
	tcp_tsecr_reset();
	CHECK(tcp_tsecr_check(htonl(1234)) == 0,
	      "history reset clears recorded values");
}

static void test_ring_overwrite(void)
{
	unsigned int i;

	tcp_tsecr_reset();
	for (i = 1; i <= TCP_TS_HISTORY_SIZE + 10; i++)
		tcp_tsecr_record(htonl(i));
	CHECK(tcp_tsecr_check(htonl(1)) == 0,
	      "oldest entries fall off the ring buffer");
	CHECK(tcp_tsecr_check(htonl(11)) == 1,
	      "recent entries remain in the ring buffer");
	CHECK(tcp_tsecr_check(htonl(TCP_TS_HISTORY_SIZE + 10)) == 1,
	      "newest entry is verifiable");
	tcp_tsecr_reset();
}

int main(void)
{
	test_raw_option_padding();
	test_separators_and_repeated_options();
	test_timestamp_layout();
	test_tsecr_history();
	test_ring_overwrite();

	if (failures) {
		printf("%d test(s) failed\n", failures);
		return 1;
	}
	puts("all tcp_options unit tests passed");
	return 0;
}
