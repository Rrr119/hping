/*
 * tcp_options.c -- custom TCP option construction
 *
 * See tcp_options.h for the public interface. The module keeps the
 * existing --tcp-timestamp behaviour working while allowing arbitrary
 * user supplied options through --tcp-option.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "hping2.h"
#include "tcp_options.h"

/* Ring buffer of TSval values we sent, used to validate TSecr echoes. */
static u_int32_t	ts_history[TCP_TS_HISTORY_SIZE];
static unsigned int	ts_history_head;
static unsigned int	ts_history_count;

static int hex_nibble(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* Parse one byte made of two hex digits starting at str[pos], advancing
 * *pos past separators. Returns -1 on malformed input. */
static int parse_hex_byte(const char *str, unsigned int *pos)
{
	int hi, lo;

	while (str[*pos] && (isspace((unsigned char)str[*pos]) ||
			     str[*pos] == ':' || str[*pos] == ',' ||
			     str[*pos] == '-'))
		(*pos)++;

	hi = hex_nibble((unsigned char)str[*pos]);
	if (hi == -1)
		return -1;
	lo = hex_nibble((unsigned char)str[*pos + 1]);
	if (lo == -1)
		return -1;
	*pos += 2;
	return (hi << 4) | lo;
}

void tcp_options_add_raw(struct tcp_options *opts, const char *spec)
{
	unsigned int pos = 0;
	int byte;

	while (spec[pos]) {
		while (spec[pos] && (isspace((unsigned char)spec[pos]) ||
				     spec[pos] == ':' || spec[pos] == ',' ||
				     spec[pos] == '-'))
			pos++;
		if (!spec[pos])
			break;

		byte = parse_hex_byte(spec, &pos);
		if (byte == -1) {
			fprintf(stderr,
				"--tcp-option: invalid hex byte near '%.8s'\n",
				spec + pos);
			exit(1);
		}
		if (opts->len >= TCP_OPT_MAX_SIZE) {
			fprintf(stderr,
				"--tcp-option: total options exceed the %d "
				"byte TCP option space\n", TCP_OPT_MAX_SIZE);
			exit(1);
		}
		opts->data[opts->len++] = (unsigned char)byte;
	}

	if (opts->len == 0) {
		fprintf(stderr, "--tcp-option: empty option string\n");
		exit(1);
	}
}

u_int32_t tcp_options_add_timestamp(struct tcp_options *opts,
				    u_int32_t tsval)
{
	u_int32_t net_tsval;

	if (opts->len + TCPOLEN_TIMESTAMP > TCP_OPT_MAX_SIZE) {
		fprintf(stderr,
			"TCP timestamp: no room left in the %d byte TCP "
			"option space\n", TCP_OPT_MAX_SIZE);
		exit(1);
	}

	opts->data[opts->len++] = TCPOPT_NOP;
	opts->data[opts->len++] = TCPOPT_NOP;
	opts->data[opts->len++] = TCPOPT_TIMESTAMP;
	opts->data[opts->len++] = TCPOLEN_TIMESTAMP;

	net_tsval = htonl(tsval);
	memcpy(opts->data + opts->len, &net_tsval, 4);
	opts->len += 4;
	/* TSecr is zero in a SYN or when no peer timestamp is known yet. */
	memset(opts->data + opts->len, 0, 4);
	opts->len += 4;

	return tsval;
}

unsigned int tcp_options_finalize(struct tcp_options *opts)
{
	/* RFC 793: the rest of the option area after EOL is filled with
	 * EOL bytes as well, so every padding byte is simply TCPOPT_EOL. */
	while (opts->len & 3) {
		if (opts->len >= TCP_OPT_MAX_SIZE)
			break;
		opts->data[opts->len++] = TCPOPT_EOL;
	}
	return opts->len;
}

void tcp_tsecr_record(u_int32_t tsval)
{
	ts_history[ts_history_head] = tsval;
	ts_history_head = (ts_history_head + 1) % TCP_TS_HISTORY_SIZE;
	if (ts_history_count < TCP_TS_HISTORY_SIZE)
		ts_history_count++;
}

int tcp_tsecr_check(u_int32_t tsecr)
{
	unsigned int i;

	if (ts_history_count == 0)
		return 0;
	for (i = 0; i < ts_history_count; i++) {
		if (ts_history[i] == tsecr)
			return 1;
	}
	return 0;
}

void tcp_tsecr_reset(void)
{
	ts_history_head = 0;
	ts_history_count = 0;
	memset(ts_history, 0, sizeof(ts_history));
}
