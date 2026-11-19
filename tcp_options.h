/*
 * tcp_options.h -- custom TCP option construction
 *
 * Collects the legacy TCP timestamp option together with user supplied
 * raw TCP options (--tcp-option) into a single, RFC 793/1323 aligned
 * option block. Every option block produced by this module is padded
 * with NOPs and terminated by EOL so the TCP data offset stays on a
 * 32 bit boundary.
 */

#ifndef _TCP_OPTIONS_H
#define _TCP_OPTIONS_H

#include <sys/types.h>

/* TCP options are at most 40 bytes long (60 byte max header - 20 fixed). */
#define TCP_OPT_MAX_SIZE	40

/* Well known option kinds, see RFC 793 / RFC 1323. */
#define TCPOPT_EOL		0
#define TCPOPT_NOP		1
#define TCPOPT_MAXSEG		2
#define TCPOPT_WSCALE		3
#define TCPOPT_SACK_PERMITTED	4
#define TCPOPT_SACK		5
#define TCPOPT_TIMESTAMP	8

#define TCPOLEN_TIMESTAMP	10

/* Number of sent timestamp values remembered for TSecr echo verification. */
#define TCP_TS_HISTORY_SIZE	256

struct tcp_options {
	unsigned char	data[TCP_OPT_MAX_SIZE];
	unsigned int	len;	/* raw option length, before EOL padding */
};

/* Append a raw option string (hex bytes, e.g. "030307") to the block.
 * Exits with a diagnostic on malformed input or when the block overflows. */
void	tcp_options_add_raw(struct tcp_options *opts, const char *spec);

/* Append a RFC 1323 timestamp option. Returns the TSval actually stored so
 * it can be registered for later echo verification. */
u_int32_t tcp_options_add_timestamp(struct tcp_options *opts, u_int32_t tsval);

/* Pad the block with NOPs and a final EOL to a 32 bit boundary and return
 * the total wire length (always a multiple of four, at most 40). */
unsigned int tcp_options_finalize(struct tcp_options *opts);

/* Remember a TSval we sent, to validate the peer's TSecr echo. */
void	tcp_tsecr_record(u_int32_t tsval);

/* Returns 1 if ts.ecr matches one of the TSval values we recently sent,
 * 0 otherwise (echo rewritten/zeroed by a middlebox, or no history). */
int	tcp_tsecr_check(u_int32_t tsecr);

/* Discard the recorded history (used by unit tests). */
void	tcp_tsecr_reset(void);

#endif /* _TCP_OPTIONS_H */
