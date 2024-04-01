#ifndef WIRLPOOL_H
# define WIRLPOOL_H

# include "ft_ssl.h"

# define WHIRLPOOL_DIGEST_SIZE 64

#define BSWAPQ(x) ((((x) & 0xff00000000000000ull) >> 56) \
				| (((x) & 0x00ff000000000000ull) >> 40) \
				| (((x) & 0x0000ff0000000000ull) >> 24) \
				| (((x) & 0x000000ff00000000ull) >> 8) \
				| (((x) & 0x00000000ff000000ull) << 8) \
				| (((x) & 0x0000000000ff0000ull) << 24) \
				| (((x) & 0x000000000000ff00ull) << 40) \
				| (((x) & 0x00000000000000ffull) << 56))

#define ROUND(b, a, n, c) { \
	b = T[(a[n] >> 56) & 0xFF]; \
	b ^= ROTRQ(T[(a[(n + 7) % 8] >> 48) & 0xFF], 8); \
	b ^= ROTRQ(T[(a[(n + 6) % 8] >> 40) & 0xFF], 16); \
	b ^= ROTRQ(T[(a[(n + 5) % 8] >> 32) & 0xFF], 24); \
	b ^= ROTRQ(T[(a[(n + 4) % 8] >> 24) & 0xFF], 32); \
	b ^= ROTRQ(T[(a[(n + 3) % 8] >> 16) & 0xFF], 40); \
	b ^= ROTRQ(T[(a[(n + 2) % 8] >> 8) & 0xFF], 48); \
	b ^= ROTRQ(T[a[(n + 1) % 8] & 0xFF], 56); \
	b ^= c; \
}

typedef struct s_whirlpool_ctx
{
	u_int64_t	len;
	u_int64_t	state[8];
	u_int8_t	buffer[64];
}	t_whirlpool_ctx;

void	whirlpool_init(void);
void	whirlpool_update(u_int8_t *data, size_t len);
void	whirlpool_final(u_int8_t *digest);

#endif
