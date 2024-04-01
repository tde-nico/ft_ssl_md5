#include "md5.h"

static t_md5_ctx	ctx;


static const u_int32_t S[] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static const u_int32_t K[] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static u_int8_t pad[] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


void	md5_init(void)
{
	ctx.len = 0;
	ctx.state[0] = 0x67452301;
	ctx.state[1] = 0xEFCDAB89;
	ctx.state[2] = 0x98BADCFE;
	ctx.state[3] = 0x10325476;
}

void	md5_transform(u_int32_t m[16])
{
	u_int32_t	A;
	u_int32_t	B;
	u_int32_t	C;
	u_int32_t	D;
	u_int32_t	FF;
	u_int32_t	g;
	int			i;


	A = ctx.state[0];
	B = ctx.state[1];
	C = ctx.state[2];
	D = ctx.state[3];
	FF = 0;
	g = 0;

	i = -1;
	while (++i < 64)
	{
		if (0 <= i && i < 16) {
			FF = (B & C) | (~B & D);
			g = i;
		} else if (16 <= i && i < 32) {
			FF = (B & D) | (C & ~D);
			g = ((i * 5) + 1) % 16;
		} else if (32 <= i && i < 48) {
			FF = B ^ C ^ D;
			g = ((i * 3) + 5) % 16;
		} else if (48 <= i && i < 64) {
			FF = C ^ (B | ~D);
			g = (i * 7) % 16;
		}

		FF += A + K[i] + m[g];
		A = D;
		D = C;
		C = B;
		B += ROTLD(FF, S[i]);
	}

	ctx.state[0] += A;
	ctx.state[1] += B;
	ctx.state[2] += C;
	ctx.state[3] += D;
}

void	md5_update(u_int8_t *data, size_t len)
{
	u_int32_t	m[16] = {0};
	u_int32_t	off;
	u_int32_t	i;
	u_int32_t	j;

	off = ctx.len % 64;
	ctx.len += len;
	i = -1;
	while (++i < len)
	{
		ctx.buffer[off++] = data[i];
		if (off % 64)
			continue ;
		j = -1;
		while (++j < 16)
			m[j] = ctx.buffer[j * 4]
				| ctx.buffer[j * 4 + 1] << 8
				| ctx.buffer[j * 4 + 2] << 16
				| ctx.buffer[j * 4 + 3] << 24;
		md5_transform(m);
		off = 0;
	}
}

void	md5_final(u_int8_t *digest)
{
	u_int32_t	m[16] = {0};
	u_int32_t	off;
	u_int32_t	pad_len;
	u_int32_t	i;

	off = ctx.len % 64;
	pad_len = 56 - off;
	if (off >= 56)
		pad_len += 64;
	md5_update(pad, pad_len);
	ctx.len -= pad_len;

	i = -1;
	while (++i < 14)
		m[i] = ctx.buffer[i * 4]
			| ctx.buffer[i * 4 + 1] << 8
			| ctx.buffer[i * 4 + 2] << 16
			| ctx.buffer[i * 4 + 3] << 24;
	m[14] = ctx.len * 8;
	m[15] = (ctx.len * 8) >> 32;
	md5_transform(m);

	i = -1;
	while (++i < 4)
	{
		digest[i] = ctx.state[0] >> (i * 8) & 0xFF;
		digest[i + 4] = ctx.state[1] >> (i * 8) & 0xFF;
		digest[i + 8] = ctx.state[2] >> (i * 8) & 0xFF;
		digest[i + 12] = ctx.state[3] >> (i * 8) & 0xFF;
	}

	ft_memset(&ctx, 0, sizeof(t_md5_ctx));
}
