#include "sha256.h"

static t_sha256_ctx	ctx;


static const u_int32_t K[] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
	0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
	0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
	0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
	0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
	0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
	0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
	0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
	0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
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


void	sha256_init(void)
{
	ctx.len = 0;
	ctx.state[0] = 0x6a09e667;
	ctx.state[1] = 0xbb67ae85;
	ctx.state[2] = 0x3c6ef372;
	ctx.state[3] = 0xa54ff53a;
	ctx.state[4] = 0x510e527f;
	ctx.state[5] = 0x9b05688c;
	ctx.state[6] = 0x1f83d9ab;
	ctx.state[7] = 0x5be0cd19;
}

void	sha256_transform(void)
{
	u_int32_t	A;
	u_int32_t	B;
	u_int32_t	C;
	u_int32_t	D;
	u_int32_t	E;
	u_int32_t	F;
	u_int32_t	G;
	u_int32_t	H;
	u_int32_t	t1;
	u_int32_t	t2;
	u_int32_t	m[64] = {0};
	u_int32_t	i;

	A = ctx.state[0];
	B = ctx.state[1];
	C = ctx.state[2];
	D = ctx.state[3];
	E = ctx.state[4];
	F = ctx.state[5];
	G = ctx.state[6];
	H = ctx.state[7];
	t1 = 0;
	t2 = 0;

	i = -1;
	while (++i < 16)
		m[i] = ctx.buffer[i * 4] << 24
			| ctx.buffer[i * 4 + 1] << 16
			| ctx.buffer[i * 4 + 2] << 8
			| ctx.buffer[i * 4 + 3];
	--i;
	while (++i < 64)
		m[i] = (ROTRD(m[i-2], 17) ^ ROTRD(m[i-2], 19) ^ (m[i-2] >> 10)) + m[i - 7]
			+ (ROTRD(m[i-15], 7) ^ ROTRD(m[i-15], 18) ^ (m[i-15] >> 3)) + m[i - 16];

	i = -1;
	while (++i < 64)
	{
		t1 = H + (ROTRD(E, 6) ^ ROTRD(E, 11) ^ ROTRD(E, 25))
			+ ((E & F) ^ (~E & G)) + K[i] + m[i];
		t2 = (ROTRD(A, 2) ^ ROTRD(A, 13) ^ ROTRD(A, 22))
			+ ((A & B) ^ (A & C) ^ (B & C));
		H = G;
		G = F;
		F = E;
		E = D + t1;
		D = C;
		C = B;
		B = A;
		A = t1 + t2;
	}
	
	ctx.state[0] += A;
	ctx.state[1] += B;
	ctx.state[2] += C;
	ctx.state[3] += D;
	ctx.state[4] += E;
	ctx.state[5] += F;
	ctx.state[6] += G;
	ctx.state[7] += H;
}

void	sha256_update(u_int8_t *data, size_t len)
{
	u_int32_t	off;
	u_int32_t	i;

	off = ctx.len % 64;
	ctx.len += len;
	i = -1;
	while (++i < len)
	{
		ctx.buffer[off++] = data[i];
		if (off % 64)
			continue ;
		sha256_transform();
		off = 0;
	}	
}

void	sha256_final(u_int8_t *digest)
{
	u_int32_t	off;
	u_int32_t	pad_len;
	u_int32_t	i;

	off = ctx.len % 64;
	pad_len = 56 - off;
	if (off >= 56)
		pad_len += 64;
	sha256_update(pad, pad_len);
	ctx.len -= pad_len;

	ctx.buffer[56] = (ctx.len * 8) >> 56;
	ctx.buffer[57] = (ctx.len * 8) >> 48;
	ctx.buffer[58] = (ctx.len * 8) >> 40;
	ctx.buffer[59] = (ctx.len * 8) >> 32;
	ctx.buffer[60] = (ctx.len * 8) >> 24;
	ctx.buffer[61] = (ctx.len * 8) >> 16;
	ctx.buffer[62] = (ctx.len * 8) >> 8;
	ctx.buffer[63] = (ctx.len * 8);
	sha256_transform();

	i = -1;
	while (++i < 4)
	{
		digest[i] = (ctx.state[0] >> (24 - i * 8)) & 0xFF;
		digest[i + 4] = (ctx.state[1] >> (24 - i * 8)) & 0xFF;
		digest[i + 8] = (ctx.state[2] >> (24 - i * 8)) & 0xFF;
		digest[i + 12] = (ctx.state[3] >> (24 - i * 8)) & 0xFF;
		digest[i + 16] = (ctx.state[4] >> (24 - i * 8)) & 0xFF;
		digest[i + 20] = (ctx.state[5] >> (24 - i * 8)) & 0xFF;
		digest[i + 24] = (ctx.state[6] >> (24 - i * 8)) & 0xFF;
		digest[i + 28] = (ctx.state[7] >> (24 - i * 8)) & 0xFF;
	}

	ft_memset(&ctx, 0, sizeof(t_sha256_ctx));
}
