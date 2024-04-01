#ifndef SHA256_H
# define SHA256_H

# include "ft_ssl.h"

# define SHA256_DIGEST_SIZE 32

typedef struct s_sha256_ctx
{
	u_int64_t	len;
	u_int32_t	state[8];
	u_int8_t	buffer[64];
}	t_sha256_ctx;

void	sha256_init(void);
void	sha256_update(u_int8_t *data, size_t len);
void	sha256_final(u_int8_t *digest);

#endif
