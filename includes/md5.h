#ifndef MD5_H
# define MD5_H

# include "ft_ssl.h"

# define MD5_DIGEST_SIZE 16

typedef struct s_md5_ctx
{
	u_int64_t	len;
	u_int32_t	state[4];
	u_int8_t	buffer[64];
}	t_md5_ctx;

void	md5_init(void);
void	md5_update(u_int8_t *data, size_t len);
void	md5_final(u_int8_t *digest);

#endif
