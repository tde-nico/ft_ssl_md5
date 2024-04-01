#ifndef FT_SSH_H
# define FT_SSH_H

# include <stdlib.h>
# include <stdio.h>
# include <unistd.h>
# include <fcntl.h>

# define PROMPT "\033[35mft_ssl> \033[0m"
# define BSIZE 1024
# define HEX "0123456789abcdef"

# define PRINT_HEX(data, size) for (u_int32_t i = 0; i < size; ++i) { printf("%02x", data[i]); }
# define ROTLD(x, n) ((x << n) | (x >> (32 - n)))
# define ROTRD(x, n) ((x >> n) | (x << (32 - n)))
# define ROTLQ(x, n) ((x << n) | (x >> (64 - n)))
# define ROTRQ(x, n) ((x >> n) | (x << (64 - n)))

typedef struct s_hash
{
	char		*name;
	void		(*init)(void);
	void		(*update)(u_int8_t *, size_t);
	void		(*final)(u_int8_t *);
	u_int32_t	digest_size;
}	t_hash;

typedef union u_algo
{
	t_hash		hash;
}	t_algo;

typedef struct s_cmd
{
	char	*name;
	int		(*schedule)(t_algo *, int, char **);
	t_algo	algo;
}	t_cmd;


// hash.c
int		ft_hash(t_algo *algo, int argc, char **argv);

// libft.c
size_t	ft_strlen(const char *str);
int		ft_strncmp(const char *s1, const char *s2, unsigned int n);
void	*ft_memset(void *b, int c, size_t len);


#endif
