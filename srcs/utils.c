#include "ft_ssl.h"

size_t	readb(int fd, char *buf, size_t len)
{
	size_t	sum;
	size_t	r;

	sum = 0;
	while (sum < len)
	{
		r = read(fd, buf, 1);
		if (r <= 0)
			break ;
		++sum; 
	}
	return (sum);
}

char	*str_to_hex(char *s, size_t len)
{
	char	*hex;
	size_t	i;

	hex = malloc(len * 2 + 1);
	if (!hex)
		return (NULL);
	i = -1;
	while (++i < len)
	{
		hex[i * 2] = HEX[(u_int8_t)s[i] / 16];
		hex[i * 2 + 1] = HEX[(u_int8_t)s[i] % 16];
	}
	hex[i * 2] = '\0';
	return (hex);
}
