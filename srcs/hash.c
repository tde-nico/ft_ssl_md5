#include "ft_ssl.h"

void	ft_hash_stdin(t_hash *h, int qflag)
{
	u_int8_t	*digest;
	u_int8_t	buf[512];
	u_int32_t	r;

	ft_memset(buf, 0, 512);
	digest = malloc(h->digest_size);
	if (!digest)
	{
		printf("Error: malloc failed\n");
		return ;
	}
	h->init();
	while ((r = read(0, buf, 512)) > 0)
	{
		if (qflag)
			write(1, buf, r);
		h->update(buf, r);
	}
	h->final(digest);
	PRINT_HEX(digest, h->digest_size);
	printf("\n");
	free(digest);
}

void	ft_hash_file(t_hash *h, char *file, u_int8_t flags)
{
	u_int8_t	*digest;
	u_int8_t	buf[512];
	int			fd;
	u_int32_t	r;

	digest = malloc(h->digest_size);
	if (!digest)
	{
		printf("Error: malloc failed\n");
		return ;
	}
	fd = open(file, O_RDONLY);
	if (fd < 0)
	{
		printf("Error: open file (%s)\n", file);
		free(digest);
		return ;
	}
	h->init();
	while ((r = read(fd, buf, 512)) > 0)
		h->update(buf, r);
	h->final(digest);
	close(fd);

	if (flags & 0x2)
		PRINT_HEX(digest, h->digest_size)
	else if (flags & 0x4) {
		PRINT_HEX(digest, h->digest_size)
		printf(" \"%s\"", file);
	} else {
		printf("%s (\"%s\") = ", h->name, file);
		PRINT_HEX(digest, h->digest_size)
	}
	printf("\n");
	free(digest);
}

void	ft_hash_str(t_hash *h, char *s, u_int8_t flags)
{
	u_int8_t	*digest;

	digest = malloc(h->digest_size);
	if (!digest)
	{
		printf("Error: malloc failed\n");
		return ;
	}
	h->init();
	h->update((u_int8_t *)s, ft_strlen(s));
	h->final(digest);

	if (flags & 0x2)
		PRINT_HEX(digest, h->digest_size)
	else if (flags & 0x4) {
		PRINT_HEX(digest, h->digest_size)
		printf(" \"%s\"", s);
	} else {
		printf("%s (\"%s\") = ", h->name, s);
		PRINT_HEX(digest, h->digest_size)
	}
	printf("\n");
	free(digest);
}

int	ft_hash(t_algo *algo, int argc, char **argv)
{
	t_hash		*hash;
	int			i;
	u_int8_t	flags;
	char		*str;

	hash = (t_hash *)algo;
	flags = 0;
	str = NULL;
	i = -1;
	while (++i < argc)
	{
		if (!ft_strncmp(argv[i], "-p", 3))
		{
			flags |= 0x1;
			ft_hash_stdin(hash, 1);
		}
		else if (!ft_strncmp(argv[i], "-q", 3))
			flags |= 0x2;
		else if (!ft_strncmp(argv[i], "-r", 3))
			flags |= 0x4;
		else if (!ft_strncmp(argv[i], "-s", 3))
		{
			flags |= 0x8;
			if (argv[i + 1])
				str = argv[++i];
			else
				return (printf("Error: '-s' option requires a parameter\n"));
			ft_hash_str(hash, str, flags);
		}
		else
		{
			flags |= 0x8;
			ft_hash_file(hash, argv[i], flags);
		}
	}

	if (!(flags & 0x8 || flags & 0x1) || (flags & 0x6 && !(flags & 0x8)))
		ft_hash_stdin(hash, 0);
	return (0);
}
