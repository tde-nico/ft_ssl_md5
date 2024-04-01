#include "ft_ssl.h"
#include "md5.h"
#include "sha256.h"
#include "whirlpool.h"


t_cmd	g_cmds[] = {
	{"md5", &ft_hash, {{"MD5", &md5_init, &md5_update, &md5_final, MD5_DIGEST_SIZE}}},
	{"sha256", &ft_hash, {{"SHA256", &sha256_init, &sha256_update, &sha256_final, SHA256_DIGEST_SIZE}}},
	{"whirlpool", &ft_hash, {{"WHIRLPOOL", &whirlpool_init, &whirlpool_update, &whirlpool_final, WHIRLPOOL_DIGEST_SIZE}}},
	{NULL, NULL, {{NULL, NULL, NULL, NULL, 0}}},
};


int	usage(void)
{
	int	i;

	printf("possible commands:\n");
	i = 0;
	while (g_cmds[i].name)
	{
		printf("\t%s\n", g_cmds[i].name);
		i++;
	}
	return (1);
}

int	ft_ssl(int argc, char **argv)
{
	int	i;

	if (argv[0] == NULL || argv[0][0] == '\0')
		return (0);
	i = 0;
	while (g_cmds[i].name)
	{
		if (!ft_strncmp(g_cmds[i].name, argv[0], ft_strlen(g_cmds[i].name)+1))
			return (g_cmds[i].schedule(&(g_cmds[i].algo), --argc, &argv[1]));
		i++;
	}
	return (1);
}

int	go_interactive(void)
{
	int		argc;
	int		prompt_len;
	char	buf[BSIZE];
	char	*argv[BSIZE];
	int		blen;
	int		i;
	int		is_start_word;

	prompt_len = ft_strlen(PROMPT);
	while (1)
	{
		i = -1;
		is_start_word = 1;
		argc = 0;
		write(1, PROMPT, prompt_len);
		blen = read(0, buf, BSIZE);
		if (blen <= 0)
			break ;
		buf[blen - 1] = '\0';
		if (!ft_strncmp(buf, "exit", 4) || !ft_strncmp(buf, "q", 1))
			break ;
		while (++i < blen-1)
		{
			if (buf[i] == ' ')
			{
				buf[i] = '\0';
				is_start_word = 1;
			}
			else if (is_start_word)
			{
				argv[argc++] = &buf[i];
				is_start_word = 0;
			}
		}
		argv[argc] = NULL;
		if (ft_ssl(argc, argv))
			usage();
	}
	write(1, "\n", 1);
	return (0);
}



int	main(int argc, char **argv)
{
	if (argc < 2)
		return (go_interactive());

	if (ft_ssl(argc-1, &argv[1]))
		return (usage());

	return (0);
}
