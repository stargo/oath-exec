/*
 * Copyright (c) 2018 Michael Gernoth <michael@gernoth.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <liboath/oath.h>

typedef enum oath_types {
	OATH_TYPE_TOTP = 1,
	OATH_TYPE_HOTP,
} oath_type;

typedef struct oath_config {
	oath_type type;
	char *secret;
	size_t secret_length;
	int digits;
} oath_config;

int read_config(char *filename, oath_config *config)
{
	char filebuf[1024] = { 0 };
	int pos = 0;
	int fd;
	int ret = 0;
	int r;
	int i;
	int comment = 0;

	if ((fd = open(filename, O_RDONLY)) == -1) {
		perror("Can't open config");
		goto out1;
	}

	config->digits = 6;
	do {
		int found = 0;

		r = read(fd, filebuf + pos, sizeof(filebuf) - (pos + 1));
		if (r < 0) {
			perror("Error while reading config");
			goto out2;
		} else if (r == 0) {
			filebuf[pos] = '\n';
		}

		pos += r;

		do {
			char *value = NULL;

			found = 0;
			for (i = 0; i < pos; i++) {
				if (comment && filebuf[i] != '\n') {
					continue;
				}

				if (filebuf[i] == ' ' || filebuf[i] == '\t' || filebuf[i] == '\r') {
					if (value == NULL) {
						filebuf[i] = '\0';
					}
					if (filebuf + i == value) {
						value++;
					}
				} else if (filebuf[i] == '=' && value == NULL) {
					filebuf[i] = '\0';
					value = filebuf + i + 1;
				} else if (filebuf[i] == '#' || filebuf[i] == '\n') {
					if (filebuf[i] == '#') {
						comment = 1;
					} else if (comment) {
						comment = 0;
					}
					filebuf[i] = '\0';

					if (value) {
						if (!strcasecmp(filebuf, "type")) {
							if (!strcasecmp(value, "TOTP")) {
								config->type = OATH_TYPE_TOTP;
							} else {
								fprintf(stderr, "Unsupported OTP type %s\n", value);
								goto out2;
							}
						} else if (!strcasecmp(filebuf, "secret")) {
							int err;
							if ((err = oath_base32_decode(value, strlen(value), &(config->secret), &(config->secret_length))) != OATH_OK) {
								fprintf(stderr, "Can't base32 decode secret: %s\n", oath_strerror(err));
								goto out2;
							}
						} else if (!strcasecmp(filebuf, "digits")) {
							char *endptr;
							errno = 0;
							config->digits = strtoul(value, &endptr, 10);
							if (errno != 0 || endptr  == NULL || *endptr != '\0') {
								fprintf(stderr, "Can't parse '%s' as number\n", value);
								goto out2;
							}
						} else {
							fprintf(stderr, "Unknown config item %s\n", filebuf);
							goto out2;
						}
					}

					value = NULL;
					memmove(filebuf, filebuf + i + 1, pos - (i + 1));
					pos -= i + 1;
					found = 1;
					break;
				}
			}
		} while (found);
	} while (r > 0);

	if (config->secret == NULL || config->secret_length == 0) {
		fprintf(stderr, "No secret defined in config!\n");
		goto out2;
	}

	ret = 1;

out2:
	close(fd);
out1:
	return ret;
}

int generate_random_b32(int len)
{
	char buf[1024] = { 0 };
	char *b32 = NULL;
	size_t b32len;
	int fd;
	int pos = 0;
	int ret = EXIT_FAILURE;
	int err;
	int r;

	if (len > sizeof(buf)) {
		fprintf(stderr, "Maximum length (%zd) exceeded!\n", sizeof(buf));
		goto out1;
	}

	if ((fd = open("/dev/random", O_RDONLY)) == -1) {
		perror("Can't open /dev/random");
		goto out1;
	}

	do {
		r = read(fd, buf + pos, len - pos);
		if (r < 0) {
			perror("Can't read random");
			goto out1;
		} else if (r == 0) {
			fprintf(stderr, "EOF reached on /dev/random?!\n");
			goto out1;
		}

		pos += r;
	} while(pos < len);

	if ((err = oath_base32_encode(buf, len, &b32, &b32len)) != OATH_OK) {
		fprintf(stderr, "Can't base32 encode secret: %s\n", oath_strerror(err));
		goto out1;
	}

	printf("%s\n", b32);

	ret = EXIT_SUCCESS;

out1:
	close(fd);
	return ret;
}

void syntax(char *progname)
{
	fprintf(stderr, "%s -c /path/to/config -- /path/to/executable [args...]\n", progname);
	fprintf(stderr, "%s -g bytes\n", progname);
}

int main(int argc, char **argv)
{
	oath_config config = { 0 };
	char *configfile = NULL;
	int genlength = 0;
	char otp[1024] = { 0 };
	char *endptr;
	int valid;
	int err;
	int opt;
	int r;
	int i;

	if ((err = oath_init()) != OATH_OK) {
		fprintf(stderr, "Can't initialize OATH library: %s\n", oath_strerror(err));
		exit(EXIT_FAILURE);
	}

	while((opt = getopt(argc, argv, "c:g:")) != -1) {
		switch(opt) {
			case 'c':
				configfile = optarg;
				break;
			case 'g':
				errno = 0;
				genlength = strtoul(optarg, &endptr, 10);
				if (errno != 0 || endptr == NULL || *endptr != '\0') {
					syntax(argv[0]);
					oath_done();
					exit(EXIT_FAILURE);
				}
				exit(generate_random_b32(genlength));
				break;
			default:
				syntax(argv[0]);
				oath_done();
				exit(EXIT_FAILURE);
				break;
		}
	}

	if (configfile == NULL || optind == argc) {
		syntax(argv[0]);
		oath_done();
		exit(EXIT_FAILURE);
	}

	if (!read_config(configfile, &config)) {
		oath_done();
		exit(EXIT_FAILURE);
	}

	printf("%cOTP: ", ((config.type == OATH_TYPE_TOTP)?'T':'H'));
	fflush(stdout);

	r = read(STDIN_FILENO, otp, sizeof(otp)-1);
	if (r <= 0) {
		oath_done();
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < r; i++) {
		if (otp[i] == '\r' || otp[i] == '\n') {
			otp[i] = '\0';
			break;
		}
	}

	valid = OATH_INVALID_OTP;
	switch(config.type) {
		case OATH_TYPE_TOTP:
			valid = oath_totp_validate(config.secret, config.secret_length,
			                           time(NULL), 30, 0, 2, otp);
			break;
		default:
			break;
	}
	oath_done();

	memset(otp, 0, sizeof(otp));
	memset(config.secret, 0, config.secret_length);
	free(config.secret);

	if (valid >= 0 && (valid != OATH_INVALID_OTP)) {
		char **newargv = NULL;
		int i;

		newargv = malloc(sizeof(char*) * ((argc - optind) + 1));
		if (newargv == NULL) {
			perror("Can't allocate memory for argv");
			exit(EXIT_FAILURE);
		}
		memset(newargv, 0, sizeof(char*) * ((argc - optind) + 1));
		for(i = 0; i < argc - optind; i++) {
			newargv[i] = argv[optind + i];
		}

		execvp(newargv[0], newargv);
		perror("Can't execute");
	}

	return EXIT_FAILURE;
}
