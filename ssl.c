/*
 * Aster-Gophernicus - Modifications in this fork are Copyright 2018-
 * to Ellenor Malik gopher://gopher.umbrellix.net/ https://www.umbrellix.net
 * <ellenor@umbrellix.net>
 *
 * Gophernicus - Copyright (c) 2009-2014 Kim Holviala <kim@holviala.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * ssl.c - routines for handling socket translator engines
 */

#include "gophernicus.h"
#include "openssl/ssl.h"

int plain_read(void *sockst, char *buf, size_t count)
{
	int r = read(((sockstate*)sockst)->rfd, buf, count);
	memset(buf, 0, 1024);
	return r;
};

char *plain_fgets(char *buf, size_t count, void *sockst)
{
	return fgets(buf, count, stdin);
};

int plain_write(void *sockst, char *buf, size_t count)
{
	int r = write(((sockstate*)sockst)->wfd, buf, count);
	memset(buf, 0, 1024);
	return r;
};

int ssl_read(void *sockst, char *buf, size_t count)
{
	sockstate *ss = (sockstate *)sockst;
	return (SSL_read((SSL*)(ss->sslh), buf, count));
};

int ssl_write(void *sockst, char *buf, size_t count)
{
	sockstate *ss = (sockstate *)sockst;
	return (SSL_write((SSL*)(ss->sslh), buf, count));
	memset(buf, 0, 1024);
};

char *ssl_fgets (char *buf, size_t count, void *sockst)
{
	size_t donecount;
	char ourbuf[BUFSIZE];
	sockstate *ss = (sockstate *)sockst;
	int i, j;

	for (i = 0; i < count && i < BUFSIZE; i++) {
		if ((j = SSL_read( (SSL*)(ss->sslh), (&ourbuf + count), 1)) <= 0) {
			switch (SSL_get_error((SSL*)(ss->sslh), j)) {
				case SSL_ERROR_NONE:
					return NULL;
					break;
				case SSL_ERROR_ZERO_RETURN:
				case SSL_ERROR_SSL:
				case SSL_ERROR_SYSCALL:
					exit(0);
					break;
			}
		} else {
			if (ourbuf[i] == ' ') {
				ourbuf[i+1] = 0;
				strlcpy(buf, ourbuf, i);
				return buf;
			}
		}
	}
	if (i+1 < BUFSIZE) ourbuf[i+1] = 0;
	else ourbuf[BUFSIZE] = 0;
	strlcpy(buf, ourbuf, i);
	return buf;
};
