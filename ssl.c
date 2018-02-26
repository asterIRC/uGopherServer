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
#include "openssl/err.h"
#include "openssl/bio.h"

int plain_read(void *sockst, char *buf, size_t count)
{
	memset(buf, 0, BUFSIZE);
	return read(((sockstate*)sockst)->rfd, buf, count);
};

char *plain_fgets(char *buf, size_t count, void *sockst)
{
	memset(buf, 0, BUFSIZE);
	return fgets(buf, count, stdin);
};

int plain_write(void *sockst, char *buf, size_t count)
{
	int r = write(((sockstate*)sockst)->wfd, buf, count);
	memset(buf, 0, BUFSIZE);
	return r;
};

int ssl_read(void *sockst, char *buf, size_t count)
{
	memset(buf, 0, BUFSIZE);
	sockstate *ss = (sockstate *)sockst;
	return (SSL_read((SSL*)(ss->sslh), buf, count));
};

int ssl_write(void *sockst, char *buf, size_t count)
{
	sockstate *ss = (sockstate *)sockst;
	int r;
	r = (SSL_write((SSL*)(ss->sslh), buf, count));
	memset(buf, 0, BUFSIZE);
	return r;
};

char *ssl_fgets (char *buf, size_t count, void *sockst)
{
	size_t donecount;
	char ourbuf[BUFSIZE];
	char *ours = ourbuf;
	char osslerr[BUFSIZE];
	sockstate *ss = (sockstate *)sockst;
	int i, j;

	for (i = 0; i < count && i < BUFSIZE; i++) {
		continuate:
		if ((j = SSL_read( (SSL*)(ss->sslh), ours, BUFSIZE - 1)) <= 0) {
			int errcode = ERR_get_error();
			ERR_error_string_n(errcode, osslerr, BUFSIZE - 1);
			switch (SSL_get_error((SSL*)(ss->sslh), j)) {
				case SSL_ERROR_ZERO_RETURN:
				syslog(LOG_ERR, "Unrecoverable SSL error in fgets: zero return");
				break;
				case SSL_ERROR_WANT_READ:
				case SSL_ERROR_WANT_WRITE:
				case SSL_ERROR_WANT_CONNECT:
				case SSL_ERROR_WANT_ACCEPT:
				case SSL_ERROR_WANT_X509_LOOKUP:
				goto continuate;
				break;
				case SSL_ERROR_SYSCALL:
				syslog(LOG_ERR, "Unrecoverable SSL error in fgets: syscall error %s, and here's the cruft in errcode and osslerr: %i, %s", strerror(errno), errcode, osslerr);
				break;
				case SSL_ERROR_SSL:
				syslog(LOG_ERR, "Unrecoverable SSL error in fgets: SSL protocol error. And, %s.", errcode == 0 ? "No SSL error." : osslerr);
				break;
			}
		} else {
			ours = ours + j;
			i = i + j - 1;
			if (ourbuf[i] == '\n') {
				break;
			}
		}
	}
	if (i+1 < BUFSIZE) ourbuf[i+1] = 0;
	else ourbuf[BUFSIZE-1] = 0;
	strlcpy(buf, ourbuf, i);
	return buf;
};
