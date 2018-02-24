/*
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


#include "gophernicus.h"
#include "openssl/ssl.h"
#include "openssl/bio.h"
#include "openssl/err.h"
//#include "ssl.c"

/*
 * Print gopher menu line
 */
void info(state *st, char *str, char type)
{
	char outstr[BUFSIZE];
	char selector[16];

	/* Convert string to output charset */
	if (st->opt_iconv) sstrniconv(st->out_charset, outstr, str);
	else sstrlcpy(outstr, str);

	/* Handle gopher title resources */
	strclear(selector);
	if (type == TYPE_TITLE) {
		sstrlcpy(selector, "TITLE");
		type = TYPE_INFO;
	}

	/* Output info line */
	strcut(outstr, st->out_width);
	snprintf(sockbuf, BUFSIZE, "%c%s\t%s\t%s" CRLF,
		type, outstr, selector, DUMMY_HOST);
	((st->write)) (&(st->ss), sockbuf, strlen(sockbuf));
}


/*
 * Print footer
 */
void footer(state *st)
{
	char line[BUFSIZE];
	char buf[BUFSIZE];
	char msg[BUFSIZE];

	if (!st->opt_footer) {
#ifndef ENABLE_STRICT_RFC1436
		if (st->req_filetype == TYPE_MENU || st->req_filetype == TYPE_QUERY) {
#else
		if (1) {
#endif
			snprintf(sockbuf, BUFSIZE, "." CRLF);
			((st->write)) (&(st->ss), sockbuf, strlen(sockbuf));
		}
		return;
	}

	/* Create horizontal line */
	strrepeat(line, '_', st->out_width);

	/* Create right-aligned footer message */
	snprintf(buf, BUFSIZE, FOOTER_FORMAT, st->server_platform);
	((st->write)) (&(st->ss), sockbuf, strlen(sockbuf));
	snprintf(msg, sizeof(msg), "%*s", st->out_width - 1, buf);

	/* Menu footer? */
	if (st->req_filetype == TYPE_MENU || st->req_filetype == TYPE_QUERY) {
		info(st, line, TYPE_INFO);
		info(st, msg, TYPE_INFO);
		snprintf(sockbuf, BUFSIZE, "." CRLF);
		((st->write)) (&(st->ss), sockbuf, strlen(sockbuf));
	}

	/* Plain text footer */
	else {
		snprintf(sockbuf, BUFSIZE, "%s" CRLF, line);
		((st->write)) (&(st->ss), sockbuf, strlen(sockbuf));
		snprintf(sockbuf, BUFSIZE, "%s" CRLF, msg);
		((st->write)) (&(st->ss), sockbuf, strlen(sockbuf));
#ifdef ENABLE_STRICT_RFC1436
		snprintf(sockbuf, BUFSIZE, "." CRLF);
		((st->write)) (&(st->ss), sockbuf, strlen(sockbuf));
#endif
	}
}


/*
 * Print error message & exit
 */
void die(state *st, char *message, char *description)
{
	char buf[BUFSIZE];
	int en = errno;
	static const char error_gif[] = ERROR_GIF;

	/* Handle NULL description */
	if (description == NULL) description = strerror(en);

	/* Log the error */
	if (st->opt_syslog) {
		syslog(LOG_ERR, "error \"%s\" for request \"%s\" from %s",
			description, st->req_selector, st->req_remote_addr);
	}
	log_combined(st, HTTP_404);

	/* Handle menu errors */
	if (st->req_filetype == TYPE_MENU || st->req_filetype == TYPE_QUERY) {
		snprintf(sockbuf, BUFSIZE, "3" ERROR_PREFIX "%s\tTITLE\t" DUMMY_HOST CRLF, message);
		((st->write)) (&(st->ss), sockbuf, strlen(sockbuf));
		footer(st);
	}

	/* Handle image errors */
	else if (st->req_filetype == TYPE_GIF || st->req_filetype == TYPE_IMAGE) {
		((st->write)) (&(st->ss), error_gif, sizeof(error_gif));
	}

	/* Handle HTML errors */
	else if (st->req_filetype == TYPE_HTML) {
		snprintf(buf, BUFSIZE, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n"
			"<HTML>\n<HEAD>\n"
			"  <META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html;charset=iso-8859-1\">\n"
			"  <TITLE>" ERROR_PREFIX "%1$s</TITLE>\n"
			"</HEAD>\n<BODY>\n"
			"<STRONG>" ERROR_PREFIX "%1$s</STRONG>\n"
			"<PRE>\n", message);
		((st->write)) (&(st->ss), sockbuf, strlen(sockbuf));
		footer(st);
		snprintf(buf, BUFSIZE, "</PRE>\n</BODY>\n</HTML>\n");
	}

	/* Use plain text error for other filetypes */
	else {
		snprintf(sockbuf, BUFSIZE, ERROR_PREFIX "%s" CRLF, message);
		((st->write)) (&(st->ss), sockbuf, strlen(sockbuf));
		footer(st);
	}

	/* Quit */
	exit(EXIT_FAILURE);
}


/*
 * Apache-compatible combined logging
 */
void log_combined(state *st, int status)
{
	FILE *fp;
	struct tm *ltime;
	char timestr[64];
	time_t now;

	/* Try to open the logfile for appending */
	if (!*st->log_file) return;
	if ((fp = fopen(st->log_file , "a")) == NULL) return;

	/* Format time */
	now = time(NULL);
	ltime = localtime(&now);
	strftime(timestr, sizeof(timestr), HTTP_DATE, ltime);

	/* Generate log entry */
	fprintf(fp, "%s %s:%i - [%s] \"GET %c%s HTTP/1.0\" %i %li \"%s\" \"" HTTP_USERAGENT "\"\n",
		st->req_remote_addr, 
		st->server_host,
		st->server_port,
		timestr,
		st->req_filetype,
		st->req_selector,
		status,
		(long) st->req_filesize,
		st->req_referrer);
	fclose(fp);
}


/*
 * Convert gopher selector to an absolute path
 */
void selector_to_path(state *st)
{
	DIR *dp;
	struct dirent *dir;
	struct stat file;
#ifdef HAVE_PASSWD
	struct passwd *pwd;
	char *path = EMPTY;
	char *c;
#endif
	char buf[BUFSIZE];
	int i;

	/* Handle selector rewriting */
	for (i = 0; i < st->rewrite_count; i++) {

		/* Match found? */
		if (strstr(st->req_selector, st->rewrite[i].match) == st->req_selector) {

			/* Replace match with a new string */
			snprintf(buf, BUFSIZE, "%s%s",
				st->rewrite[i].replace,
				st->req_selector + strlen(st->rewrite[i].match));

			if (st->debug) {
				syslog(LOG_INFO, "rewriting selector \"%s\" -> \"%s\"",
					st->req_selector, buf);
			}

			sstrlcpy(st->req_selector, buf);
		}
	}

#ifdef HAVE_PASSWD
	/* Virtual userdir (~user -> /home/user/public_gopher)? */
	if ((st->user_dir) && sstrncmp(st->req_selector, "/~") == MATCH) {

		/* Parse userdir login name & path */;
		sstrlcpy(buf, st->req_selector + 2);
		if ((c = strchr(buf, '/'))) {
			*c = '\0';
			path = c + 1;
		}

		/* Check user validity */
		if ((pwd = getpwnam(buf)) == NULL)
			die(st, ERR_NOTFOUND, "User not found");
		if (pwd->pw_uid < PASSWD_MIN_UID)
			die(st, ERR_NOTFOUND, "User found but UID too low");

		/* Generate absolute path to users own gopher root */
		snprintf(st->req_realpath, sizeof(st->req_realpath),
			"%s/%s/%s", pwd->pw_dir, st->user_dir, path);

		/* Check ~public_gopher access rights */
		if (stat(st->req_realpath, &file) == ERROR)
			die(st, ERR_NOTFOUND, NULL);
		if ((file.st_mode & S_IROTH) == 0)
			die(st, ERR_ACCESS, "~/public_gopher not world-readable");
		if (file.st_uid != pwd->pw_uid)
			die(st, ERR_ACCESS, "~/ and ~/public_gopher owned by different users");

		/* Userdirs always come from the default vhost */
		if (st->opt_vhost)
			sstrlcpy(st->server_host, st->server_host_default);
		return;
	}
#endif

	/* Virtual hosting */
	if (st->opt_vhost) {

		/* Try looking for the selector from the current vhost */
		snprintf(st->req_realpath, sizeof(st->req_realpath), "%s/%s%s",
			st->server_root, st->server_host, st->req_selector);
		if (stat(st->req_realpath, &file) == OK) return;

		/* Loop through all vhosts looking for the selector */
		if ((dp = opendir(st->server_root)) == NULL) die(st, ERR_NOTFOUND, NULL);
		while ((dir = readdir(dp))) {

			/* Skip .hidden dirs and . & .. */
			if (dir->d_name[0] == '.') continue;

			/* Special case - skip lost+found (don't ask) */
			if (sstrncmp(dir->d_name, "lost+found") == MATCH) continue;

			/* Generate path to the found vhost */
			snprintf(st->req_realpath, sizeof(st->req_realpath), "%s/%s%s",
				st->server_root, dir->d_name, st->req_selector);

			/* Did we find the selector under this vhost? */
			if (stat(st->req_realpath, &file) == OK) {

				/* Virtual host found - update state & return */
				sstrlcpy(st->server_host, dir->d_name);
				return;
			}
		}
		closedir(dp);
	}

	/* Handle normal selectors */
	snprintf(st->req_realpath, sizeof(st->req_realpath),
		"%s%s", st->server_root, st->req_selector);
}


/*
 * Get local IP address
 */
char *get_local_address(void)
{
#ifdef HAVE_IPv4
	struct sockaddr_in addr;
	socklen_t addrsize = sizeof(addr);
#endif
#ifdef HAVE_IPv6
	struct sockaddr_in6 addr6;
	socklen_t addr6size = sizeof(addr6);
	static char address[INET6_ADDRSTRLEN];
#endif
	char *c;

	/* Try IPv4 first */
#ifdef HAVE_IPv4
	if (getsockname(0, (struct sockaddr *) &addr, &addrsize) == OK) {
		c = inet_ntoa(addr.sin_addr);
		if (strlen(c) > 0 && *c != '0') return c;
	}
#endif

	/* IPv4 didn't work - try IPv6 */
#ifdef HAVE_IPv6
	if (getsockname(0, (struct sockaddr *) &addr6, &addr6size) == OK) {
		if (inet_ntop(AF_INET6, &addr6.sin6_addr, address, sizeof(address))) {

			/* Strip ::ffff: IPv4-in-IPv6 prefix */
			if (sstrncmp(address, "::ffff:") == MATCH) return (address + 7);
			else return address;
		}
	}
#endif

	/* Nothing works... I'm out of ideas */
	return DEFAULT_ADDR;
}


/*
 * Get remote peer IP address
 */
char *get_peer_address(void)
{
#ifdef HAVE_IPv4
	struct sockaddr_in addr;
	socklen_t addrsize = sizeof(addr);
#endif
#ifdef HAVE_IPv6
	struct sockaddr_in6 addr6;
	socklen_t addr6size = sizeof(addr6);
	static char address[INET6_ADDRSTRLEN];
#endif
	char *c;

	/* Are we a CGI script? */
	if ((c = getenv("REMOTE_ADDR"))) return c;
	// Are we a stunnel thing? It's likely, since our own SSL isn't great
	if ((c = getenv("REMOTE_HOST"))) return c;

	/* Try IPv4 first */
#ifdef HAVE_IPv4
	if (getpeername(0, (struct sockaddr *) &addr, &addrsize) == OK) {
		c = inet_ntoa(addr.sin_addr);
		if (strlen(c) > 0 && *c != '0') return c;
	}
#endif

	/* IPv4 didn't work - try IPv6 */
#ifdef HAVE_IPv6
	if (getpeername(0, (struct sockaddr *) &addr6, &addr6size) == OK) {
		if (inet_ntop(AF_INET6, &addr6.sin6_addr, address, sizeof(address))) {

			/* Strip ::ffff: IPv4-in-IPv6 prefix */
			if (sstrncmp(address, "::ffff:") == MATCH) return (address + 7);
			else return address;
		}
	}
#endif

	/* Nothing works... I'm out of ideas */
	return DEFAULT_ADDR;
}


/*
 * Initialize state struct to default/empty values
 */
void init_state(state *st)
{
	static const char *filetypes[] = { FILETYPES };
	char buf[BUFSIZE];
	char *c;
	int i;

	/* Request */
	strclear(st->req_selector);
	strclear(st->req_realpath);
	strclear(st->req_query_string);
	strclear(st->req_referrer);
	sstrlcpy(st->req_local_addr, get_local_address());
	sstrlcpy(st->req_remote_addr, get_peer_address());
	/* strclear(st->req_remote_host); */
	st->req_filetype = DEFAULT_TYPE;
	st->req_protocol = PROTO_GOPHER;
	st->req_filesize = 0;

	/* Output */
	st->out_width = DEFAULT_WIDTH;
	st->out_charset = DEFAULT_CHARSET;
	st->out_protection = FALSE;

	/* Settings */
	sstrlcpy(st->server_root, DEFAULT_ROOT);
	sstrlcpy(st->server_host_default, DEFAULT_HOST);

	if ((c = getenv("HOSTNAME")))
		sstrlcpy(st->server_host, c);
	else if ((gethostname(buf, BUFSIZE)) != ERROR)
		sstrlcpy(st->server_host, buf);

	st->server_port = DEFAULT_PORT;

	st->default_filetype = DEFAULT_TYPE;
	sstrlcpy(st->map_file, DEFAULT_MAP);
	sstrlcpy(st->tag_file, DEFAULT_TAG);
	sstrlcpy(st->hdr_ext, DEFAULT_HDR_EXT);
	sstrlcpy(st->tag_ext, DEFAULT_TAG_EXT);
	sstrlcpy(st->ftr_ext, DEFAULT_FTR_EXT);
	sstrlcpy(st->protection_certkeyfile, DEFAULT_SSL_CKF);
	sstrlcpy(st->cgi_file, DEFAULT_CGI);
	sstrlcpy(st->user_dir, DEFAULT_USERDIR);
	strclear(st->log_file);

	st->hidden_count = 0;
	st->filetype_count = 0;
	strclear(st->filter_dir);
	st->rewrite_count = 0;

	strclear(st->server_description);
	strclear(st->server_location);
	strclear(st->server_platform);
	strclear(st->server_admin);

	/* Session */
	st->session_timeout = DEFAULT_SESSION_TIMEOUT;
	st->session_max_kbytes = DEFAULT_SESSION_MAX_KBYTES;
	st->session_max_hits = DEFAULT_SESSION_MAX_HITS;

	/* Feature options */
	st->opt_vhost = TRUE;
	st->opt_parent = TRUE;
	st->opt_header = TRUE;
	st->opt_footer = TRUE;
	st->opt_date = TRUE;
	st->opt_syslog = TRUE;
	st->opt_magic = TRUE;
	st->opt_iconv = TRUE;
	st->opt_query = TRUE;
	st->opt_caps = TRUE;
	st->opt_shm = TRUE;
	st->opt_root = TRUE;
	st->debug = FALSE;

	/* Load default suffix -> filetype mappings */
	for (i = 0; filetypes[i]; i += 2) {
		if (st->filetype_count < MAX_FILETYPES) {
			sstrlcpy(st->filetype[st->filetype_count].suffix, filetypes[i]);
			st->filetype[st->filetype_count].type = *filetypes[i + 1];
			st->filetype_count++;
		}
	}
}


/*
 * Main
 */
int main(int argc, char *argv[])
{
	struct stat file;
	state st;
	char self[64];
	char selector[BUFSIZE];
	char buf[BUFSIZE];
	char *dest;
	char *c;
#ifdef HAVE_SHMEM
	struct shmid_ds shm_ds;
	shm_state *shm;
	int shmid;
#endif
	FILE *fp;
	char osslerr[BUFSIZE];

	/* Get the name of this binary */
	if ((c = strrchr(argv[0], '/'))) sstrlcpy(self, c + 1);
	else sstrlcpy(self, argv[0]);

	/* Initialize state */
#ifdef HAVE_LOCALES
	setlocale(LC_TIME, DATE_LOCALE);
#endif
	init_state(&st);

	/* Handle command line arguments */
	parse_args(&st, argc, argv);

	if (st.out_protection && strlen(st.protection_certkeyfile) > 2) {
		char pathname[BUFSIZE];
		snprintf(pathname, sizeof(pathname), "%s",
                        st.protection_certkeyfile);
		if (stat(pathname, &file) == OK &&
			(file.st_mode & S_IFMT) != S_IFREG) {
			die(&st, ERR_ACCESS, "Unrecoverable SSL error: certificate and key bundle file not found or not regular");
		};
		st.ss.wfd = fileno(stdout);
		st.ss.rfd = fileno(stdin);
		st.ss.sslctx = (void *)SSL_CTX_new(SSLv23_server_method());
		SSL_CTX_set_options(st.ss.sslctx, SSL_OP_SINGLE_DH_USE);
		int use_cert, use_pkey, reterr;
		use_cert = SSL_CTX_use_certificate_chain_file((SSL_CTX*)(st.ss.sslctx), st.protection_certkeyfile);
		use_pkey = SSL_CTX_use_PrivateKey_file((SSL_CTX*)(st.ss.sslctx), st.protection_certkeyfile, SSL_FILETYPE_PEM);
		st.ss.sslh = (void *)SSL_new(st.ss.sslctx);
		SSL_set_wfd((SSL*)st.ss.sslh, fileno(stdout));
		SSL_set_rfd((SSL*)st.ss.sslh, fileno(stdin));
		SSL_load_error_strings();
		while ((reterr = SSL_do_handshake((SSL*)st.ss.sslh)) <= 0) {
			int errcode = ERR_get_error();
			ERR_error_string_n(errcode, osslerr, 1024);
			switch (SSL_get_error((SSL*)st.ss.sslh, reterr)) {
				case SSL_ERROR_ZERO_RETURN:
				snprintf(buf, BUFSIZE, "Unrecoverable SSL error post accept: zero return");
				break;
				case SSL_ERROR_WANT_READ:
				case SSL_ERROR_WANT_WRITE:
				case SSL_ERROR_WANT_CONNECT:
				case SSL_ERROR_WANT_ACCEPT:
				case SSL_ERROR_WANT_X509_LOOKUP:
				goto continuation;
				break;
				case SSL_ERROR_SYSCALL:
				snprintf(buf, BUFSIZE, "Unrecoverable SSL error post accept: syscall error %s", strerror(errno));
				break;
				case SSL_ERROR_SSL:
				snprintf(buf, BUFSIZE, "Unrecoverable SSL error post accept: SSL protocol error. And, %s.", errcode == 0 ? "No SSL error." : osslerr);
				break;
			}
  goto notused;

  continuation:

  continue;

  notused:
			syslog(LOG_ERR, "%s", buf);
	/* Try to open the logfile for appending */
			if (st.log_file) {
				if ((fp = fopen(st.log_file , "a")) == NULL) exit(0);

				SSL_load_error_strings();
				/* Generate log entry */
				ERR_print_errors_fp(fp);
				fclose(fp);
			}
			exit(0);
		}
		st.read = &ssl_read;
		st.write = &ssl_write;
		st.fgets = &ssl_fgets;
	} else {
		st.ss.wfd = 1;
		st.ss.rfd = 0;
		st.read = &plain_read;
		st.write = &plain_write;
		st.fgets = &plain_fgets;
	}

	/* Open syslog() */
	if (st.opt_syslog) openlog(self, LOG_PID, LOG_DAEMON);

	/* Make sure the computer is turned on -- joke function in
	   BeOS */
#ifdef __HAIKU__
	if (is_computer_on() != TRUE)
		die(&st, ERR_ACCESS, "Please turn on the computer first");
#endif

	/* Refuse to run as root */
#ifdef HAVE_PASSWD
	if (st.opt_root && getuid() == 0)
		die(&st, ERR_ACCESS, "Refusing to run as root");
#endif

	/* Try to get shared memory */
#ifdef HAVE_SHMEM
	if ((shmid = shmget(SHM_KEY, sizeof(shm_state), IPC_CREAT | SHM_MODE)) == ERROR) {

		/* Getting memory failed -> delete the old allocation */
		shmctl(shmid, IPC_RMID, &shm_ds);
		shm = NULL;
	}
	else {
		/* Map shared memory */
		if ((shm = (shm_state *) shmat(shmid, (void *) 0, 0)) == (void *) ERROR)
			shm = NULL;

		/* Initialize mapped shared memory */
		if (shm && shm->start_time == 0) {
			shm->start_time = time(NULL);

			/* Keep server platform & description in shm */
			platform(&st);
			sstrlcpy(shm->server_platform, st.server_platform);
			sstrlcpy(shm->server_description, st.server_description);
		}
	}

	/* For debugging shared memory issues */
	if (!st.opt_shm) shm = NULL;

	/* Get server platform and description */
	if (shm) {
		sstrlcpy(st.server_platform, shm->server_platform);

		if (!*st.server_description)
			sstrlcpy(st.server_description, shm->server_description);
	}
	else
#endif
		platform(&st);

	/* Read selector */
	if ((st.fgets)(selector, sizeof(selector) - 1, &st.ss) == NULL)
		selector[0] = '\0';

	/* Remove trailing CRLF */
	chomp(selector);

	if (st.debug) syslog(LOG_INFO, "client sent us \"%s\"", selector);

	/* Handle hURL: redirect page */
	if (sstrncmp(selector, "URL:") == MATCH) {
		st.req_filetype = TYPE_HTML;
		sstrlcpy(st.req_selector, selector);
		url_redirect(&st);
		return OK;
	}

	/* Handle gopher+ root requests (UMN gopher client is seriously borken) */
	if (sstrncmp(selector, "\t$") == MATCH) {
		snprintf(sockbuf, BUFSIZE, "+-1" CRLF);
		((st.write)) ((void*)&st.ss, sockbuf, strlen(sockbuf));
		snprintf(sockbuf, BUFSIZE, "+INFO: 1Main menu\t\t%s\t%i" CRLF,
			st.server_host,
			st.server_port);
		((st.write)) ((void*)&st.ss, sockbuf, strlen(sockbuf));
		snprintf(sockbuf, BUFSIZE, "+VIEWS:" CRLF " application/gopher+-menu: <512b>" CRLF);
		((st.write)) ((void*)&st.ss, sockbuf, strlen(sockbuf));
		snprintf(sockbuf, BUFSIZE, "." CRLF);
		((st.write)) ((void*)&st.ss, sockbuf, strlen(sockbuf));

		if (st.debug) syslog(LOG_INFO, "got a request for gopher+ root menu");
		return OK;
	}

	/* Convert HTTP request to gopher (respond using headerless HTTP/0.9) */
	if (sstrncmp(selector, "GET ") == MATCH ||
	    sstrncmp(selector, "POST ") == MATCH ) {

		if ((c = strchr(selector, ' '))) sstrlcpy(selector, c + 1);
		if ((c = strchr(selector, ' '))) *c = '\0';

		st.req_protocol = PROTO_HTTP;

		if (st.debug) syslog(LOG_INFO, "got HTTP request for \"%s\"", selector);
	}

	/* Save default server_host & fetch session data (including new server_host) */
	sstrlcpy(st.server_host_default, st.server_host);
#ifdef HAVE_SHMEM
	if (shm) get_shm_session(&st, shm);
#endif

	/* Loop through the selector, fix it & separate query_string */
	dest = st.req_selector;
	if (selector[0] != '/') *dest++ = '/';

	for (c = selector; *c;) {

		/* Skip duplicate slashes and /./ */
		while (*c == '/' && *(c + 1) == '/') c++;
		if (*c == '/' && *(c + 1) == '.' && *(c + 2) == '/') c += 2;

		/* Start of a query string (either type 7 or HTTP-style)? */
		if (*c == '\t' || (st.opt_query && *c == '?')) {
			sstrlcpy(st.req_query_string, c + 1);
			if ((c = strchr(st.req_query_string, '\t'))) *c = '\0';
			break;
		}

		/* Start of virtual host hint? */
		if (*c == ';') {
			if (st.opt_vhost) sstrlcpy(st.server_host, c + 1);

			/* Skip vhost on selector */
			while (*c && *c != '\t') c++;
			continue;
		}

		/* Copy valid char */
		*dest++ = *c++;
	}
	*dest = '\0';

	/* Remove encodings from selector */
	strndecode(st.req_selector, st.req_selector, sizeof(st.req_selector));

	/* Deny requests for Slashdot and /../ hackers */
	if (strstr(st.req_selector, "/."))
		die(&st, ERR_ACCESS, "Refusing to serve out dotfiles");

	/* Handle /server-status requests */
#ifdef HAVE_SHMEM
	if (sstrncmp(st.req_selector, SERVER_STATUS) == MATCH) {
		if (shm) server_status(&st, shm, shmid);
		return OK;
	}
#endif

	/* Remove possible extra cruft from server_host */
	if ((c = strchr(st.server_host, '\t'))) *c = '\0';

	/* Guess request filetype so we can die() with style... */
	st.req_filetype = gopher_filetype(&st, st.req_selector, FALSE);

	/* Convert seletor to path & stat() */
	selector_to_path(&st);
	if (st.debug) syslog(LOG_INFO, "path to resource is \"%s\"", st.req_realpath);

	if (stat(st.req_realpath, &file) == ERROR) {

		/* Handle virtual /caps.txt requests */
		if (st.opt_caps && sstrncmp(st.req_selector, CAPS_TXT) == MATCH) {
#ifdef HAVE_SHMEM
			caps_txt(&st, shm);
#else
			caps_txt(&st, NULL);
#endif
			return OK;
		}

		/* Requested file not found - die() */
		die(&st, ERR_NOTFOUND, NULL);
	}

	/* Fetch request filesize from stat() */
	st.req_filesize = file.st_size;

	/* Everyone must have read access but no write access */
	if ((file.st_mode & S_IROTH) == 0)
		die(&st, ERR_ACCESS, "File or directory not world-readable");
	if ((file.st_mode & S_IWOTH) != 0)
		die(&st, ERR_ACCESS, "File or directory world-writeable");

	/* If stat said it was a dir then it's a menu */
	if ((file.st_mode & S_IFMT) == S_IFDIR) st.req_filetype = TYPE_MENU;

	/* Not a dir - let's guess the filetype again... */
	else if ((file.st_mode & S_IFMT) == S_IFREG)
		st.req_filetype = gopher_filetype(&st, st.req_realpath, st.opt_magic);

	/* Menu selectors must end with a slash */
	if (st.req_filetype == TYPE_MENU && strlast(st.req_selector) != '/')
		sstrlcat(st.req_selector, "/");

	/* Change directory to wherever the resource was */
	sstrlcpy(buf, st.req_realpath);

	if ((file.st_mode & S_IFMT) != S_IFDIR) c = dirname(buf);
	else c = buf;

	if (chdir(c) == ERROR) die(&st, ERR_ACCESS, NULL);

	/* Keep count of hits and data transfer */
#ifdef HAVE_SHMEM
	if (shm) {
		shm->hits++;
		shm->kbytes += st.req_filesize / 1024;

		/* Update user session */
		update_shm_session(&st, shm);
	}
#endif

	/* Log the request */
	if (st.opt_syslog) {
		syslog(LOG_INFO, "request for \"gopher://%s:%i/%c%s\" from %s",
			st.server_host,
			st.server_port,
			st.req_filetype,
			st.req_selector,
			st.req_remote_addr);
	}

	/* Check file type & act accordingly */
	switch (file.st_mode & S_IFMT) {
		case S_IFDIR:
			log_combined(&st, HTTP_OK);
			gopher_menu(&st);
			break;

		case S_IFREG:
			log_combined(&st, HTTP_OK);
			gopher_file(&st);
			break;

		default:
			die(&st, ERR_ACCESS, "Refusing to serve out special files");
	}

	/* Clean exit */
	return OK;
}

