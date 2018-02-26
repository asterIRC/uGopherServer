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

#include "fcntl.h"
#include "signal.h"
#include "sys/wait.h"
#include "gophernicus.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

/*
 * Send a binary file to the client
 */
void send_binary_file(state *st)
{
	/* More compatible POSIX fread()/fwrite() version, now mandatory as SSL */
	FILE *fp;
	char buf[BUFSIZE];
	int bytes;

	if (st->debug) syslog(LOG_INFO, "outputting binary file \"%s\"", st->req_realpath);

	if ((fp = fopen(st->req_realpath , "r")) == NULL) return;
	while ((bytes = fread(buf, 1, sizeof(buf), fp)) > 0)
		(*st->write) (&(st->ss), buf, bytes);
	fclose(fp);
}


/*
 * Send a text file to the client
 */
void send_text_file(state *st)
{
	FILE *fp;
	char in[BUFSIZE];
	char out[BUFSIZE];
	int line;

	if (st->debug) syslog(LOG_INFO, "outputting text file \"%s\"", st->req_realpath);
	if ((fp = fopen(st->req_realpath , "r")) == NULL) return;

	/* Loop through the file line by line */
	line = 0;

	while (fgets(in, sizeof(in), fp)) {

		/* Covert to output charset & print */
		if (st->opt_iconv) sstrniconv(st->out_charset, out, in);
		else sstrlcpy(out, in);

		chomp(out);

#ifdef ENABLE_STRICT_RFC1436
		if (strcmp(out, ".") == MATCH) snprintf(sockbuf, BUFSIZE, ".." CRLF);
		else
#endif
		snprintf(sockbuf, BUFSIZE, "%s" CRLF, out);
		(*st->write) (&(st->ss), sockbuf, strlen(sockbuf));
		line++;
	}

#ifdef ENABLE_STRICT_RFC1436
	snprintf(sockbuf, BUFSIZE, "." CRLF);
#endif
	fclose(fp);
}


/*
 * Print hURL redirect page
 */
void url_redirect(state *st)
{
	char dest[BUFSIZE];
	char *c;

	/* Basic security checking */
	sstrlcpy(dest, st->req_selector + 4);

	// ellenor@umbrellix.net - add https
	if (sstrncmp(dest, "http://") != MATCH &&
	    sstrncmp(dest, "https://") != MATCH &&
	    sstrncmp(dest, "ftp://") != MATCH &&
	    sstrncmp(dest, "mailto:") != MATCH)
		die(st, ERR_ACCESS, "Refusing to HTTP redirect unsafe protocols");

	if ((c = strchr(dest, '"'))) *c = '\0';
	if ((c = strchr(dest, '?'))) *c = '\0';

	/* Log the redirect */
	if (st->opt_syslog) {
		syslog(LOG_INFO, "request for \"gopher://%s:%i/h%s\" from %s",
			st->server_host,
			st->server_port,
			st->req_selector,
			st->req_remote_addr);
	}
	log_combined(st, HTTP_OK);

	/* Output HTML */
	snprintf(sockbuf, BUFSIZE, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n"
		"<HTML>\n<HEAD>\n"
		"  <META HTTP-EQUIV=\"Refresh\" content=\"1;URL=%1$s\">\n"
		"  <META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html;charset=iso-8859-1\">\n"
		"  <TITLE>URL Redirect page</TITLE>\n"
		"</HEAD>\n<BODY>\n"
		"<STRONG>Redirecting to <A HREF=\"%1$s\">%1$s</A></STRONG>\n"
		"<PRE>\n", dest);
	(*st->write) (&(st->ss), sockbuf, strlen(sockbuf));

	footer(st);
	snprintf(sockbuf, BUFSIZE, "</PRE>\n</BODY>\n</HTML>\n");
	(*st->write) (&(st->ss), sockbuf, strlen(sockbuf));
}


/*
 * Handle /server-status
 */
#ifdef HAVE_SHMEM
void server_status(state *st, shm_state *shm, int shmid)
{
	struct shmid_ds shm_ds;
	time_t now;
	time_t uptime;
	int sessions;
	int i;

	/* Log the request */
	if (st->opt_syslog) {
		syslog(LOG_INFO, "request for \"gopher://%s:%i/0" SERVER_STATUS "\" from %s",
			st->server_host,
			st->server_port,
			st->req_remote_addr);
	}
	log_combined(st, HTTP_OK);

	/* Quit if shared memory isn't initialized yet */
	if (!shm) return;

	/* Update counters */
	shm->hits++;
	shm->kbytes += 1;

	/* Get server uptime */
	now = time(NULL);
	uptime = (now - shm->start_time) + 1;

	/* Get shared memory info */
	shmctl(shmid, IPC_STAT, &shm_ds);

	/* Print statistics */
	snprintf(sockbuf, BUFSIZE, "Total Accesses: %li" CRLF
		"Total kBytes: %li" CRLF
		"Uptime: %i" CRLF
		"ReqPerSec: %.3f" CRLF
		"BytesPerSec: %li" CRLF
		"BytesPerReq: %li" CRLF
		"BusyServers: %i" CRLF
		"IdleServers: 0" CRLF
		"CPULoad: %.2f" CRLF,
			shm->hits,
			shm->kbytes,
			(int) uptime,
			(float) shm->hits / (float) uptime,
			shm->kbytes * 1024 / (int) uptime,
			shm->kbytes * 1024 / (shm->hits + 1),
			(int) shm_ds.shm_nattch,
			loadavg());

	/* Print active sessions */
	sessions = 0;

	for (i = 0; i < SHM_SESSIONS; i++) {
		if ((now - shm->session[i].req_atime) < st->session_timeout) {
			sessions++;

			snprintf(sockbuf, BUFSIZE, "Session: %-4i %-40s %-4li %-7li gopher://%s:%i/%c%s" CRLF,
				(int) (now - shm->session[i].req_atime),
				shm->session[i].req_remote_addr,
				shm->session[i].hits,
				shm->session[i].kbytes,
				shm->session[i].server_host,
				shm->session[i].server_port,
				shm->session[i].req_filetype,
				shm->session[i].req_selector);
		}
	}

	snprintf(sockbuf, BUFSIZE, "Total Sessions: %i" CRLF, sessions);
	(*st->write) (&(st->ss), sockbuf, strlen(sockbuf));
}
#endif


/*
 * Handle /caps.txt
 */
void caps_txt(state *st, shm_state *shm)
{
	/* Log the request */
	if (st->opt_syslog) {
		syslog(LOG_INFO, "request for \"gopher://%s:%i/0" CAPS_TXT "\" from %s",
			st->server_host,
			st->server_port,
			st->req_remote_addr);
	}
	log_combined(st, HTTP_OK);

	/* Update counters */
#ifdef HAVE_SHMEM
	if (shm) {
		shm->hits++;
		shm->kbytes += 1;

		/* Update session data */
		st->req_filesize += 1024;
		update_shm_session(st, shm);
	}
#endif

	/* Standard caps.txt stuff */
	snprintf(sockbuf, BUFSIZE, "CAPS" CRLF
		CRLF
		"##" CRLF
		"## This is an automatically generated caps file." CRLF
		"##" CRLF
		CRLF
		"CapsVersion=1" CRLF
		"ExpireCapsAfter=%i" CRLF
		CRLF
		"PathDelimeter=/" CRLF
		"PathIdentity=." CRLF
		"PathParent=.." CRLF
		"PathParentDouble=FALSE" CRLF
		"PathKeepPreDelimeter=FALSE" CRLF
		CRLF
		"ServerSoftware=" SERVER_SOFTWARE CRLF
		"ServerSoftwareVersion=" VERSION CRLF
		"ServerArchitecture=%s" CRLF,
			st->session_timeout,
			st->server_platform);
	(*st->write) (&(st->ss), sockbuf, strlen(sockbuf));


	/* Optional keys */
	if (*st->server_description) {
		snprintf(sockbuf, BUFSIZE, "ServerDescription=%s" CRLF, st->server_description);
		(*st->write) (&(st->ss), sockbuf, strlen(sockbuf));
	}
	if (*st->server_location) {
		snprintf(sockbuf, BUFSIZE, "ServerGeolocationString=%s" CRLF, st->server_location);
		(*st->write) (&(st->ss), sockbuf, strlen(sockbuf));
	}
	if (*st->server_admin) {
		snprintf(sockbuf, BUFSIZE, "ServerAdmin=%s" CRLF, st->server_admin);
		(*st->write) (&(st->ss), sockbuf, strlen(sockbuf));
	}
}


/*
 * Setup environment variables as per the CGI spec
 */
void setenv_cgi(state *st, char *script)
{
	char buf[BUFSIZE];

	/* Security */
	setenv("PATH", SAFE_PATH, 1);

	/* Set up the environment as per CGI spec */
	setenv("GATEWAY_INTERFACE", "CGI/1.1", 1);
	setenv("CONTENT_LENGTH", "0", 1);
	setenv("QUERY_STRING", st->req_query_string, 1);
	snprintf(buf, sizeof(buf), SERVER_SOFTWARE_FULL, st->server_platform);
	setenv("SERVER_SOFTWARE", buf, 1);
	setenv("SERVER_ARCH", st->server_platform, 1);
	setenv("SERVER_DESCRIPTION", st->server_description, 1);
	snprintf(buf, sizeof(buf), SERVER_SOFTWARE "/" VERSION);
	setenv("SERVER_VERSION", buf, 1);

	if (st->req_protocol == PROTO_HTTP)
		setenv("SERVER_PROTOCOL", "HTTP/0.9", 1);
	else
		setenv("SERVER_PROTOCOL", "RFC1436", 1);

	setenv("SERVER_NAME", st->server_host, 1);
	snprintf(buf, sizeof(buf), "%i", st->server_port);
	setenv("SERVER_PORT", buf, 1);
	setenv("REQUEST_METHOD", "GET", 1);
	setenv("DOCUMENT_ROOT", st->server_root, 1);
	setenv("SCRIPT_NAME", st->req_selector, 1);
	setenv("SCRIPT_FILENAME", script, 1);
	setenv("LOCAL_ADDR", st->req_local_addr, 1);
	setenv("REMOTE_ADDR", st->req_remote_addr, 1);
	setenv("HTTP_REFERER", st->req_referrer, 1);
	setenv("HTTP_ACCEPT_CHARSET", strcharset(st->out_charset), 1);

	/* Gophernicus extras */
	snprintf(buf, sizeof(buf), "%c", st->req_filetype);
	setenv("GOPHER_FILETYPE", buf, 1);
	setenv("GOPHER_CHARSET", strcharset(st->out_charset), 1);
	setenv("GOPHER_REFERER", st->req_referrer, 1);
	snprintf(buf, sizeof(buf), "%i", st->out_width);
	setenv("COLUMNS", buf, 1);

	/* Bucktooth extras */
	if (*st->req_query_string) {
		snprintf(buf, sizeof(buf), "%s?%s",
			st->req_selector, st->req_query_string);
		setenv("SELECTOR", buf, 1);
	}
	else setenv("SELECTOR", st->req_selector, 1);

	setenv("SERVER_HOST", st->server_host, 1);
	setenv("REQUEST", st->req_selector, 1);
	setenv("SEARCHREQUEST", st->req_query_string, 1);
}


/*
 * Execute a CGI script - modified to work with new SSL support
 */
void run_cgi(state *st, char *script, char *arg)
{
	char buf[BUFSIZE];
	FILE *pp;
	/* Setup environment & execute the binary */
	if (st->debug) syslog(LOG_INFO, "executing script \"%s\"", script);

	setenv_cgi(st, script);
	int pipedesc[2], status;
	int bytes, proc;
	pipe(pipedesc);
	fcntl(pipedesc[0], F_SETFL, O_NONBLOCK);
	fcntl(pipedesc[1], F_SETFL, O_NONBLOCK);
	switch (proc = fork()) {
		case 0:
			dup2(pipedesc[1], 0);
			dup2(pipedesc[1], 1);
			dup2(pipedesc[1], 2);
			execl(script, script, arg, NULL);
			/* Didn't work - die */
			info(st, ERR_ACCESS, TYPE_ERROR);
			return;
			break;
		case -1:
			info(st, "Couldn't fork!", TYPE_ERROR);
			return;
			break;
	}
	int contin = 1;
	while (contin) {
		bytes = read(pipedesc[0], buf, 32);
		switch (bytes) {
			case -1:
				switch (errno) {
					case EAGAIN:
						if (wait(NULL) == -1) goto stop;
						goto cont;
						break;
					default:
						goto stop;
						break;
				}
			case 0:
				goto stop;
				break;
			default:
				(*st->write) (&(st->ss), buf, bytes);
		}
		goto cont;
		stop:
		contin = 0;
		break;
		cont:
		contin = 1; // Make compiler happy
	}
	return;
}


/*
 * Handle file selectors
 */
void gopher_file(state *st)
{
	struct stat file;
	char buf[BUFSIZE];
	char *c, *d;

	/* Refuse to serve out gophermaps/tags */
	if ((c = strrchr(st->req_realpath, '/'))) c++;
	else c = st->req_realpath;
	d = strrchr(c, '.');

	if (strcmp(c, st->map_file) == MATCH)
		die(st, ERR_ACCESS, "Refusing to serve out a gophermap file");
	if (strcmp(c, st->tag_file) == MATCH)	
		die(st, ERR_ACCESS, "Refusing to serve out a gophertag file");
	if (d++ != NULL) {
		if (strcmp(d, st->hdr_ext) == MATCH)
			die(st, ERR_ACCESS, "Refusing to serve out a file-selector footer file");
		if (strcmp(d, st->ftr_ext) == MATCH)
			die(st, ERR_ACCESS, "Refusing to serve out a file-selector header file");
		if (strcmp(d, st->tag_ext) == MATCH)
			die(st, ERR_ACCESS, "Refusing to serve out a file-selector tag file");
	}

	/* Check for & run CGI and query scripts */
	if (strstr(st->req_realpath, st->cgi_file) || st->req_filetype == TYPE_QUERY)
		run_cgi(st, st->req_realpath, NULL);

	/* Check for a file suffix filter */
	if (*st->filter_dir && (c = strrchr(st->req_realpath, '.'))) {
		snprintf(buf, sizeof(buf), "%s/%s", st->filter_dir, c + 1);

		/* Filter file through the script */
		if (stat(buf, &file) == OK && (file.st_mode & S_IXOTH))
			run_cgi(st, buf, st->req_realpath);
	}

	/* Check for a filetype filter */
	if (*st->filter_dir) {
		snprintf(buf, sizeof(buf), "%s/%c", st->filter_dir, st->req_filetype);

		/* Filter file through the script */
		if (stat(buf, &file) == OK && (file.st_mode & S_IXOTH))
			run_cgi(st, buf, st->req_realpath);
	}

	/* Output regular files */
	if (st->req_filetype == TYPE_TEXT || st->req_filetype == TYPE_MIME)
		send_text_file(st);
	else
		send_binary_file(st);


	if (st->out_protection && strlen(st->protection_certkeyfile) > 2) {
		SSL_shutdown(st->ss.sslh);
	}
	close(0);
	close(1);
	close(2);
	exit(0);
}


