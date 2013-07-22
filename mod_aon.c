/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * mod_aon.c: Stuff for dealing with directory as subdomains
 *
 * Original by Raúl Trepiana
 *
 */
#include "apr.h"
#include "apr_strings.h"
#include "apr_strmatch.h"

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"

#include "http_core.h"
#include "http_log.h"
#include "http_request.h"

#define aon_log(x) do_aon_log x
#define FIXUP_GWT_CONTENT_IN "FIXUP_GWT_CONTENT_IN"
#define FIXUP_CONTENT_OUT "FIXUP_CONTENT_OUT"
#define FIXUP_HEADERS_OUT "FIXUP_HEADERS_OUT"
#define REWRITELOG_MODE  ( APR_UREAD | APR_UWRITE | APR_GREAD | APR_WREAD )
#define REWRITELOG_FLAGS ( APR_WRITE | APR_APPEND | APR_CREATE )

#define AP_MAX_BUCKETS 1000

/* remembered host & directory for  */
#define AON_USER_HOST "aon-user-host"
#define AON_USER_CONTEXT  "aon-user-ctx"
#define AON_USER_DIRECTORY  "aon-user-dir"
#define AON_USER_GWT_MODULE_BASE  "aon-gwt-module-base"

#define SEDSCAT(s1, s2, pool, buff, blen, repl) do { \
    if (!s1) {                                       \
        s1 = apr_pstrmemdup(pool, buff, blen);       \
    }                                                \
    else {                                           \
        s2 = apr_pstrmemdup(pool, buff, blen);       \
        s1 = apr_pstrcat(pool, s1, s2, NULL);        \
    }                                                \
    s1 = apr_pstrcat(pool, s1, repl, NULL);          \
} while (0)

#define SEDRMPATBCKT(b, offset, tmp_b, patlen) do {  \
    apr_bucket_split(b, offset);                     \
    tmp_b = APR_BUCKET_NEXT(b);                      \
    apr_bucket_split(tmp_b, patlen);                 \
    b = APR_BUCKET_NEXT(tmp_b);                      \
    apr_bucket_delete(tmp_b);                        \
} while (0)

/*
 =======================================================================================================================
    Configuration structures
 =======================================================================================================================
 */

typedef struct {
    const char *subdomain;
    const char *directory;
    char *handler;
    ap_regex_t *regexp;
} directory_match;


typedef struct {

    apr_array_header_t *directories;

    const char   *logfile;     /* the AonLog filename            */
    apr_file_t   *logfp;       /* the AonLog open filepointer    */
    int           loglevel;    /* the AonLog level of verbosity  */
} aon_server_config;

typedef struct {
    apr_array_header_t *directories;

} aon_dir_config;


typedef struct {
    ap_regex_t *regexp;
    const char *replacement;

}aon_content_filter_pattern;

typedef apr_status_t (*aon_content_filter_cb)(ap_filter_t *f, apr_bucket_brigade *bb);

typedef struct {
    apr_bucket_brigade 		*linebb;
    apr_bucket_brigade 		*linesbb;
    apr_bucket_brigade 		*passbb;
    apr_bucket_brigade 		*pattbb;
    apr_pool_t 				*tpool;
	apr_array_header_t 		*patterns;
	aon_content_filter_cb 	cb;
} aon_content_filter_ctx;


typedef struct {
	aon_content_filter_ctx ctx;
	apr_bucket_brigade 		*bb;
} aon_content_input_filter_ctx;

/*
 =======================================================================================================================
    Prototypes
 =======================================================================================================================
 */
static int 			aon_post_config(apr_pool_t *pool, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);
static apr_status_t ap_headers_fixup(request_rec *r);
static int 			aon_directory_translate(request_rec *r);
static void 		aon_insert_filter(request_rec *r);
static apr_status_t aon_gwt_content_input_filter(ap_filter_t *f, apr_bucket_brigade *b, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes);
static apr_status_t aon_content_output_filter(ap_filter_t *f, apr_bucket_brigade *bb);
static apr_status_t aon_headers_output_filter(ap_filter_t *f, apr_bucket_brigade *bb);
static const char 	*aon_set_log(cmd_parms *cmd, void *cfg, const char *arg1);
static const char 	*aon_set_log_level(cmd_parms *cmd, void *cfg, const char *arg1);
static const char 	*aon_add_directory_regexp(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2);
static void			*aon_create_dir_conf(apr_pool_t *pool, char *context);
static void			*aon_merge_dir_conf(apr_pool_t *pool, void *basev, void *overridesv);
static void			*aon_create_server_conf(apr_pool_t *pool, server_rec *s);
static void			*aon_merge_server_conf(apr_pool_t *p, void *basev, void *overridesv);
static void 		aon_register_hooks(apr_pool_t *p);



/*
 =======================================================================================================================
   Static module data
 =======================================================================================================================
 */

/* whether proxy module is available or not */
static int proxy_available;

static const apr_strmatch_pattern *cookie_path_pattern ;


/*
 =======================================================================================================================
    Configuration directives
 =======================================================================================================================
 */
static const command_rec aon_directives[] =
{
		AP_INIT_TAKE2(	"AonDirectoryMatch", aon_add_directory_regexp, NULL, RSRC_CONF,
						"a regular expression and a subdomain"),
		AP_INIT_TAKE1(	"AonLog", aon_set_log,      NULL, RSRC_CONF,
						"the filename of the rewriting logfile"),
		AP_INIT_TAKE1(	"AonLogLevel", aon_set_log_level, NULL, RSRC_CONF,
						"the level of the rewriting logfile verbosity "
						"(0=none, 1=std, .., 9=max)"),

						 { NULL }
};

/*
 =======================================================================================================================
    Our name tag
 =======================================================================================================================
 */

module AP_MODULE_DECLARE_DATA aon_module = {
    STANDARD20_MODULE_STUFF,
    aon_create_dir_conf,	/* create per-dir    config structures */
    aon_merge_dir_conf,		/* merge  per-dir    config structures */
    aon_create_server_conf,	/* create per-server config structures */
    aon_merge_server_conf,	/* merge  per-server config structures */
    aon_directives,        	/* table of config file commands       */
    aon_register_hooks     	/* register hooks                      */
};


/*
 =======================================================================================================================
 The hook registration function
 =======================================================================================================================
 */

static void aon_register_hooks(apr_pool_t *p)
{
    /* translate before mod_proxy.
     */
    static const char * const aszSucc[]={ "mod_proxy.c",NULL };

    /* post config handling */
	ap_hook_post_config(aon_post_config, NULL, NULL, APR_HOOK_MIDDLE);

    /* filename-to-URI translation */
    ap_hook_translate_name(aon_directory_translate,NULL,aszSucc,APR_HOOK_FIRST);

    /* fixup header fields*/
    ap_hook_fixups(ap_headers_fixup, NULL, aszSucc, APR_HOOK_FIRST);

    ap_hook_insert_filter(aon_insert_filter, NULL, NULL, APR_HOOK_FIRST);

    ap_register_input_filter(FIXUP_GWT_CONTENT_IN, aon_gwt_content_input_filter,
                              NULL, AP_FTYPE_CONTENT_SET);
    ap_register_output_filter(FIXUP_HEADERS_OUT, aon_headers_output_filter,
                              NULL, AP_FTYPE_CONTENT_SET);
    ap_register_output_filter(FIXUP_CONTENT_OUT, aon_content_output_filter,
                              NULL, AP_FTYPE_CONTENT_SET);

}


/*
 -----------------------------------------------------------------------------------------------------------------------
 aon logfile support
 -----------------------------------------------------------------------------------------------------------------------
 */

static char *current_logtime(request_rec *r)
{
    apr_time_exp_t 	t;
    char 			tstr[80];
    apr_size_t 		len;

    apr_time_exp_lt(&t, apr_time_now());

    apr_strftime(tstr, &len, sizeof(tstr), "[%d/%b/%Y:%H:%M:%S ", &t);
    apr_snprintf(tstr+len, sizeof(tstr)-len, "%c%.2d%.2d]",
                 t.tm_gmtoff < 0 ? '-' : '+',
                 t.tm_gmtoff / (60*60), t.tm_gmtoff % (60*60));

    return apr_pstrdup(r->pool, tstr);
}
static int open_aon_log(server_rec *s, apr_pool_t *p)
{
    aon_server_config 	*conf;
    const char 			*fname;

    conf = ap_get_module_config(s->module_config, &aon_module);

    ap_log_error(APLOG_MARK, APLOG_ERR, APR_EBADPATH, s,
                 "mod_aon: AonLog "
                 "path %s", conf->logfile);

    /* - no logfile configured
     * - logfilename empty
     * - virtual log shared w/ main server
     */
    if (!conf->logfile || !*conf->logfile || conf->logfp) {
        return 1;
    }

    if (*conf->logfile == '|') {
        piped_log *pl;

        fname = ap_server_root_relative(p, conf->logfile+1);
        if (!fname) {
            ap_log_error(APLOG_MARK, APLOG_ERR, APR_EBADPATH, s,
                         "mod_aon: Invalid AonLog "
                         "path %s", conf->logfile+1);
            return 0;
        }

        if ((pl = ap_open_piped_log(p, fname)) == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "mod_aon: could not open reliable pipe "
                         "to AonLog filter %s", fname);
            return 0;
        }
        conf->logfp = ap_piped_log_write_fd(pl);
    }
    else {
        apr_status_t rc;

        fname = ap_server_root_relative(p, conf->logfile);
        if (!fname) {
            ap_log_error(APLOG_MARK, APLOG_ERR, APR_EBADPATH, s,
                         "mod_aon: Invalid AonLog "
                         "path %s", conf->logfile);
            return 0;
        }

        if ((rc = apr_file_open(&conf->logfp, fname,
                                REWRITELOG_FLAGS, REWRITELOG_MODE, p))
                != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rc, s,
                         "mod_aon: could not open AonLog "
                         "file %s", fname);
            return 0;
        }
    }

    return 1;
}

static void do_aon_log(request_rec *r, int level, char *perdir,
                          const char *fmt, ...)
{
	aon_server_config 	*conf;
    char 				*logline, *text;
    const char 			*rhost, *rname;
    apr_size_t 			nbytes;
    int 				redir;
    request_rec 		*req;
    va_list 			ap;

    conf = ap_get_module_config(r->server->module_config, &aon_module);

    if (!conf->logfp || level > conf->loglevel) {
        return;
    }

    rhost = ap_get_remote_host(r->connection, r->per_dir_config,
                               REMOTE_NOLOOKUP, NULL);
    rname = ap_get_remote_logname(r);

    for (redir=0, req=r; req->prev; req = req->prev) {
        ++redir;
    }

    va_start(ap, fmt);
    text = apr_pvsprintf(r->pool, fmt, ap);
    va_end(ap);

    logline = apr_psprintf(r->pool, "%s %s %s %s [%s/sid#%pp][rid#%pp/%s%s%s] "
                                    "(%d) %s%s%s%s" APR_EOL_STR,
                           rhost ? rhost : "UNKNOWN-HOST",
                           rname ? rname : "-",
                           r->user ? (*r->user ? r->user : "\"\"") : "-",
                           current_logtime(r),
                           ap_get_server_name(r),
                           (void *)(r->server),
                           (void *)r,
                           r->main ? "subreq" : "initial",
                           redir ? "/redir#" : "",
                           redir ? apr_itoa(r->pool, redir) : "",
                           level,
                           perdir ? "[perdir " : "",
                           perdir ? perdir : "",
                           perdir ? "] ": "",
                           text);

    nbytes = strlen(logline);
    apr_file_write(conf->logfp, logline, &nbytes);

    return;
}

/*
 =======================================================================================================================

 =======================================================================================================================
 */
static int 	aon_post_config(apr_pool_t *pool, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s){


    /* check if proxy module is available */
    proxy_available = (ap_find_linked_module("mod_proxy.c") != NULL);

    /* step through the servers and
     * - open each aon logfile
     */

	for (; s; s = s->next) {
        if (!open_aon_log(s, pool)) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

	cookie_path_pattern = apr_strmatch_precompile(pool , "path=", 0);

    return OK;
}




static void fixup_gwt_module_base(request_rec *r) {

	/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
	int 			port;
	const char 		*repl;
	const char 		*host;
	const char 		*user_port;
	const char 		*user_directory;
	const char 		*gwt_module_path;
	const char 		*gwt_module_base;
	const char 		*fixup_gwt_module_base;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

	gwt_module_base  = apr_table_get(r->headers_in, "X-GWT-Module-Base");
	if ( !gwt_module_base ) {
		return;
	}

	user_directory = apr_table_get(r->notes, AON_USER_DIRECTORY);

	/* if no user_directory, no fixups needed*/
	if ( !user_directory ) {
		return;
	}

	host = apr_table_get(r->headers_in, "Host");

	apr_table_set(r->notes, AON_USER_GWT_MODULE_BASE, gwt_module_base);

	port = ap_get_server_port(r);
	repl = ap_strstr(gwt_module_base, user_directory ) ;
	gwt_module_path = repl + strlen(user_directory);
	user_port = ap_is_default_port(port, r) ? "" : apr_psprintf(r->pool, ":%u", port);

	fixup_gwt_module_base = apr_psprintf(r->pool, "%s://%s%s%s",
			ap_http_scheme(r), host, user_port,gwt_module_path);

	apr_table_set(r->headers_in, "X-GWT-Module-Base", fixup_gwt_module_base );

	aon_log((r, 0, NULL, "fixup  X-GWT-Module-Base  '%s'", fixup_gwt_module_base));

}

static apr_status_t ap_headers_fixup(request_rec *r)
{
	fixup_gwt_module_base(r);

    return OK;
}


/*
 * Apply a single AonDirectoryMatch
 */
static int apply_directory_match(directory_match *match, request_rec *r)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
	int 				port;
	const char 			*host;
	const char 			*server;
	const char 			*subdomain;
	const char 			*filename;
	ap_regmatch_t 		regmatch[AP_MAX_REG_MATCH];
	const char 			*user_host;
	const char 			*user_context;
	const char 			*user_directory;

	char 				*tok_cntx;
	char 				*path;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

	/* Try to match the URI against the AonDirectoryMatch regexp.
	 */
	aon_log((r, 0, NULL,
				"applying regexp '%s' to uri '%s'", match->directory, r->filename));

	if (!ap_regexec(match->regexp, r->filename, AP_MAX_REG_MATCH, regmatch, 0)) {

		subdomain = ap_pregsub(r->pool, match->subdomain, r->filename,
								   AP_MAX_REG_MATCH, regmatch);

		port = ap_get_server_port(r);

		server = ap_get_server_name(r);

		host = apr_pstrcat(r->pool, subdomain, ".", server, NULL );

		user_directory = apr_pstrndup(r->pool, r->filename, regmatch[0].rm_eo );
		apr_table_setn(r->notes, AON_USER_DIRECTORY , user_directory);
		filename =  apr_pstrdup(r->pool, r->filename + regmatch[0].rm_eo);

		path = apr_pstrdup(r->pool, filename);
		user_context = apr_strtok(path, "/", &tok_cntx);
		apr_table_setn(r->notes, AON_USER_CONTEXT , user_context );


		r->filename = apr_psprintf(r->pool, "%s://%s%s%s%s",
								   ap_http_scheme(r), host,
								   ap_is_default_port(port, r) ? "" : apr_psprintf(r->pool, ":%u", port),
								   (*filename == '/') ? "" : "/",
								   filename);
		aon_log((r, 0, NULL,
				"forcing proxy-throughput with %s", r->filename));

		user_host = apr_table_get(r->headers_in, "Host");
		apr_table_setn(r->notes, AON_USER_HOST , user_host);
		/* Sets Host header value. This value will be retrieve by method
		 * 'getServerName()' of interface 'javax.servlet.ServletRequest'.
		 * And it's exactly the method used by aon for guess the domain.
		 */
		apr_table_set(r->headers_in, "Host", host );

		r->filename = apr_pstrcat(r->pool, "proxy:", r->filename, NULL);

		return 1;

	}

	return 0;
}

static int aon_directory_translate(request_rec *r)
{

    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
	aon_dir_config 		*config  ;
	directory_match 	*matchs ;
	int 				i ;
	int 				rc;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

	config = (aon_dir_config*) ap_get_module_config(r->per_dir_config, &aon_module);
	matchs = (directory_match *)config->directories->elts;

	/* if filename was not initially set,
     * we start with the requested URI
     */
    if (r->filename == NULL) {
        r->filename = apr_pstrdup(r->pool, r->uri);
        aon_log((r, 0, NULL,
        			"init aon directory with requested uri %s", r->uri));
    }
    else {
        aon_log((r, 0, NULL,
    				"init aon with passed filename %s. .Original uri = %s", r->uri, r->filename));
    }

    /*
      *  now apply the directories directives ...
      */
    for (i = 0; i < config->directories->nelts; ++i) {
    	directory_match *match = &matchs[i];
    	rc = apply_directory_match ( match, r );
    	if ( rc ) {
            /* it should be go on as an internal proxy request */

            /* check if the proxy module is enabled, so
             * we can actually use it!
             */
            if (!proxy_available) {
                aon_log((r, 0, NULL,
                              "attempt to make remote request from mod_rewrite "
                              "without proxy enabled: %s", r->filename));
                return HTTP_FORBIDDEN;
            }

            apr_table_setn(r->notes, "proxy-nocanon", "1");

            /* make sure the QUERY_STRING and
             * PATH_INFO parts get incorporated
             */
            if (r->path_info != NULL) {
                r->filename = apr_pstrcat(r->pool, r->filename,
                                          r->path_info, NULL);
            }
            if (r->args != NULL) {
                /* see proxy_http:proxy_http_canon() */
                r->filename = apr_pstrcat(r->pool, r->filename,
                                          "?", r->args, NULL);
            }

            /* now make sure the request gets handled by the proxy handler */
            if (PROXYREQ_NONE == r->proxyreq) {
                r->proxyreq = PROXYREQ_REVERSE;
            }
            r->handler  = "proxy-server";

            aon_log((r, 1, NULL, "go-ahead with proxy request %s [OK]",
                        r->filename));

            ap_add_output_filter(FIXUP_HEADERS_OUT, NULL, r, r->connection);
            ap_add_output_filter(FIXUP_CONTENT_OUT, NULL, r, r->connection);

            return OK;
    	}

	}


	return DECLINED;
}

static void aon_fix_redirect(request_rec *r, const char *user_directory, const  char *user_host) {

    /*
     * Shortcircuit processing
     */
	if (!ap_is_HTTP_REDIRECT(r->status))
		return;

	/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
	const char 		*location;
	const char 		*fixed_location;
	apr_uri_t 		parsed_location;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

	location = apr_table_get(r->headers_out, "Location");
	if ( location == NULL ) {
		return;
	}

	apr_uri_parse(r->pool, location, &parsed_location);
	parsed_location.hostname = apr_pstrdup(r->pool, user_host );
	parsed_location.path = apr_pstrcat(r->pool, user_directory, parsed_location.path, NULL);

	fixed_location = apr_uri_unparse(r->pool, &parsed_location, APR_URI_UNP_REVEALPASSWORD);
	apr_table_set(r->headers_out, "Location", fixed_location );
	aon_log((r, 0, NULL,
                 "redirect [%u]: fix location '%s' to '%s'",
                 r->status,
                 location,
                 fixed_location));

}


static void aon_fix_cookie(request_rec *r, const  char *user_directory) {

    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
	const char 		*cookie;
	const char		*cookie_path;
	char			*fixed_cookie;
	int				cookie_path_off;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/


	cookie = apr_table_get(r->headers_out, "Set-Cookie");

	if ( cookie == NULL ) {
		return;
	}

	cookie_path = apr_strmatch ( cookie_path_pattern, cookie, strlen(cookie) );
	if ( cookie_path == NULL ){
		return;
	}

	cookie_path_off = cookie_path + 5 - cookie;
	user_directory = apr_table_get(r->notes, AON_USER_DIRECTORY);
	fixed_cookie = apr_pstrcat(r->pool,
			apr_pstrndup(r->pool, cookie, cookie_path_off ),
			user_directory,
			apr_pstrdup(r->pool, cookie + cookie_path_off),
			NULL);
	apr_table_set(r->headers_out, "Set-Cookie", fixed_cookie);
	aon_log((r, 0, NULL,
				 "fixup Cookie '%s' to '%s'",
				 cookie, fixed_cookie ));
}

static void aon_fix_ajax_redirect(request_rec *r, const char *user_directory, const  char *user_host) {

	/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
	const char		*ajax_response;
	const char 		*location;
	const char 		*fixed_location;
	apr_uri_t 		parsed_location;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

	/*
     * Shortcircuit processing
     */
	ajax_response = apr_table_get(r->headers_out, "Ajax-Response");
	if ( ajax_response == NULL || strncasecmp("redirect", ajax_response, 8) ) {
		return;
	}

	user_host = apr_table_get(r->notes, AON_USER_HOST);
	user_directory = apr_table_get(r->notes, AON_USER_DIRECTORY);

	location = apr_table_get(r->headers_out, "Location");
	apr_uri_parse(r->pool, location, &parsed_location);

	if ( parsed_location.hostname  ) {
		parsed_location.hostname = apr_pstrdup(r->pool, user_host );
	}
	parsed_location.path = apr_pstrcat(r->pool, user_directory, parsed_location.path, NULL);

	fixed_location = apr_uri_unparse(r->pool, &parsed_location, APR_URI_UNP_REVEALPASSWORD);
	apr_table_set(r->headers_out, "Location", fixed_location );
	aon_log((r, 0, NULL,
                 "Ajax-Response: redirect [%u]: fix location '%s' to '%s'",
                 r->status,
                 location,
                 fixed_location));

}




static apr_status_t aon_headers_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
	request_rec 	*r = f->r;
	const char 		*user_directory;
	const char		*user_host;
	apr_status_t 	rv;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/


    user_host = apr_table_get(r->notes, AON_USER_HOST);
	user_directory = apr_table_get(r->notes, AON_USER_DIRECTORY);

	aon_fix_redirect(r, user_directory, user_host);

	aon_fix_cookie(r, user_directory);


	aon_fix_ajax_redirect(r, user_directory, user_host);

    /* remove ourselves from the filter chain */
    ap_remove_output_filter(f);

    /* send the data up the stack */
    rv = ap_pass_brigade(f->next,bb);

    return rv;
}

static void aon_fix_content(ap_filter_t *f, apr_bucket *inb,
                         apr_bucket_brigade *mybb,
                         apr_pool_t *tmp_pool)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
	int						i;
	apr_bucket 				*b;
    apr_size_t 				bytes;
    apr_size_t 				len;
    apr_size_t 				fbytes = 0;
    const char 				*buff;
    char 					*scratch = NULL;
    char 					*p;
    const char 				*repl;
    apr_bucket 				*tmp_b;
    apr_pool_t 				*tpool ;
	aon_content_filter_ctx 		*ctx ;
	aon_content_filter_pattern	*patterns;
	aon_content_filter_pattern	*pattern;
    ap_regmatch_t 			regm[AP_MAX_REG_MATCH];
	/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

	ctx = f->ctx;
	apr_pool_create(&tpool, tmp_pool);
	patterns = (aon_content_filter_pattern*) ctx->patterns->elts;

    APR_BRIGADE_INSERT_TAIL(mybb, inb);

    for (i = 0; i < ctx->patterns->nelts; i++) {

    	pattern = &patterns[i];


    	for (b = APR_BRIGADE_FIRST(mybb);
			 b != APR_BRIGADE_SENTINEL(mybb);
			 b = APR_BUCKET_NEXT(b)) {

	    	if (APR_BUCKET_IS_METADATA(b)) {
				/*
				 * we should NEVER see this, because we should never
				 * be passed any, but "handle" it just in case.
				 */
				continue;
			}

			if (apr_bucket_read(b, &buff, &bytes, APR_BLOCK_READ)
					== APR_SUCCESS) {

		    	/*
				 * we need a null terminated string here :(. To hopefully
				 * save time and memory, we don't alloc for each run
				 * through, but only if we need to have a larger chunk
				 * to save the string to. So we keep track of how much
				 * we've allocated and only re-alloc when we need it.
				 * NOTE: this screams for a macro.
				 */
				if (!scratch || (bytes > (fbytes + 1))) {
					fbytes = bytes + 1;
					scratch = apr_palloc(tpool, fbytes);
				}
				/* reset pointer to the scratch space */
				p = scratch;
				memcpy(p, buff, bytes);
				p[bytes] = '\0';

				while (!ap_regexec(pattern->regexp, p,
								   AP_MAX_REG_MATCH, regm, 0)) {
					/* first, grab the replacement string */
					repl = ap_pregsub(tmp_pool, pattern->replacement, p,
									  AP_MAX_REG_MATCH, regm);

					aon_log((f->r, 0, NULL,
			    			"replace %s %s" ,
			    			 apr_pstrndup(tpool, p + regm[0].rm_so, regm[0].rm_eo - regm[0].rm_so), repl  ));

					len = (apr_size_t) (regm[0].rm_eo - regm[0].rm_so);
					SEDRMPATBCKT(b, regm[0].rm_so, tmp_b, len);
					tmp_b = apr_bucket_transient_create(repl,
														strlen(repl),
									 f->r->connection->bucket_alloc);
					APR_BUCKET_INSERT_BEFORE(b, tmp_b);
					/*
					 * reset to past what we just did. buff now maps to b
					 * again
					 */
					p += regm[0].rm_eo;
				}
			}
		}
    }

    return;
}

static apr_status_t aon_content_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{

	/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    int 					num = 0;
    apr_size_t 				len;
    const char 				*nl = NULL;
	apr_bucket				*b;
	char					*bflat;
	apr_size_t				fbytes;
	const char				*buff;
	apr_size_t				bytes;
	apr_status_t 			rv;
	aon_content_filter_ctx 		*ctx ;
    apr_bucket 				*tmp_b;
    apr_bucket_brigade 		*tmp_bb = NULL;
	request_rec 			*r = f->r;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

	ctx = f->ctx;


    /*
     * Here's the concept:
     *  Read in the data and look for newlines. Once we
     *  find a full "line", add it to our working brigade.
     *  If we've finished reading the brigade and we have
     *  any left over data (not a "full" line), store that
     *  for the next pass.
     *
     * Note: anything stored in ctx->linebb for sure does not have
     * a newline char, so we don't concat that bb with the
     * new bb, since we would spending time searching for the newline
     * in data we know it doesn't exist. So instead, we simply scan
     * our current bb and, if we see a newline, prepend ctx->linebb
     * to the front of it. This makes the code much less straight-
     * forward (otherwise we could APR_BRIGADE_CONCAT(ctx->linebb, bb)
     * and just scan for newlines and not bother with needing to know
     * when ctx->linebb needs to be reset) but also faster. We'll take
     * the speed.
     *
     * Note: apr_brigade_split_line would be nice here, but we
     * really can't use it since we need more control and we want
     * to re-use already read bucket data.
     *
     * See mod_include if still confused :)
     */
	while ((b = APR_BRIGADE_FIRST(bb)) && (b != APR_BRIGADE_SENTINEL(bb))) {

		if (APR_BUCKET_IS_EOS(b)) {
            /*
             * if we see the EOS, then we need to pass along everything we
             * have. But if the ctx->linebb isn't empty, then we need to add
             * that to the end of what we'll be passing.
             */
            if (!APR_BRIGADE_EMPTY(ctx->linebb)) {
                rv = apr_brigade_pflatten(ctx->linebb, &bflat,
                                          &fbytes, ctx->tpool);
                tmp_b = apr_bucket_transient_create(bflat, fbytes,
                                                r->connection->bucket_alloc);
                aon_fix_content(f, tmp_b, ctx->pattbb, ctx->tpool);

                APR_BRIGADE_CONCAT(ctx->passbb, ctx->pattbb);
            }
            apr_brigade_cleanup(ctx->linebb);
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(ctx->passbb, b);
        }
        /*
         * No need to handle FLUSH buckets separately as we call
         * ap_pass_brigade anyway at the end of the loop.
         */
        else if (APR_BUCKET_IS_METADATA(b)) {
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(ctx->passbb, b);
        }
        else {
            /*
             * We have actual "data" so read in as much as we can and start
             * scanning and splitting from our read buffer
             */
            rv = apr_bucket_read(b, &buff, &bytes, APR_BLOCK_READ);
            if (rv != APR_SUCCESS || bytes == 0) {
                apr_bucket_delete(b);
            }
            else {

                while (bytes > 0) {
                    nl = memchr(buff, APR_ASCII_LF, bytes);
                    if (nl) {
                        len = (apr_size_t) (nl - buff) + 1;
                        /* split *after* the newline */
                        apr_bucket_split(b, len);
                        /*
                         * We've likely read more data, so bypass rereading
                         * bucket data and continue scanning through this
                         * buffer
                         */
                        bytes -= len;
                        buff += len;
                        /*
                         * we need b to be updated for future potential
                         * splitting
                         */
                        tmp_b = APR_BUCKET_NEXT(b);
                        APR_BUCKET_REMOVE(b);
                        /*
                         * Hey, we found a newline! Don't forget the old
                         * stuff that needs to be added to the front. So we
                         * add the split bucket to the end, flatten the whole
                         * bb, morph the whole shebang into a bucket which is
                         * then added to the tail of the newline bb.
                         */
                        if (!APR_BRIGADE_EMPTY(ctx->linebb)) {
                            APR_BRIGADE_INSERT_TAIL(ctx->linebb, b);
                            rv = apr_brigade_pflatten(ctx->linebb, &bflat,
                                                      &fbytes, ctx->tpool);
                            b = apr_bucket_transient_create(bflat, fbytes,
                                            f->r->connection->bucket_alloc);
                            apr_brigade_cleanup(ctx->linebb);
                        }
                        aon_fix_content(f, b, ctx->pattbb, ctx->tpool);
                        /*
                         * Count how many buckets we have in ctx->passbb
                         * so far. Yes, this is correct we count ctx->passbb
                         * and not ctx->pattbb as we do not reset num on every
                         * iteration.
                         */
                        for (b = APR_BRIGADE_FIRST(ctx->pattbb);
                             b != APR_BRIGADE_SENTINEL(ctx->pattbb);
                             b = APR_BUCKET_NEXT(b)) {
                            num++;
                        }
                        APR_BRIGADE_CONCAT(ctx->passbb, ctx->pattbb);
                        /*
                         * If the number of buckets in ctx->passbb reaches an
                         * "insane" level, we consume much memory for all the
                         * buckets as such. So lets flush them down the chain
                         * in this case and thus clear ctx->passbb. This frees
                         * the buckets memory for further processing.
                         * Usually this condition should not become true, but
                         * it is a safety measure for edge cases.
                         */
                        if (num > AP_MAX_BUCKETS) {
                            b = apr_bucket_flush_create(
                                                f->r->connection->bucket_alloc);
                            APR_BRIGADE_INSERT_TAIL(ctx->passbb, b);
                            rv = ctx->cb(f, ctx->passbb);
                            apr_brigade_cleanup(ctx->passbb);
                            num = 0;
                            apr_pool_clear(ctx->tpool);
                            if (rv != APR_SUCCESS)
                                return rv;
                        }
                        b = tmp_b;
                    }
                    else {
                        /*
                         * no newline in whatever is left of this buffer so
                         * tuck data away and get next bucket
                         */
                        APR_BUCKET_REMOVE(b);
                        APR_BRIGADE_INSERT_TAIL(ctx->linebb, b);
                        bytes = 0;
                    }
                }
            }
        }
		if (!APR_BRIGADE_EMPTY(ctx->passbb)) {
            rv = ctx->cb(f, ctx->passbb);
            if (rv != APR_SUCCESS) {
                apr_pool_clear(ctx->tpool);
                return rv;
            }
        }
        apr_pool_clear(ctx->tpool);
	}

    /* Anything left we want to save/setaside for the next go-around */
    if (!APR_BRIGADE_EMPTY(ctx->linebb)) {
        /*
         * Provide ap_save_brigade with an existing empty brigade
         * (ctx->linesbb) to avoid creating a new one.
         */
        ap_save_brigade(f, &(ctx->linesbb), &(ctx->linebb), f->r->pool);
        tmp_bb = ctx->linebb;
        ctx->linebb = ctx->linesbb;
        ctx->linesbb = tmp_bb;
    }

    return APR_SUCCESS;

}


static apr_status_t aon_content_output_filter_cb (ap_filter_t *f, apr_bucket_brigade *bb){
	return ap_pass_brigade(f->next, bb);
}


static apr_status_t aon_content_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
	apr_status_t			rv;
	aon_content_filter_ctx 		*ctx ;
	request_rec 			*r = f->r;
	aon_content_filter_pattern 	*pattern;
	char					*regexp;
	const char 				*user_context = apr_table_get(r->notes, AON_USER_CONTEXT);
	const char 				*user_directory = apr_table_get(r->notes, AON_USER_DIRECTORY);
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    /* We can't do anything with no content-type or if type isn't 'text'.
     */
    if ( !r->content_type || strncmp(r->content_type, "text/", 5 ) ){
		/* remove ourselves from the filter chain */
		ap_remove_output_filter(f);
		/* send the data up the stack */
		return ap_pass_brigade(f->next,bb);
    }

    ctx = f->ctx;
    /*
     * First time around? Create the saved bb that we used for each pass
     * through. Note that we can also get here when we explicitly clear ctx,
     * for error handling
     */
    if (!ctx) {
        f->ctx = ctx = apr_pcalloc(r->pool, sizeof(*ctx));
        /*
         * Create all the temporary brigades we need and reuse them to avoid
         * creating them over and over again from r->pool which would cost a
         * lot of memory in some cases.
         */
        ctx->linebb = apr_brigade_create(r->pool, f->c->bucket_alloc);
        ctx->linesbb = apr_brigade_create(r->pool, f->c->bucket_alloc);
        ctx->pattbb = apr_brigade_create(r->pool, f->c->bucket_alloc);
        /*
         * Everything to be passed to the next filter goes in
         * here, our pass brigade.
         */
        ctx->passbb = apr_brigade_create(r->pool, f->c->bucket_alloc);
        /* Create our temporary pool only once */
        apr_pool_create(&(ctx->tpool), r->pool);
        apr_table_unset(f->r->headers_out, "Content-Length");

        ctx->patterns = apr_array_make(r->pool, 2, sizeof(aon_content_filter_pattern));

        pattern = apr_array_push(ctx->patterns);
        regexp = apr_psprintf(r->pool, "\"/(%s[^\"]*)\"", user_context );
        pattern->regexp = ap_pregcomp(r->pool, regexp, AP_REG_EXTENDED | AP_REG_ICASE);
        pattern->replacement = apr_psprintf(r->pool, "\"%s/$1\"", user_directory );

        pattern = apr_array_push(ctx->patterns);
        regexp = apr_psprintf(r->pool, "'/(%s[^']*)'", user_context );
        pattern->regexp = ap_pregcomp(r->pool, regexp, AP_REG_EXTENDED | AP_REG_ICASE);
        pattern->replacement = apr_psprintf(r->pool, "'%s/$1'", user_directory );

        /* Callback for pass filtered content*/
        ctx->cb = aon_content_output_filter_cb;

    }

    /*
     * Shortcircuit processing
     */
    if (APR_BRIGADE_EMPTY(bb))
        return APR_SUCCESS;

    rv = aon_content_filter(f, bb);

    return rv;

}

/* aon_insert_filter() is a filter hook which decides whether or not
 * to insert a translation filter for the current request.
 */
static void aon_insert_filter(request_rec *r)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
	const char *gwt_module_base;
	/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

	gwt_module_base =
			apr_table_get(r->notes, AON_USER_GWT_MODULE_BASE);
	if ( gwt_module_base ) {
		ap_add_input_filter(FIXUP_GWT_CONTENT_IN, NULL, r, r->connection);
	}
}

static apr_status_t aon_content_input_filter_cb (ap_filter_t *f, apr_bucket_brigade *bb){
	/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
	aon_content_input_filter_ctx	*ctx ;
	/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

	ctx = f->ctx;

	aon_log((f->r, 0, NULL, "aon_content_input_filter_cb"));

	APR_BRIGADE_CONCAT(ctx->bb, bb);

	return APR_SUCCESS;
}

static apr_status_t aon_gwt_content_input_filter(ap_filter_t *f,
		apr_bucket_brigade *bb,
		ap_input_mode_t mode,
		apr_read_type_e block,
		apr_off_t readbytes)
{

	/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
	apr_status_t					rv;
	aon_content_filter_ctx 			*ctx ;
	aon_content_input_filter_ctx	*input_ctx;
	request_rec 					*r = f->r;
	apr_bucket_brigade				*next_bb;
	aon_content_filter_pattern 		*pattern;
	const char 						*gwt_module_base = apr_table_get(r->headers_in, "X-GWT-Module-Base");
	const char 						*user_gwt_module_base = apr_table_get(r->notes, AON_USER_GWT_MODULE_BASE);
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

	ctx = f->ctx;
    /*
     * First time around? Create the saved bb that we used for each pass
     * through. Note that we can also get here when we explicitly clear ctx,
     * for error handling
     */
    if (!ctx) {
        f->ctx = input_ctx = apr_pcalloc(r->pool, sizeof(*input_ctx));
        ctx = ( aon_content_filter_ctx* ) input_ctx;
        /*
         * Create all the temporary brigades we need and reuse them to avoid
         * creating them over and over again from r->pool which would cost a
         * lot of memory in some cases.
         */
        ctx->linebb = apr_brigade_create(r->pool, f->c->bucket_alloc);
        ctx->linesbb = apr_brigade_create(r->pool, f->c->bucket_alloc);
        ctx->pattbb = apr_brigade_create(r->pool, f->c->bucket_alloc);
        /*
         * Everything to be passed to the next filter goes in
         * here, our pass brigade.
         */
        ctx->passbb = apr_brigade_create(r->pool, f->c->bucket_alloc);
        /* Create our temporary pool only once */
        apr_pool_create(&(ctx->tpool), r->pool);
        apr_table_unset(f->r->headers_out, "Content-Length");

        ctx->patterns = apr_array_make(r->pool, 1, sizeof(aon_content_filter_pattern));

        pattern = apr_array_push(ctx->patterns);
        pattern->regexp = ap_pregcomp(r->pool, user_gwt_module_base, AP_REG_EXTENDED | AP_REG_ICASE);
        pattern->replacement = gwt_module_base;

        /* Callback for passthrough filtered content. */
        ctx->cb = aon_content_input_filter_cb;

        /* Output brigade, where callback above put's filtered content. */
        input_ctx->bb = bb;
    }

    next_bb = apr_brigade_create(r->pool, f->c->bucket_alloc);

    rv = ap_get_brigade(f->next, next_bb, mode, block, readbytes);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = aon_content_filter(f, next_bb);

	return rv;

}

/*
 =======================================================================================================================
    Handler for the "AonSubDirectoryMatch" directive
 =======================================================================================================================
 */
static const char *aon_add_directory_regexp(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2 )
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
	aon_dir_config   *config = (aon_dir_config *) cfg;
    directory_match *new = apr_array_push(config->directories);
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    new->regexp = ap_pregcomp(cmd->pool, arg1, AP_REG_EXTENDED);
    if (new->regexp == NULL) {
    	return "Regular expression could not be compiled.";
    }

    new->directory = arg1;
    new->subdomain = arg2;
    new->handler = cmd->info;


    return NULL;
}

/*
 =======================================================================================================================
    Handler for the "AonLog" directive
 =======================================================================================================================
 */
static const char 	*aon_set_log(cmd_parms *cmd, void *dir_cfg, const char *arg1) {

    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
	aon_server_config *server_conf = ap_get_module_config(cmd->server->module_config, &aon_module);
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

	server_conf->logfile = arg1;

    return NULL;

}

/*
 =======================================================================================================================
    Handler for the "AonLogLevel" directive
 =======================================================================================================================
 */
static const char 	*aon_set_log_level(cmd_parms *cmd, void *cfg, const char *arg1){

    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
	aon_server_config *server_conf = ap_get_module_config(cmd->server->module_config, &aon_module);
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

	server_conf->loglevel = atoi(arg1);

    return NULL;

}


/*
 =======================================================================================================================
    Function for creating new configurations for per-directory contexts
 =======================================================================================================================
 */
static void *aon_create_dir_conf(apr_pool_t *pool, char *context)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    aon_dir_config    *config = apr_pcalloc(pool, sizeof(aon_dir_config));
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    config->directories = apr_array_make(pool, 2, sizeof(directory_match));
    return config;
}

/*
 =======================================================================================================================
    Merging function for per-directory configurations
 =======================================================================================================================
 */
static void *aon_merge_dir_conf(apr_pool_t *pool, void *basev, void *overridesv)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
	aon_dir_config    *base = (aon_dir_config *) basev;
	aon_dir_config    *overrides = (aon_dir_config *) overridesv;
	aon_dir_config    *config = apr_pcalloc(pool, sizeof(aon_dir_config));
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

	config->directories = apr_array_append(pool, overrides->directories, base->directories);
    return config;
}


/*
 =======================================================================================================================
    Function for creating new configurations for per-directory contexts
 =======================================================================================================================
 */
static void *aon_create_server_conf(apr_pool_t *pool, server_rec *s)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    aon_server_config    *config = apr_pcalloc(pool, sizeof(aon_server_config));
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    config->directories = apr_array_make(pool, 2, sizeof(directory_match));

    config->logfile  = NULL;
    config->logfp    = NULL;
    config->loglevel = 0;

    return config;
}

/*
 =======================================================================================================================
    Merging function for per-directory configurations
 =======================================================================================================================
 */
static void *aon_merge_server_conf(apr_pool_t *pool, void *basev, void *overridesv)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
	aon_server_config    *base = (aon_server_config *) basev;
	aon_server_config    *overrides = (aon_server_config *) overridesv;
	aon_server_config    *config = apr_pcalloc(pool, sizeof(aon_server_config));
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

	config->directories = apr_array_append(pool, overrides->directories, base->directories);

	config->loglevel = overrides->loglevel != 0 ? overrides->loglevel : base->loglevel;
	config->logfile  = overrides->logfile != NULL ? overrides->logfile : base->logfile;
	config->logfp    = overrides->logfp != NULL  ? overrides->logfp  : base->logfp;

	return config;
}



