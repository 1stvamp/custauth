/*
	Copyright 2008 Wesley Mason (wes@1stvamp.org)
	Base on the basic Apache module tutorial "mod_tut1" & "mod_tut2" by Kevin O'Donnell
	<http://threebit.net/tutorials/>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 * Include the core server components.
 */
#include "mod_custauth.h"
#include "httpd.h"
#include "http_config.h"
#include "stdio.h"
#include "util.c"

/*
 * The default value for the error string.
 */
#ifndef DEFAULT_MODCUSTAUTH_ERRSTRING
#define DEFAULT_MODCUSTAUTH_ERRSTRING "apache2_mod_custauth: config error"
#endif

/*
 * This module
 */
module AP_MODULE_DECLARE_DATA custauth_module;

/*
 * This modules per-server configuration structure.
 */
typedef struct {
	char *string;
} modcustauth_config;

/*
 * This function is registered as a handler for HTTP Auth methods and will
 * therefore be invoked for Basic and Digest Auth requests
 */
static int mod_custauth_basic_auth_handler (request_rec *r)
{
	char *sent_pw, *sent_un, *buffer, *cmd;
	int result;
	// Get the module configuration
	modcustauth_config *s_cfg = ap_get_module_config(r->server->module_config, &custauth_module);

	// Get the http password
	result = ap_get_basic_auth_pw(r, &sent_pw);
	// Get the http username
	sent_un = ap_pstrdup(r->pool, r->connection->user);

	sprintf(cmd, "%s \"%s:::%s\"", s_cfg->command_string, ap_escape_shell_cmd(r->pool, sent_un), ap_escape_shell_cmd(r->pool, sent_pw));
	result = (int) exec_cmd(cmd, &buffer);

	switch(result) {
		case 0:
			return HTTP_UNAUTHORIZED;
			break;
		case 1:
			return OK;
			break;
		case 2:
		default:
			// Send a message to stderr (apache redirects this to the error log)
			fprintf(stderr,"apache2_mod_custauth: Auth request by %s\n", sent_un);
			return DECLINED;
			break;
	}
}

char exec_cmd(char *cmd, char *buf)
{
	char output[1024], start[1024];
	char *s;
	FILE *fpo;
	int size;
	int ret;
	if((fpo = popen(cmd, "r") )== NULL)
	{
		sprintf(start, "error");
		size = 6;
	}
	else
	{
		sprintf(start, "");
		size =0;
		while((s =fgets(output, 1024, fpo)) != NULL){
			strcat(start, output);
			size += (strlen(output)+1);
			if(output == NULL)
				break;
		}
	}
	strcpy(buf, start);
	ret = pclose(fpo);
	return (ret);
}

/*
 * This function is a callback and it declares what other functions
 * should be called for request processing and configuration requests.
 * This callback function declares the Handlers for other events.
 */
static void mod_custauth_register_hooks (apr_pool_t *p)
{
	// I think this is the call to make to register a handler for method calls (GET PUT et. al.).
	// We will ask to be last so that the comment has a higher tendency to
	// go at the end.
	ap_hook_handler(mod_custauth_basic_auth_handler, NULL, NULL, APR_HOOK_FIRST);
}
/**
 * This function is called when the "ModCustAuth2String" configuration directive is parsed.
 */
static const char *set_modcustauth_command_string(cmd_parms *parms, void *mconfig, const char *arg)
{
	// get the module configuration (this is the structure created by create_modcustauth_config())
	modcustauth_config *s_cfg = ap_get_module_config(parms->server->module_config, &custauth_module);

	// make a duplicate of the argument's value using the command parameters pool.
	s_cfg->command_string = (char *) arg;

	// success
	return NULL;
}

/**
 * A declaration of the configuration directives that are supported by this module.
 */
static const command_rec mod_custauth_cmds[] =
{
	AP_INIT_TAKE1(
		"ModuleCustAuthCommandString",
		set_modcustauth_command_string,
		NULL,
		RSRC_CONF,
		"ModCustAuthCommandString <string> -- the command (script) to pass authentication details to."
	),
	{NULL}
};

/**
 * Creates the per-server configuration records.
 */
static void *create_modcustauth_config(apr_pool_t *p, server_rec *s)
{
	modcustauth_config *newcfg;

	// allocate space for the configuration structure from the provided pool p.
	newcfg = (modcustauth_config *) apr_pcalloc(p, sizeof(modcustauth_config));

	// set the default value for the error string.
	newcfg->string = DEFAULT_MODTUT2_STRING;

	// return the new server configuration structure.
	return (void *) newcfg;
}

/*
 * Declare and populate the module's data structure.  The
 * name of this structure ('custauth_module') is important - it
 * must match the name of the module.  This structure is the
 * only "glue" between the httpd core and the module.
 */
module AP_MODULE_DECLARE_DATA custauth_module =
{
	STANDARD20_MODULE_STUFF, // standard stuff; no need to mess with this.
	NULL, // create per-directory configuration structures - we do not.
	NULL, // merge per-directory - no need to merge if we are not creating anything.
	create_modcustauth_config, // create per-server configuration structures.
	NULL, // merge per-server - hrm - examples I have been reading don't bother with this for trivial cases.
	mod_custauth_cmds, // configuration directive handlers
	mod_custauth_register_hooks, // request handlers
};
