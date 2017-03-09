// Include the required headers from httpd
#include "httpd.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "apr_strings.h"
#include <stdbool.h>

// Define prototypes of our functions in this module
static void register_hooks(apr_pool_t *pool);
static int nudge_handler(request_rec *r);
static void nudge_log(const char* str);
static void nudge_child_init(apr_pool_t *p, server_rec *s);
static apr_status_t nudge_close(void *data);
static void nudge_child_init_connection();

static apr_socket_t *sock = NULL;
static apr_sockaddr_t *addr = NULL;
static apr_time_t last_connection_try = 0;
static bool connected = false;

// TODO put the agent host and port in configuration
// TODO app key ??

// Define our module as an entity and assign a function for registering hooks

module AP_MODULE_DECLARE_DATA nudge_module =
{
STANDARD20_MODULE_STUFF, //
		NULL,            // Per-directory configuration handler
		NULL,            // Merge handler for per-directory configurations
		NULL,            // Per-server configuration handler
		NULL,            // Merge handler for per-server configurations
		NULL,            // Any directives we may have for httpd
		register_hooks   // Our hook registering function
		};

// register_hooks: Adds a hook to the httpd process
static void register_hooks(apr_pool_t *pool)
{
	ap_hook_log_transaction(nudge_handler, NULL, NULL, APR_HOOK_LAST);
	ap_hook_child_init(nudge_child_init, NULL, NULL, APR_HOOK_MIDDLE);
}

static void nudge_child_init(apr_pool_t *pool, server_rec *server)
{
	apr_status_t result;

	result = apr_socket_create(&sock, APR_INET, SOCK_STREAM, APR_PROTO_TCP, pool);
	if (result != APR_SUCCESS)
	{
		sock = NULL;
		nudge_log("nudge_child_init: failed to create socket");
		return;
	}

	result = apr_sockaddr_info_get(&addr, "127.0.0.1", APR_INET, 1025, 0, pool);
	if (result != APR_SUCCESS)
	{
		nudge_log("nudge_child_init: failed to create addr");
		return;
	}

	nudge_child_init_connection();

	apr_pool_cleanup_register(pool, NULL, nudge_close, apr_pool_cleanup_null);
}

static void nudge_child_init_connection()
{
	last_connection_try = apr_time_now();
	apr_status_t result = apr_socket_connect(sock, addr);
	if (result != APR_SUCCESS)
	{
		connected = false;
		nudge_log("nudge_child_init_connection: failed to connect socket");
		return;
	}
	connected = true;
}

/*
 */
static int nudge_handler(request_rec *r)
{
	if (connected)
	{
		apr_time_t start = r->request_time / 1000000;
		apr_time_t end = apr_time_now() / 1000000;
		char* uri = r->uri;
		int status = r->status;
		char* user = r->user;
		char* userip = r->useragent_ip;
		const char* method = r->method;
		char* first_line = r->the_request;
		const char* hostname = r->hostname;
		apr_table_t* headers = r->headers_in;
		const char* ua = apr_table_get(headers, "User-Agent");

		// TODO appkey, query_string ?, request_scheme ?
		char* str = apr_psprintf(r->pool, "{\"request_uri\":\"%s\","
				"\"time_begin\":\"%ld\","
				"\"time_end\":\"%ld\","
				"\"status_code\":\"%d\","
				"\"user\":\"%s\","
				"\"userip\":\"%s\","
				"\"request_method\":\"%s\","
				"\"script_filename\":\"%s\","
				"\"server_name\":\"%s\","
				"\"user_agent\":\"%s\","
				"}\0", uri, start, end, status, user, userip, method, first_line, hostname, ua);
		apr_size_t len = strlen(str) + 1;
		str[len] = '\0';
		apr_status_t result = apr_socket_send(sock, str, &len);
		if (result != APR_SUCCESS || len == 0)
		{
			connected = false;
			nudge_log("nudge_handler: failed to send data");
		}
		else
		{
			nudge_log(str);
		}
	}
	else
	{
		if(apr_time_now() - last_connection_try > 10000000)
		{
			nudge_log("nudge_handler: trying new connection");
			nudge_child_init_connection(r->pool, NULL);
		}
	}
	return DECLINED;
}

static void nudge_log(const char* str)
{
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, str);
}

static apr_status_t nudge_close(void *data)
{
	apr_status_t result = apr_socket_close(sock);
	if (result != APR_SUCCESS)
	{
		nudge_log("failed to close socket at shutdown hook");
	}
	return APR_SUCCESS;
}
