//
//  mod_tile_nginx.c
//  mod_tile
//
//  Created by Артём Оконечников on 23.05.2020.
//  Copyright © 2020 Артём Оконечников. All rights reserved.
//

#include "render_config.h"

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "config.h"
#include "protocol.h"

typedef ngx_uint_t  apr_uint64_t;
typedef ngx_time_t  apr_time_t;
typedef ngx_array_t apr_array_header_t;

#include "mod_tile.h"
#include "mod_tile_nginx.h"

#define URI_PATTERN "/%99[^/]/%d/%d/%d.%255[a-z]"

static ngx_command_t ngx_mod_tile_commands[] =
{
    // Specify the default base storage path for where tiles live.
    {
        ngx_string("mod_tile_tile_dir"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(mod_tile_server_conf, tile_dir),
        NULL
    },
    
    // Unix domain socket where we connect to the rendering daemon
    {
        ngx_string("mod_tile_renderd_socket_name"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(mod_tile_server_conf, renderd_socket_name),
        NULL
    },
    
    // Alternatively you can use a TCP socket to connect to renderd. The first part
    // is the location of the renderd server and the second is the port to connect to.
    {
        ngx_string("mod_tile_renderd_socket_port"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(mod_tile_server_conf, renderd_socket_port),
        NULL
    },
    
    // Timeout before giving up for a tile to be rendered
    {
        ngx_string("mod_tile_request_timeout"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(mod_tile_server_conf, request_timeout),
        NULL
    },
    
    // Timeout before giving up for a tile to be rendered that is otherwise missing
    {
        ngx_string("mod_tile_missing_request_timeout"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(mod_tile_server_conf, request_timeout_priority),
        NULL
    },
    
    // Turn mod tile on/off
    {
        ngx_string("mod_tile_enable"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(mod_tile_server_conf, enable),
        NULL
    },
    
    ngx_null_command
};

static ngx_http_module_t ngx_mod_tile_module_ctx =
{
    NULL,                                  /* preconfiguration */
    ngx_http_mod_tile_init,                /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_mod_tile_create_conf,         /* create location configuration */
    ngx_http_mod_tile_merge_conf           /* merge location configuration */
};

ngx_module_t ngx_http_mod_tile_module =
{
    NGX_MODULE_V1,
    &ngx_mod_tile_module_ctx,              /* module context */
    ngx_mod_tile_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    
    NGX_MODULE_V1_PADDING
};


/*
 * Initialize configuration (memory allocate)
 */
static void * ngx_http_mod_tile_create_conf(ngx_conf_t * cf)
{
    mod_tile_server_conf  * conf;

    conf = ngx_pcalloc(cf->pool, sizeof(mod_tile_server_conf));
    if (conf == NULL) {
        return NULL;
    }
    
    conf -> enable = NGX_CONF_UNSET;
    conf -> renderd_socket_port = NGX_CONF_UNSET_UINT;
    conf -> request_timeout = NGX_CONF_UNSET_UINT;
    conf -> request_timeout_priority = NGX_CONF_UNSET_UINT;
    
    return conf;
}


/*
 * Configuration merge with locaion section
 * Default values
 */
static char * ngx_http_mod_tile_merge_conf(ngx_conf_t * cf, void * parent, void * child)
{
    mod_tile_server_conf * prev = parent;
    mod_tile_server_conf * conf = child;

    ngx_conf_merge_value  (
        conf -> enable,
        prev -> enable,
        0
    );
    
    ngx_conf_merge_str_value  (
        conf -> tile_dir,
        prev -> tile_dir,
        HASH_PATH
    );
    
    ngx_conf_merge_str_value  (
        conf -> renderd_socket_name,
        prev -> renderd_socket_name,
        RENDER_SOCKET
    );
    
    ngx_conf_merge_uint_value (
        conf -> renderd_socket_port,
        prev -> renderd_socket_port,
        0
    );
    
    ngx_conf_merge_uint_value (
        conf -> request_timeout,
        prev -> request_timeout,
        REQUEST_TIMEOUT
   );
    
    ngx_conf_merge_uint_value (
        conf -> request_timeout_priority,
        prev -> request_timeout_priority,
        REQUEST_TIMEOUT
   );

    return NGX_CONF_OK;
}


/*
 * Initialize module ...
 */
static ngx_int_t ngx_http_mod_tile_init(ngx_conf_t * cf)
 {
    ngx_http_core_main_conf_t * core_conf;
    ngx_http_phase_t * preaccess_phase;
    ngx_http_handler_pt * handler;
    
    core_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    preaccess_phase = &core_conf -> phases[NGX_HTTP_PREACCESS_PHASE];
    handler = ngx_array_push(&(*preaccess_phase).handlers);
    
    if (handler == NULL) {
        return NGX_ERROR;
    }

    *handler = ngx_http_mod_tile_handler;

    return NGX_OK;
}


/*
 *
 */
static ngx_int_t ngx_http_mod_tile_handler(ngx_http_request_t * request)
{
    mod_tile_server_conf * conf;
    tile_request_data * rdata;
    struct protocol * cmd;
    
    conf = ngx_http_get_module_loc_conf(request, ngx_http_mod_tile_module);
    
    if (!conf -> enable) {
        return NGX_DECLINED;
    }
  
    rdata = ngx_pcalloc(request -> pool, sizeof(struct tile_request_data));
    cmd   = ngx_pcalloc(request -> pool, sizeof(struct protocol));
    
    char extension[5];
    char parameters[41];
    
    const int min_segments = 4;
    const int segments = sscanf((const char *) request -> uri.data, URI_PATTERN,
        parameters,
        &(cmd -> z),
        &(cmd -> x),
        &(cmd -> y),
        extension
    );
    
    cmd -> ver = 2;

    if (segments < min_segments)
    {
        ngx_log_error(NGX_LOG_DEBUG_HTTP,
            request -> connection -> log, 0, "tile_translate: Invalid URL %s", request -> uri);

        return NGX_DECLINED;
    }
    
    rdata -> cmd = cmd;
    rdata -> layerNumber = 0;
    rdata -> store = init_storage_backend((const char *) conf -> tile_dir.data);
    
    if (rdata -> store == NULL)
    {
        ngx_log_error(NGX_LOG_ERR,
            request -> connection -> log, 0, "tile_translate: failed to get valid storage backend");

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    struct storage_backend * store = rdata -> store;
    char * buffer;
    const int tile_max = MAX_SIZE;
    char err_msg[PATH_MAX];
    int compressed;
    
    buffer = ngx_pcalloc(request -> pool, tile_max);
    
    if (!buffer)
    {
        ngx_log_error(NGX_LOG_ERR,
            request -> connection -> log, 0, "Failed to alloc buffer");

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    err_msg[0] = 0;

    int lenght = store -> tile_read (
        store,
        "default",       // XML
        cmd -> options,
        cmd -> x,
        cmd -> y,
        cmd -> z,
        buffer,         // MAX_SIZE
        tile_max,       // MAX_SIZE
        &compressed,    // out
        err_msg         // out
    );
    
    if (lenght > 0)
    {
        // TODO: Accept-Encoding
        if (compressed)
        {
            ngx_log_error(NGX_LOG_ERR,
                request -> connection -> log, 0, "Gzip support not implemented");
            
            return NGX_HTTP_NOT_IMPLEMENTED;
        }
        
        return ngx_http_mod_tile_send_file(request, (unsigned char *) buffer, lenght);
    }
   
    return ngx_http_mod_tile_process_request(request, conf);
}

static ngx_int_t ngx_http_mod_tile_send_file(ngx_http_request_t * request, unsigned char * file, int length)
{
    request -> headers_out.status = NGX_HTTP_OK;
    request -> headers_out.content_length_n = length;
    request -> headers_out.content_type_lowcase = (unsigned char *) "image/png";
    
    ngx_int_t result = ngx_http_send_header(request);

    if (result == NGX_ERROR || result > NGX_OK || request -> header_only) {
        return result;
    }
    
    ngx_chain_t out;
    ngx_buf_t * buffer = ngx_calloc_buf(request -> pool);
    
    if (buffer == NULL)
    {
        ngx_log_error(NGX_LOG_ERR,
            request -> connection -> log, 0, "File buffer not allocated nginx");
        
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    buffer -> file = ngx_pcalloc(request -> pool, sizeof(ngx_file_t));
    
    buffer -> file_pos  = 0;
    buffer -> file_last = length;
    buffer -> start = file;
    buffer -> end   = file + length;
    
    buffer -> file -> name = (ngx_str_t)  ngx_string("image.png");
    
    buffer -> pos  = file;
    buffer -> last = file + length;
    
    buffer -> last_buf = (request == request -> main) ? 1: 0;
    buffer -> last_in_chain = 1;

    buffer -> memory = 1;
    
    out.buf  = buffer;
    out.next = NULL;

    return ngx_http_output_filter(request, &out);
}

static ngx_int_t ngx_http_mod_tile_process_request(ngx_http_request_t * request, mod_tile_server_conf * conf)
{
    ngx_int_t rc;
    ngx_buf_t * b;
    ngx_chain_t out;

    /* send header */

    request -> headers_out.status = NGX_HTTP_OK;
    request -> headers_out.content_length_n = request -> uri.len;
    

    rc = ngx_http_send_header(request);

    if (rc == NGX_ERROR || rc > NGX_OK || request -> header_only) {
        return rc;
    }

    b = ngx_calloc_buf(request->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b -> last_buf = (request == request -> main) ? 1: 0;
    b -> last_in_chain = 1;

    b -> memory = 1;

    b -> pos = request -> uri.data;
    b -> last = b -> pos + request->uri.len;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(request, &out);
}
