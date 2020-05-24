//
//  mod_tile_nginx.c
//  mod_tile
//
//  Created by Артём Оконечников on 23.05.2020.
//  Copyright © 2020 Артём Оконечников. All rights reserved.
//

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "mod_tile_nginx.h"

#define MODULE_NAME ngx_string("ngx_http_mod_tile_module")

static ngx_conf_post_t ngx_mod_tile_socket_address_post = {
    ngx_mod_tile_socket_address
};

static ngx_command_t ngx_mod_tile_commands[] =
{
    // Specify the default base storage path for where tiles live.
    //
    // The file based storage uses a simple file path as its storage path ( /path/to/tiledir )
    // The RADOS based storage takes a location to the rados config file and a pool name ( rados://poolname/path/to/ceph.conf )
    // The memcached based storage currently has no configuration options and always connects to memcached on localhost ( memcached:// )
    //
    // The storage path can be overwritten on a style by style basis from the style TileConfigFile
    {
        ngx_string("mod_tile_tile_dir"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(tile_server_conf, tile_dir),
        NULL
    },
    
    // Unix domain socket where we connect to the rendering daemon
    {
        ngx_string("mod_tile_renderd_socket_name"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(tile_server_conf, renderd_socket_name),
        NULL
    },
    
    // Alternatively you can use a TCP socket to connect to renderd. The first part
    // is the location of the renderd server and the second is the port to connect to.
    {
        ngx_string("mod_tile_renderd_socket_address"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(tile_server_conf, renderd_socket_name),
        &ngx_mod_tile_socket_address_post
    },
    
    // Timeout before giving up for a tile to be rendered
    {
        ngx_string("mod_tile_request_timeout"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(tile_server_conf, request_timeout),
        NULL
    },
    
    // Timeout before giving up for a tile to be rendered that is otherwise missing
    {
        ngx_string("mod_tile_missing_request_timeout"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(tile_server_conf, request_timeout_priority),
        NULL
    },
    
    // Turn mod tile on/off
    {
        ngx_string("mod_tile_enable"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(tile_server_conf, enable),
        NULL
    },
    
    ngx_null_command
};

static ngx_http_module_t ngx_mod_tile_module_ctx =
{
    NULL,                                /* preconfiguration */
    NULL,                                /* postconfiguration */

    NULL,                                /* create main configuration */
    NULL,                                /* init main configuration */

    NULL,                                /* create server configuration */
    NULL,                                /* merge server configuration */

    ngx_http_mod_tile_create_conf,       /* create location configuration */
    NULL                                 /* merge location configuration */
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

static void * ngx_http_mod_tile_create_conf(ngx_conf_t *cf)
{
    tile_server_conf  * conf;

    conf = ngx_pcalloc(cf->pool, sizeof(tile_server_conf));
    if (conf == NULL) {
        return NULL;
    }
    
    conf->enable = NGX_CONF_UNSET;
    conf->renderd_socket_port = NGX_CONF_UNSET;
    conf->request_timeout = NGX_CONF_UNSET;
    conf->request_timeout_priority = NGX_CONF_UNSET;

    return conf;
}

static char * ngx_mod_tile_socket_address(ngx_conf_t * cf, void * post, void * data)
{
    ngx_str_t * str = data;
    if (str == 0)
        return NGX_CONF_OK;
    
    ngx_log_error(NGX_LOG_NOTICE, cf -> log, 0, "Use renderd TCP address");
    
    // scanf data
    
    return NGX_CONF_OK;
}
