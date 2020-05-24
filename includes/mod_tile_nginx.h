//
//  mod_tile_nginx.h
//  ngx_http_mod_tile_module
//
//  Created by Артём Оконечников on 23.05.2020.
//  Copyright © 2020 Артём Оконечников. All rights reserved.
//

#ifndef mod_tile_nginx_h
#define mod_tile_nginx_h

static char * ngx_mod_tile_socket_address(ngx_conf_t * cf, void * post, void * data);
static void * ngx_http_mod_tile_create_conf(ngx_conf_t * cf);

typedef struct
{
    /*
     * Turn mod_tile enable
     */
    ngx_flag_t enable;
    
    /*
     * Set name of tile cache directory
     */
    ngx_str_t tile_dir;
    
    /*
     * Set name of unix domain socket for connecting to rendering daemon
     */
    ngx_str_t renderd_socket_name;
    
    /*
     * Set renderd socket port
     */
    ngx_int_t renderd_socket_port;
    
    /*
     * Set timeout in seconds on mod_tile requests
     */
    ngx_int_t request_timeout;
    
    /*
     * Set timeout in seconds on missing mod_tile requests
     */
    ngx_int_t request_timeout_priority;
    
} tile_server_conf;

#endif /* mod_tile_nginx_h */
