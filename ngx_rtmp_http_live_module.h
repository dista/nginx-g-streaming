#ifndef _NGX_RTMP_HTTP_LIVE_H_INCLUDED_
#define _NGX_RTMP_HTTP_LIVE_H_INCLUDED_

#include <ngx_http.h>
#include "ngx_rtmp.h"

typedef struct ngx_http_rtmp_live_stream_s ngx_http_rtmp_live_stream_t;
typedef struct ngx_http_rtmp_live_play_ctx_s ngx_http_rtmp_live_play_ctx_t;
typedef struct ngx_rtmp_http_live_ctx_s ngx_rtmp_http_live_ctx_t;

typedef struct {
    ngx_str_t app;
    ngx_str_t stream;
} ngx_http_rtmp_live_play_req_t;

typedef struct {
    uint32_t                   tag_type;
    uint32_t                   timestamp;
    unsigned                   active:1;
    unsigned                   sqh_sent:1;
} ngx_http_rtmp_live_tag_stream_t;

typedef struct ngx_http_rtmp_live_packet_s {
    ngx_rtmp_header_t header;
    ngx_chain_t      *body;
} ngx_http_rtmp_live_packet_t;

#define NGX_HTTP_RTMP_LIVE_CACHE_SIZE 1024

typedef struct ngx_http_rtmp_live_cache_s {
    ngx_http_rtmp_live_packet_t   pkts[NGX_HTTP_RTMP_LIVE_CACHE_SIZE];
    int                           pos;
    int                           last;
    int                           play_pos;
} ngx_http_rtmp_live_cache_t;

struct ngx_http_rtmp_live_stream_s {
    u_char                            app[NGX_RTMP_MAX_NAME];
                                      /* stream name */
    u_char                            name[NGX_RTMP_MAX_NAME];

    ngx_http_rtmp_live_stream_t      *next;

    ngx_rtmp_session_t               *session;
    ngx_rtmp_session_t               *publisher;

    ngx_http_rtmp_live_play_ctx_t    *http_players;

    ngx_rtmp_core_srv_conf_t         *cscf;

    ngx_chain_t                      *flv_header;

    ngx_chain_t                      *meta;

    ngx_uint_t                        meta_version;

    ngx_http_rtmp_live_cache_t        cache;

    unsigned                          played:1;
    unsigned                          has_video:1;
    unsigned                          has_audio:1;
};

typedef struct {
    size_t                         out_count;
    size_t                         out_queue;
    size_t                         out_pos;
    size_t                         out_last;
    ngx_chain_t                  **out;

    ngx_chain_t                   *free;
    ngx_chain_t                   *busy;
} ngx_rtmp_shared_send_chain_ctx_t;

struct ngx_http_rtmp_live_play_ctx_s {
    ngx_http_request_t               *r;
    ngx_http_rtmp_live_stream_t      *stream;
    ngx_http_rtmp_live_play_ctx_t    *next;

    ngx_rtmp_shared_send_chain_ctx_t *chain_ctx;

    uint32_t                          prev_tag_size;

    ngx_uint_t                        meta_version;

    /* ts[0] for video, ts[1] for audio */
    ngx_http_rtmp_live_tag_stream_t   ts[2];

    unsigned                          flv_header_sent:1;
    unsigned                          cache_sent:1;
};

struct ngx_rtmp_http_live_ctx_s {
    ngx_http_rtmp_live_stream_t   *stream;
    unsigned publishing:1;
};

typedef struct {
    ngx_str_t                      http_rtmp_live_dst;
    ngx_flag_t                     http_rtmp_live;
    ngx_pool_t                    *pool;
} ngx_http_rtmp_live_loc_conf_t;

typedef struct {
    ngx_str_t    http_live_src;
} ngx_rtmp_http_live_srv_conf_t;

typedef struct {
    ngx_flag_t   live;
    ngx_flag_t   interleave;
    ngx_flag_t   wait_key;
    ngx_flag_t   wait_video;
    ngx_flag_t   cache;
    ngx_int_t    nbuckets;
    ngx_log_t   *log;
    ngx_pool_t  *pool;

    ngx_http_rtmp_live_stream_t  **streams;
    ngx_http_rtmp_live_stream_t   *free_streams;
} ngx_rtmp_http_live_app_conf_t;


#endif
