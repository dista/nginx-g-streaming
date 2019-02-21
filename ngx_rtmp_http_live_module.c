
/*
 * Copyright (C) dista
 */


#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_http_live_module.h"
#include "ngx_rtmp_codec_module.h"


/* flv header plus previous tag size */
#define FLV_HEADER_PLUS_PTS_SIZE 13
#define FLV_TAG_HEADER_SIZE 11

static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_close_stream_pt         next_close_stream;

static ngx_int_t ngx_rtmp_http_live_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_http_live_create_srv_conf(ngx_conf_t *cf);
static void * ngx_rtmp_http_live_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_http_live_merge_app_conf(ngx_conf_t *cf, 
    void *parent, void *child);
static ngx_int_t ngx_http_rtmp_live_postconfiguration(ngx_conf_t *cf);
static void * ngx_http_rtmp_live_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_rtmp_live_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_rtmp_live_handler(ngx_http_request_t *r);
static ngx_http_rtmp_live_play_req_t * ngx_http_rtmp_live_parse_url(
    ngx_http_request_t *r);
static ngx_http_rtmp_live_stream_t **ngx_rtmp_http_live_join_stream_play(
    ngx_rtmp_http_live_app_conf_t *lacf, ngx_str_t *name, ngx_rtmp_conf_ctx_t *cctx);
static ngx_http_rtmp_live_stream_t **ngx_rtmp_http_live_get_stream(
    ngx_rtmp_http_live_app_conf_t *lacf, ngx_str_t *name, ngx_int_t create);
static ngx_int_t ngx_rtmp_http_live_play_local(ngx_rtmp_session_t *s, u_char *name);
static ngx_int_t ngx_rtmp_http_live_send(ngx_http_rtmp_live_play_ctx_t *play,
    ngx_chain_t *in, ngx_uint_t priority);
static void ngx_rtmp_http_live_build_header(u_char *header, size_t header_size,
    int has_video, int has_audio);

static ngx_command_t ngx_rtmp_http_live_commands[] = {
    { ngx_string("http_live_src"),
      NGX_RTMP_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_http_live_srv_conf_t, http_live_src),
      NULL },

    { ngx_string("http_live"),
      NGX_RTMP_MAIN_CONF | NGX_RTMP_SRV_CONF | NGX_RTMP_APP_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_http_live_app_conf_t, live),
      NULL },

    { ngx_string("http_wait_key"),
      NGX_RTMP_MAIN_CONF | NGX_RTMP_SRV_CONF | NGX_RTMP_APP_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_http_live_app_conf_t, wait_key),
      NULL },

    { ngx_string("http_wait_video"),
      NGX_RTMP_MAIN_CONF | NGX_RTMP_SRV_CONF | NGX_RTMP_APP_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_http_live_app_conf_t, wait_video),
      NULL },

    { ngx_string("http_live_buckets"),
      NGX_RTMP_MAIN_CONF | NGX_RTMP_SRV_CONF | NGX_RTMP_APP_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_http_live_app_conf_t, nbuckets),
      NULL },

    ngx_null_command
};

static ngx_rtmp_module_t  ngx_rtmp_http_live_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_http_live_postconfiguration,   /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    ngx_rtmp_http_live_create_srv_conf,     /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_http_live_create_app_conf,     /* create app configuration */
    ngx_rtmp_http_live_merge_app_conf,      /* merge app configuration */
};


ngx_module_t  ngx_rtmp_http_live_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_http_live_module_ctx,         /* module context */
    ngx_rtmp_http_live_commands,            /* module directives */
    NGX_RTMP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_command_t ngx_http_rtmp_live_commands[] = {
    { ngx_string("http_rtmp_live_dst"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_rtmp_live_loc_conf_t, http_rtmp_live_dst),
        NULL },
    { ngx_string("http_rtmp_live"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_rtmp_live_loc_conf_t, http_rtmp_live),
        NULL },
    ngx_null_command
};

static ngx_rtmp_module_t ngx_http_rtmp_live_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_rtmp_live_postconfiguration,   /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_http_rtmp_live_create_loc_conf,     /* create location configuration */
    ngx_http_rtmp_live_merge_loc_conf,      /* merge location configuration */
};

ngx_module_t ngx_http_rtmp_live_module = {
    NGX_MODULE_V1,
    &ngx_http_rtmp_live_module_ctx,          /* module context */
    ngx_http_rtmp_live_commands,             /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};

static void * 
ngx_rtmp_http_live_create_srv_conf(ngx_conf_t *cf)
{
    ngx_rtmp_http_live_srv_conf_t   *lscf;

    lscf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_http_live_srv_conf_t));
    if (lscf == NULL) {
        return NULL;
    }

    return lscf;
}

static void * 
ngx_rtmp_http_live_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_http_live_app_conf_t   *lacf;

    lacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_http_live_app_conf_t));
    if (lacf == NULL) {
        return NULL;
    }

    lacf->live = NGX_CONF_UNSET;
    lacf->nbuckets = NGX_CONF_UNSET;
    lacf->wait_key = NGX_CONF_UNSET;
    lacf->wait_video = NGX_CONF_UNSET;

    lacf->log = &cf->cycle->new_log;

    return lacf;
}

static char * 
ngx_rtmp_http_live_merge_app_conf(ngx_conf_t *cf, 
        void *parent, void *child)
{
    ngx_rtmp_http_live_app_conf_t   *prev = parent;
    ngx_rtmp_http_live_app_conf_t   *conf = child;

    ngx_conf_merge_value(conf->live, prev->live, 0);
    ngx_conf_merge_value(conf->nbuckets, prev->nbuckets, 1024);
    ngx_conf_merge_value(conf->wait_key, prev->wait_key, 1);
    ngx_conf_merge_value(conf->wait_video, prev->wait_video, 0);

    conf->pool = ngx_create_pool(4096, &cf->cycle->new_log);
    if (conf->pool == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->streams = ngx_pcalloc(conf->pool, 
                                conf->nbuckets * sizeof(ngx_http_rtmp_live_stream_t *));

    if (conf->streams == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static void
ngx_http_rtmp_cleanup_handler(void *data)
{
    ngx_http_rtmp_live_play_ctx_t    *ctx, **l;
    ngx_http_rtmp_live_stream_t      *stream;
    ngx_rtmp_shared_send_chain_ctx_t *chain_ctx;
    ngx_rtmp_core_srv_conf_t         *cscf;

    ctx = data;
    chain_ctx = ctx->chain_ctx;
    stream = ctx->stream;
    cscf = stream->cscf;

    while (chain_ctx->out_pos != chain_ctx->out_last) {
        ngx_rtmp_free_shared_chain(cscf, chain_ctx->out[chain_ctx->out_pos++]);
        chain_ctx->out_pos %= chain_ctx->out_queue;
    }

    l = &stream->http_players;

    // remove it from list
    for (; *l; l = &((*l)->next)) {
        if (*l == ctx) {
            *l = ctx->next;
            ctx->next = NULL;

            break;
        }
    }

    // no clients
    if (stream->http_players == NULL) {
        // destroy the only rtmp play session
        if (stream->session != NULL) {
            ngx_rtmp_finalize_session(stream->session);
        }
    }
}

static void
ngx_http_rtmp_live_write_handler(ngx_http_request_t *r)
{
    ngx_http_rtmp_live_play_ctx_t      *play;
    ngx_event_t                        *wev;
    ngx_connection_t                   *c;

    c = r->connection;
    wev = c->write;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "client timed out");

        c->timedout = 1;

        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    play = ngx_http_get_module_ctx(r, ngx_http_rtmp_live_module);

    ngx_rtmp_http_live_send(play, NULL, 0);
}

static ngx_int_t
ngx_http_rtmp_live_handler(ngx_http_request_t *r)
{
    ngx_int_t                             i;
    ngx_http_rtmp_live_loc_conf_t        *hlcf;
    ngx_http_rtmp_live_play_req_t        *play;
    ngx_rtmp_core_main_conf_t            *cmcf;
    ngx_rtmp_core_srv_conf_t            **pcscf, *cscf;
    ngx_rtmp_core_app_conf_t            **pcacf, *cacf;
    ngx_rtmp_http_live_srv_conf_t        *lscf;
    ngx_rtmp_http_live_app_conf_t        *lacf;
    ngx_http_rtmp_live_play_ctx_t        *ctx;
    ngx_http_rtmp_live_stream_t         **stream;
    ngx_rtmp_conf_ctx_t                   cctx;
    ngx_rtmp_shared_send_chain_ctx_t     *chain_ctx;
    ngx_pool_cleanup_t                   *cln;
    ngx_int_t                             rc;
    ngx_http_core_loc_conf_t             *clcf;
    ngx_event_t                          *wev;

    wev = r->connection->write;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_rtmp_live_module);
    if (ctx != NULL) {
        return NGX_AGAIN;
    }

    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_rtmp_live_module);

    /* not enabled, skip this module, go next one */
    if (!hlcf->http_rtmp_live) {
        return NGX_DECLINED;
    }

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    /* find the server block in rtmp */
    cmcf = ngx_rtmp_core_main_conf;

    /* rtmp is not enabled */
    if (cmcf == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }

    pcscf = cmcf->servers.elts;
    cscf = NULL;
    for (i = 0; i < (ngx_int_t)cmcf->servers.nelts; i++, pcscf++) {
        lscf = ngx_rtmp_conf_get_module_srv_conf((*pcscf), ngx_rtmp_http_live_module);

        if (lscf != NULL) {
            if (hlcf->http_rtmp_live_dst.len == lscf->http_live_src.len &&
                ngx_strncmp(hlcf->http_rtmp_live_dst.data, lscf->http_live_src.data,
                    hlcf->http_rtmp_live_dst.len) == 0) 
            {
                cscf = *pcscf;
                break;
            }
        }
    }

    if (cscf == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }

#if 0
    /* we do not care about the request body*/
    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }
#endif

    /* get app name, stream name etc */
    play = ngx_http_rtmp_live_parse_url(r);

    if (play == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }

    /* find application */
    pcacf = cscf->applications.elts;
    cacf = NULL;
    for (i = 0; i < (ngx_int_t)cscf->applications.nelts; i++, pcacf++) {
        if (play->app.len == (*pcacf)->name.len &&
            ngx_strncmp(play->app.data, (*pcacf)->name.data, play->app.len) == 0) 
        {
            cacf = *pcacf;
            break;
        }
    }

    if (cacf == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }

    cctx = *(cscf->ctx);
    cctx.app_conf = cacf->app_conf;

    lacf = ngx_rtmp_get_module_app_conf(cacf, ngx_rtmp_http_live_module);

    if (lacf == NULL || lacf->live == 0) {
        return NGX_HTTP_NOT_FOUND;
    }


    /* bypass rtmp_live module
     * create a rtmp session, unset live module app conf
     * call ngx_rtmp_play to call all modules with a play command
     *
     * all client request the same stream share one rtmp session
     */
    stream = ngx_rtmp_http_live_join_stream_play(lacf, &play->stream, &cctx);
    if (stream == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }

    if (!(*stream)->played) {
        if (ngx_rtmp_http_live_play_local((*stream)->session, (*stream)->name) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        (*stream)->played = 1;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_rtmp_live_play_ctx_t));
    if (ctx == NULL) {
        // TODO: free stream, ... resource
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    chain_ctx = ngx_pcalloc(r->pool, sizeof(ngx_rtmp_shared_send_chain_ctx_t));
    if (chain_ctx == NULL) {
        // TODO: free stream, ... resource
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    chain_ctx->out_queue = 1024;
    chain_ctx->out = ngx_pcalloc(r->pool, chain_ctx->out_queue * sizeof(ngx_chain_t *));
    if (chain_ctx->out == NULL) {
        // TODO: free stream, ... resource
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->chain_ctx = chain_ctx;
    ctx->r = r;
    ctx->stream = *stream;

    if ((*stream)->http_players == NULL) {
        (*stream)->http_players = ctx;
    } else {
        ctx->next = (*stream)->http_players;
        (*stream)->http_players = ctx;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_rtmp_live_module);

    r->read_event_handler = ngx_http_test_reading;
    r->write_event_handler = ngx_http_rtmp_live_write_handler;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (!wev->delayed) {
        ngx_add_timer(wev, clcf->send_timeout);
    }

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cln = ngx_pool_cleanup_add(r->pool, 0);
    cln->data = ctx;
    cln->handler = ngx_http_rtmp_cleanup_handler;

    r->headers_out.status = NGX_HTTP_OK;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    return NGX_AGAIN;
}

static void
ngx_rtmp_update_chains_and_shared_pkt(ngx_pool_t *p, ngx_rtmp_core_srv_conf_t *cscf, 
        ngx_rtmp_shared_send_chain_ctx_t *chain_ctx, ngx_chain_t **out){
    ngx_chain_t               **free;
    ngx_chain_t               **busy;
    ngx_chain_t                *pkt, *cl;
    size_t                     count;
    ngx_uint_t                  nmsg;

    count = 0;

    free = &chain_ctx->free;
    busy = &chain_ctx->busy;

    if (*out) {
        if (*busy == NULL) {
            *busy = *out;

        } else {
            for (cl = *busy; cl->next; cl = cl->next) { /* void */ }

            cl->next = *out;
        }

        *out = NULL;
    }

    while (*busy) {
        cl = *busy;

        if (ngx_buf_size(cl->buf) != 0) {
            break;
        }

        chain_ctx->out_count++;

        cl->buf->pos = cl->buf->start;
        cl->buf->last = cl->buf->start;

        *busy = cl->next;
        cl->next = *free;
        *free = cl;
    }

    for (;;) {
        nmsg = (chain_ctx->out_last - chain_ctx->out_pos) % chain_ctx->out_queue;

        if (nmsg == 0) {
            // out_count should be 0
            break;
        }

        pkt = chain_ctx->out[chain_ctx->out_pos];

        count = 0;
        for (cl = pkt; cl; cl = cl->next) {
            count++;
        }

        if (count <= chain_ctx->out_count) {
            chain_ctx->out_count -= count;

            ngx_rtmp_free_shared_chain(cscf, pkt);

            chain_ctx->out_pos++;
            chain_ctx->out_pos %= chain_ctx->out_queue;
        } else {
            break;
        }
    }
}

static ngx_int_t
ngx_rtmp_http_live_send(ngx_http_rtmp_live_play_ctx_t *play, ngx_chain_t *in,
        ngx_uint_t priority)
{
    ngx_uint_t                            nmsg;
    ngx_http_request_t                   *r;
    ngx_int_t                             rc;
    ngx_chain_t                          *ln, *out, **ll;
    ngx_chain_t                          *chain;
    ngx_buf_t                            *b;
    ngx_rtmp_shared_send_chain_ctx_t     *chain_ctx;
    ngx_rtmp_core_srv_conf_t             *cscf;
    ngx_http_core_loc_conf_t             *clcf;
    ngx_event_t                          *wev;

    r = play->r;
    chain_ctx = play->chain_ctx;
    wev = r->connection->write;

    cscf = play->stream->cscf;

    if (in != NULL) {
        nmsg = (chain_ctx->out_last - chain_ctx->out_pos) % chain_ctx->out_queue + 1;

        if (priority > 3) {
            priority = 3;
        }

        if (nmsg + priority * chain_ctx->out_queue / 4 >= chain_ctx->out_queue) {
            return NGX_AGAIN;
        }

        chain_ctx->out[chain_ctx->out_last++] = in;
        chain_ctx->out_last %= chain_ctx->out_queue;

        ngx_rtmp_acquire_shared_chain(in);
    }

    out = NULL;
    ll = &out;

    for (ln = in; ln; ln = ln->next) {
        chain = ngx_chain_get_free_buf(r->pool, &chain_ctx->free);

        b = chain->buf; 

        ngx_memzero(b, sizeof(ngx_buf_t));

        b->temporary = 1;
        b->tag = (ngx_buf_tag_t)&ngx_rtmp_http_live_send;
        b->start = ln->buf->start;
        b->pos = ln->buf->pos;
        b->last = ln->buf->last;
        b->end = ln->buf->end;

        *ll = chain;
        ll = &chain->next;
    }

    rc = ngx_http_output_filter(r, out);

    if (rc == NGX_ERROR) {
        /* TODO: handle error */
        ngx_http_finalize_request(r, rc);
        return NGX_ERROR;
    }

    ngx_rtmp_update_chains_and_shared_pkt(r->pool, cscf, play->chain_ctx, &out);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (!wev->delayed) {
        ngx_add_timer(wev, clcf->send_timeout);
    }

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_http_finalize_request(r, 0);
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void
ngx_rtmp_http_live_build_header(u_char *header, size_t header_size, 
    int has_video, int has_audio)
{
    ngx_memzero(header, header_size);

    header[0] = (u_char)'F';
    header[1] = (u_char)'L';
    header[2] = (u_char)'V';
    header[3] = 1; /*version 1*/
    header[4] = (u_char)(has_video | (has_audio << 2));
    header[8] = 9;
}

static void
ngx_rtmp_http_prepare_packet(ngx_rtmp_session_t *s,
                             uint32_t tag_type, 
                             uint32_t timestamp, 
                             ngx_chain_t *pkt)
{
    ngx_rtmp_core_srv_conf_t   *cscf;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    /*
     * tag type                1 byte
     * data size               3 bytes
     * timestamp               3 bytes
     * timestamp ext           1 byte
     * stream id               3 bytes
     * --------------------------
     * FLV_TAG_HEADER_SIZE  = 11 bytes
     */

    ngx_chain_t      *cl, ncl;
    ngx_buf_t        *buf;
    off_t             size;
    ngx_buf_t         b;
    u_char            prev_tag_size[4], *p;

    size = 0;
    for (cl = pkt; cl; cl = cl->next) {
        size += ngx_buf_size(cl->buf);
    }

    buf = pkt->buf;

    buf->pos -= FLV_TAG_HEADER_SIZE;

    /* set to zero */
    ngx_memzero(buf->pos, FLV_TAG_HEADER_SIZE);

    buf->pos[0] = tag_type & 0xFF;
    buf->pos[1] = (size >> 16) & 0xFF;
    buf->pos[2] = (size >> 8) & 0xFF;
    buf->pos[3] = size & 0xFF;
    buf->pos[4] = (timestamp >> 16) & 0xFF;
    buf->pos[5] = (timestamp >> 8) & 0xFF;
    buf->pos[6] = timestamp & 0xFF;
    buf->pos[7] = (timestamp >> 24) & 0xFF;

    /*8 - 10 is zero*/

    /* append previous tag size */
    ncl.next = NULL;
    ncl.buf = &b;

    b.start = prev_tag_size;
    b.end = prev_tag_size + 4;
    b.pos = b.start;
    b.last = b.end;

    p = b.pos;
    size += FLV_TAG_HEADER_SIZE;
    *p++ = (size >> 24) & 0xFF;
    *p++ = (size >> 16) & 0xFF;
    *p++ = (size >> 8) & 0xFF;
    *p = size & 0xFF;

    ngx_rtmp_append_shared_bufs(cscf, pkt, &ncl);
}

static ngx_chain_t *
ngx_rtmp_http_live_from_raw_meta(ngx_rtmp_session_t *s,
        ngx_chain_t *in) {
    ngx_chain_t              *meta;
    ngx_rtmp_core_srv_conf_t *cscf;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    meta = ngx_rtmp_append_shared_bufs(cscf, NULL, in);

    ngx_rtmp_http_prepare_packet(s, NGX_RTMP_MSG_AMF_META, 0, meta);

    return meta;
}

static ngx_int_t
ngx_rtmp_http_live_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                 ngx_chain_t *in)
{
    ngx_rtmp_http_live_app_conf_t     *lacf;
    ngx_rtmp_http_live_ctx_t          *ctx;
    ngx_rtmp_core_srv_conf_t          *cscf;
    ngx_rtmp_codec_ctx_t              *codec_ctx;
    ngx_chain_t                        tmp, *pkt, *hpkt, *flv_header, *meta,
                                      *header;
    ngx_buf_t                          buf;
    ngx_http_rtmp_live_stream_t       *stream;
    ngx_http_rtmp_live_play_ctx_t     *pctx;
    u_char                             tmp_header[FLV_HEADER_PLUS_PTS_SIZE];
    ngx_int_t                          mandatory;
    ngx_uint_t                         prio;
    ngx_uint_t                         tsid;
    ngx_uint_t                         meta_version;
    ngx_http_rtmp_live_tag_stream_t   *ts;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_http_live_module);
    if (lacf == NULL) {
        return NGX_ERROR;
    }

    if (!lacf->live || in == NULL  || in->buf == NULL) {
        return NGX_OK;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_http_live_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    if(ctx->publishing == 0) {
        return NGX_OK;
    }

    pkt = NULL;
    hpkt = NULL;
    flv_header = NULL;
    header = NULL;
    meta = NULL;
    meta_version = 0;
    mandatory = 0;

    prio = (h->type == NGX_RTMP_MSG_VIDEO ?
            ngx_rtmp_get_video_frame_type(in) : 0);

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    tsid = !(h->type == NGX_RTMP_MSG_VIDEO);

    pkt = ngx_rtmp_append_shared_bufs(cscf, NULL, in);
    ngx_rtmp_http_prepare_packet(s, h->type, h->timestamp, pkt);

    stream = ctx->stream;
    if (stream == NULL) {
        return NGX_OK;
    }

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (codec_ctx) {
        if (h->type == NGX_RTMP_MSG_AUDIO) {
            header = codec_ctx->aac_header;

            if (codec_ctx->audio_codec_id == NGX_RTMP_AUDIO_AAC &&
                ngx_rtmp_is_codec_header(in))
            {
                prio = 0;
                mandatory = 1;
            }

        } else {
            header = codec_ctx->avc_header;

            if (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264 &&
                ngx_rtmp_is_codec_header(in))
            {
                prio = 0;
                mandatory = 1;
            }
        }

        if (codec_ctx->meta) {
            if (stream->meta_version != codec_ctx->meta_version) {
                if (stream->meta) {
                    ngx_rtmp_free_shared_chain(cscf, stream->meta);
                    stream->meta = NULL;
                }

                /* remove rtmp header*/
                stream->meta = ngx_rtmp_http_live_from_raw_meta(s, codec_ctx->raw_meta);
                stream->meta_version = codec_ctx->meta_version;
            }

            meta = stream->meta;
            meta_version = stream->meta_version;
        }
    }

    if (stream->flv_header == NULL) {
        stream->has_audio = 1;
        stream->has_video = 1;
        ngx_rtmp_http_live_build_header(tmp_header, sizeof(tmp_header), 
            stream->has_video, stream->has_audio);

        buf.start = tmp_header;
        buf.pos = buf.start;
        buf.end = tmp_header + sizeof(tmp_header);
        buf.last = buf.end;
        tmp.buf = &buf;
        tmp.next = NULL;

        flv_header = ngx_rtmp_append_shared_bufs(cscf, NULL, &tmp);

        if (stream->flv_header != NULL) {
            ngx_rtmp_free_shared_chain(cscf, stream->flv_header);
        }

        stream->flv_header = flv_header;
    }

    for (pctx = stream->http_players; pctx; pctx = pctx->next){

        ts = &pctx->ts[tsid];

        if (!pctx->flv_header_sent) {
            if (ngx_rtmp_http_live_send(pctx, stream->flv_header, 0) == NGX_OK) {
                pctx->flv_header_sent = 1;
            }
        }

        if (meta && meta_version != pctx->meta_version) {
            if (ngx_rtmp_http_live_send(pctx, meta, 0) == NGX_OK) {
                pctx->meta_version = meta_version;
            }
        }

        if (!ts->active) {
            if (mandatory) {
                continue;
            }

            if (lacf->wait_video && h->type == NGX_RTMP_MSG_AUDIO &&
                !pctx->ts[0].active) {
                continue;
            }

            if (lacf->wait_key && prio != NGX_RTMP_VIDEO_KEY_FRAME &&
               (h->type == NGX_RTMP_MSG_VIDEO))
            {
                continue;
            }

            if (!header) {
                continue;
            }

            if (hpkt == NULL) {
                hpkt = ngx_rtmp_append_shared_bufs(cscf, NULL, header);
                ngx_rtmp_http_prepare_packet(s, h->type, h->timestamp, hpkt);
            }

            if (ngx_rtmp_http_live_send(pctx, hpkt, 0) != NGX_OK) {
                continue;
            }

            ts->active = 1;
        }

        if (ngx_rtmp_http_live_send(pctx, pkt, prio) != NGX_OK) {
            continue;
        }

        ts->timestamp = h->timestamp;
    }

    if (pkt) {
        ngx_rtmp_free_shared_chain(cscf, pkt);
    }

    if (hpkt) {
        ngx_rtmp_free_shared_chain(cscf, hpkt);
    }

    return NGX_OK;
}


static ngx_http_rtmp_live_play_req_t *
ngx_http_rtmp_live_parse_url(ngx_http_request_t *r)
{
    ngx_http_rtmp_live_play_req_t *req;
    ngx_uint_t                     i;

    req = ngx_pcalloc(r->pool, sizeof(ngx_http_rtmp_live_play_req_t));
    if (req == NULL) {
        return NULL;
    }

    for (i = 1; i < r->uri.len; i++) {
        if (req->app.data == NULL) {
            req->app.data = r->uri.data + i;
        } else if (r->uri.data[i] == '/') {
            if (req->app.len == 0) {
                req->app.len = r->uri.data + i - req->app.data;
                req->stream.data = r->uri.data + i + 1;
            } else {
                /* do not allow stream contains '/' */
                return NULL;
            }
        } else if (r->uri.data[i] == '.') {
            if (req->stream.data == NULL) {
                return NULL;
            }

            req->stream.len = r->uri.data + i - req->stream.data;
            i++;
            break;
        }
    }

    if (req->app.len == 0 || req->stream.len == 0) {
        return NULL;
    }

    /* left flv */
    if (r->uri.len - i != 3 ||
        ngx_strncmp(r->uri.data + i, "flv", 3) != 0) {
        return NULL;
    }

    return req;
}

static ngx_http_rtmp_live_stream_t **
ngx_rtmp_http_live_get_stream(ngx_rtmp_http_live_app_conf_t *lacf,
        ngx_str_t *name, ngx_int_t create)
{
    ngx_http_rtmp_live_stream_t      **stream;
    u_char                            *n;

    stream = &lacf->streams[ngx_hash_key(name->data, name->len) % lacf->nbuckets];

    for (; *stream; stream = &(*stream)->next) {
        n = (*stream)->name;
        if (ngx_strlen(n) == name->len &&
            !ngx_strncmp(n, name->data, name->len)) {
            return stream;
        }
    }

    if (!create) {
        return NULL;
    }

    if (lacf->free_streams) {
        *stream = lacf->free_streams;
        lacf->free_streams = lacf->free_streams->next;
    } else {
        *stream = ngx_pcalloc(lacf->pool, sizeof(ngx_http_rtmp_live_stream_t));

        if (*stream == NULL) {
            return NULL;
        }
    }

    ngx_memzero(*stream, sizeof(ngx_http_rtmp_live_stream_t));
    ngx_memcpy((*stream)->name, name->data, name->len);

    return stream;
}

static ngx_http_rtmp_live_stream_t ** 
ngx_rtmp_http_live_join_stream_play(ngx_rtmp_http_live_app_conf_t *lacf,
    ngx_str_t *name, ngx_rtmp_conf_ctx_t *cctx)
{
    ngx_http_rtmp_live_stream_t      **stream;
    ngx_pool_t                        *pool;
    ngx_connection_t                  *c;
    ngx_rtmp_session_t                *s;
    ngx_rtmp_addr_conf_t              *addr_conf;
    ngx_uint_t                         i;
    ngx_rtmp_http_live_ctx_t          *ctx;
    ngx_rtmp_live_app_conf_t          *pcf;
    ngx_rtmp_core_srv_conf_t          *cscf;
    ngx_log_t                         *log;

    pool = NULL;
    s = NULL;

    stream = ngx_rtmp_http_live_get_stream(lacf, name, 1);

    if (stream == NULL) {
        return NULL;
    }

    if ((*stream)->session != NULL) {
        return stream;
    }

    /* create session */
    pool = ngx_create_pool(4096, lacf->log);
    if (pool == NULL) {
        goto error;
    }

    /* create a fake connection with fake socket fd*/
    c = ngx_get_connection((ngx_socket_t)65536, lacf->log);
    if (c == NULL) {
        goto error;
    }
    // do not close socket fd
    c->shared = 1;
    c->pool = pool;
    pool = NULL;

    log = ngx_palloc(c->pool, sizeof(ngx_log_t));
    if (log == NULL) {
        goto error;
    }

    *log = *lacf->log;

    c->log = log;
    c->pool->log = log;

    addr_conf = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_addr_conf_t));
    if (addr_conf == NULL) {
        goto error;
    }

    addr_conf->ctx = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_conf_ctx_t));
    if (addr_conf->ctx == NULL) {
        goto error;
    }
    addr_conf->ctx->main_conf = cctx->main_conf;
    addr_conf->ctx->srv_conf = cctx->srv_conf;
    ngx_str_set(&addr_conf->addr_text, "httpflv-aggr");

    s = ngx_rtmp_init_session(c, addr_conf);
    if (s == NULL) {
        goto error;
    }

    s->app_conf = ngx_pcalloc(c->pool, sizeof(void **) * ngx_rtmp_max_module);
    if (s->app_conf == NULL) {
        goto error;
    }

    ctx = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_http_live_ctx_t));
    if (ctx == NULL) {
        goto error;
    }

    /* skip live module */
    for (i = 0; i < ngx_rtmp_max_module; i++) {
        if (i != ngx_rtmp_live_module.ctx_index) {
            s->app_conf[i] = cctx->app_conf[i];
        } else {
            pcf = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_live_app_conf_t));
            if (pcf == NULL) {
                goto error;
            }
            /* skip */
            pcf->live = 0;
            s->app_conf[i] = pcf;
        }
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    /* play mode */
    ctx->publishing = 0;
    ctx->stream = *stream;
    ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_http_live_module);
    (*stream)->session = s;
    (*stream)->cscf = cscf;

    return stream;

error:
    if (pool != NULL) {
        ngx_destroy_pool(pool);
    }

    if (s != NULL) {
        ngx_rtmp_finalize_session(s);
    }

    (*stream)->next = lacf->free_streams;
    lacf->free_streams = *stream;
    *stream = NULL;

    return NULL;
}

static void
ngx_rtmp_http_live_free_stream(ngx_rtmp_session_t *s,
    ngx_http_rtmp_live_stream_t *stream)
{
    ngx_rtmp_http_live_app_conf_t     *lacf;
    ngx_str_t                          name;
    ngx_http_rtmp_live_stream_t      **ps;
    ngx_rtmp_core_srv_conf_t          *cscf;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_http_live_module);
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    name.data = stream->name;
    name.len = ngx_strlen(stream->name);

    ps = ngx_rtmp_http_live_get_stream(lacf, &name, 0);
    if (ps == NULL) {
        return;
    }
    *ps = (*ps)->next;


    if (stream->meta != NULL) {
        ngx_rtmp_free_shared_chain(cscf, stream->meta);
        stream->meta = NULL;
        stream->meta_version = 0;
    }

    stream->next = lacf->free_streams;
    lacf->free_streams = stream;
}

static ngx_int_t
ngx_rtmp_http_live_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_http_live_ctx_t       *ctx;
    ngx_http_rtmp_live_stream_t    *stream;
    ngx_rtmp_http_live_app_conf_t  *lacf;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_http_live_module);
    if (lacf == NULL || !lacf->live) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_http_live_module);
    // not our faked rtmp play stream or publish stream
    if (ctx == NULL) {
        goto next;
    }

    stream = NULL;

    if (!ctx->publishing) {
        if (ctx->stream) {
            stream = ctx->stream;
            stream->session = NULL;
            ctx->stream = NULL;
        }
    } else {
        /* remove publish */
        if (ctx->stream) {
            stream = ctx->stream;
            stream->publisher = NULL;
            ctx->stream = NULL;
        }
    }

    if (stream && stream->session == NULL
        && stream->publisher == NULL) {
        ngx_rtmp_http_live_free_stream(s, stream);
    }

next:
    return next_close_stream(s, v);
}

static ngx_int_t
ngx_rtmp_http_live_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_http_live_app_conf_t    *lacf;
    ngx_str_t                         name;
    ngx_http_rtmp_live_stream_t     **stream;
    ngx_rtmp_http_live_ctx_t         *ctx;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_http_live_module);

    if (lacf == NULL || !lacf->live) {
        goto next;
    }

    name.data = v->name;
    name.len = ngx_strlen(v->name);

    stream = ngx_rtmp_http_live_get_stream(lacf, &name, 1);

    if (stream == NULL) {
        /* TODO: check if it works*/
        return NGX_ERROR;
    }

    if ((*stream)->publisher != NULL) {
        /* TODO: already published */
        return NGX_ERROR;
    }

    (*stream)->publisher = s;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_http_live_module);

    if (ctx == NULL) {
        ctx = ngx_palloc(s->connection->pool, sizeof(ngx_rtmp_http_live_ctx_t));
        if (ctx == NULL) {
            /* TODO: should free stream is no player and publish */
            return NGX_ERROR;
        }

        ctx->publishing = 1;
        ctx->stream = *stream;
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_http_live_module);
    }

next:
    return next_publish(s, v);
}

static ngx_int_t
ngx_rtmp_http_live_play_local(ngx_rtmp_session_t *s, u_char *name)
{
    ngx_rtmp_play_t     v;

    ngx_memzero(&v, sizeof(v));

    /* do not output anything */
    v.silent = 1;
    ngx_memcpy(v.name, name, ngx_strlen(name));

    ngx_rtmp_play(s, &v);

    return NGX_OK;
}

static void *
ngx_http_rtmp_live_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_rtmp_live_loc_conf_t     *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_rtmp_live_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->http_rtmp_live = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_rtmp_live_merge_loc_conf(ngx_conf_t *cf,
        void *parent, void *child)
{
    ngx_http_rtmp_live_loc_conf_t     *prev = parent;
    ngx_http_rtmp_live_loc_conf_t     *conf = child;

    ngx_conf_merge_str_value(conf->http_rtmp_live_dst, prev->http_rtmp_live_dst, "");
    ngx_conf_merge_value(conf->http_rtmp_live, prev->http_rtmp_live, 0);

    if (conf->http_rtmp_live && conf->http_rtmp_live_dst.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "http_rtmp_live is set but http_rtmp_live_dst is not set");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_rtmp_live_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_rtmp_live_handler;

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_http_live_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t      *cmcf;
    ngx_rtmp_handler_pt            *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_http_live_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_http_live_av;

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_http_live_publish;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_http_live_close_stream;

    return NGX_OK;
}
