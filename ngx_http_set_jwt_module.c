/*
 * Copyright (C) Sergey Maslov
 */


#include <ngx_http.h>
#include <ndk_set_var.h>
#include <jwt.h>

// Module structures

typedef struct {
    ngx_str_t   key;
    ngx_uint_t  algorithm;
    time_t      expires;
} ngx_http_set_jwt_conf_t;

typedef struct {
    size_t              length;
    unsigned char      *body;
    unsigned char      *last;
} ngx_http_set_jwt_ctx_t;

// Function forward declaration

static void * ngx_http_set_jwt_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_set_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char * ngx_http_set_jwt_key_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_set_jwt(ngx_http_request_t *r, ngx_str_t *res, ngx_http_variable_value_t *v);

static ndk_set_var_t ngx_http_set_jwt_filter = {
    NDK_SET_VAR_VALUE,
    (void *) ngx_http_set_jwt,
    0,
    NULL
};

static ngx_conf_enum_t ngx_http_set_jwt_algorithms[] = {
    { ngx_string("none"), JWT_ALG_NONE },
    { ngx_string("HS256"), JWT_ALG_HS256 },
    { ngx_string("HS384"), JWT_ALG_HS384 },
    { ngx_string("HS512"), JWT_ALG_HS512 },
    { ngx_string("RS256"), JWT_ALG_RS256 },
    { ngx_string("RS384"), JWT_ALG_RS384 },
    { ngx_string("RS512"), JWT_ALG_RS512 },
    { ngx_string("ES256"), JWT_ALG_ES256 },
    { ngx_string("ES384"), JWT_ALG_ES384 },
    { ngx_string("ES512"), JWT_ALG_ES512 },
    { ngx_null_string, 0 }
};

// Directives
static ngx_command_t ngx_http_set_jwt_commands[] = {
    { ngx_string("set_jwt_key"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_set_jwt_conf_t, key),
      NULL },
    { ngx_string("set_jwt_key_file"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_jwt_key_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_set_jwt_conf_t, key),
      NULL },
    { ngx_string("set_jwt"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ndk_set_var_value,
      0,
      0,
      &ngx_http_set_jwt_filter },
    { ngx_string("set_jwt_algorithm"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_set_jwt_conf_t, algorithm),
      &ngx_http_set_jwt_algorithms },
    { ngx_string("set_jwt_expires"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_set_jwt_conf_t, expires),
      NULL },
    ngx_null_command
};

// Module definition

static ngx_http_module_t ngx_http_set_jwt_module_ctx = {
    NULL,                               /* preconfiguration */
    NULL,                               /* postconfiguration */
    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */
    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */
    ngx_http_set_jwt_create_loc_conf,   /* create location configuration */
    ngx_http_set_jwt_merge_loc_conf     /* merge location configuration */
};

ngx_module_t  ngx_http_set_jwt_module = {
    NGX_MODULE_V1,
    &ngx_http_set_jwt_module_ctx,       /* module context */
    ngx_http_set_jwt_commands,          /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};

// Function implementation

// Create location configuration
static void *
ngx_http_set_jwt_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_set_jwt_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_set_jwt_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->algorithm = NGX_CONF_UNSET_UINT;
    conf->expires = NGX_CONF_UNSET;

    return conf;
}

// Merge location configuration
static char *
ngx_http_set_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_set_jwt_conf_t *prev = parent;
    ngx_http_set_jwt_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->key, prev->key, "");
    ngx_conf_merge_uint_value(conf->algorithm, prev->algorithm, JWT_ALG_HS512);

    return NGX_CONF_OK;
}

// set_jwt_key_file config directive callback
static char *
ngx_http_set_jwt_key_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t          *key = conf;
    ngx_str_t          *args = cf->args->elts;
    ngx_fd_t            fd;
    ngx_file_t          file;
    ngx_file_info_t     fi;
    size_t              size;
    ssize_t             n;

    fd = ngx_open_file(args[1].data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                        ngx_open_file_n " \"%s\" failed", args[1].data);
        return NGX_CONF_ERROR;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                        ngx_fd_info_n " \"%s\" failed", args[1].data);
        ngx_close_file(fd);
        return NGX_CONF_ERROR;
    }

    size = ngx_file_size(&fi);
    key->data = ngx_palloc(cf->pool, size);
    if (key->data == NULL) {
        ngx_close_file(fd);
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.fd = fd;
    file.name = args[1];
    file.log = cf->log;

    n = ngx_read_file(&file, key->data, size, 0);
    if (n == NGX_ERROR || (size_t) n != size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                        ngx_read_file_n " \"%s\" failed", args[1].data);
        ngx_close_file(fd);
        return NGX_CONF_ERROR;
    }

    while (size && (*key->data == ' ' || *key->data == '\t' ||
                    *key->data == '\r' || *key->data == '\n'))
    {
        key->data++;
        size--;
    }
    while (size && (key->data[size - 1] == ' '  || key->data[size - 1] == '\t' ||
                    key->data[size - 1] == '\r' || key->data[size - 1] == '\n'))
    {
        size--;
    }
    key->data[size] = '\0';

    key->len = size;
    ngx_close_file(fd);

    return NGX_CONF_OK;
}

ngx_int_t
ngx_http_set_jwt(ngx_http_request_t *r, ngx_str_t *res, ngx_http_variable_value_t *v)
{
    jwt_t*      token;
    char       *token_result;
    u_char     *token_json;
    size_t      token_len;
    time_t      now = ngx_time();
    int         err;

    ngx_http_set_jwt_conf_t *conf;
    conf = ngx_http_get_module_loc_conf(r, ngx_http_set_jwt_module);

    err = jwt_new(&token);
    if (err) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                    "set_jwt jwt_new: %s", strerror(err));
        return NGX_ERROR;
    }

    err = jwt_set_alg(token, conf->algorithm, conf->key.data, conf->key.len);
    if (err) {
        jwt_free(token);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                    "set_jwt jwt_set_alg: %s", strerror(err));
        return NGX_ERROR;
    }

    err = jwt_add_grant_int(token, "iat", now); // Issued at time
    if (err) {
        jwt_free(token);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                    "set_jwt jwt_add_grant_int iat: %s", strerror(err));
        return NGX_ERROR;
    }

    if (conf->expires != NGX_CONF_UNSET && conf->expires > 0) {
        err = jwt_add_grant_int(token, "exp", now + conf->expires); // Expiration time
        if (err) {
            jwt_free(token);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                    "set_jwt jwt_add_grant_int iat: %s", strerror(err));
            return NGX_ERROR;
        }
    }

    token_json = ngx_pnalloc(r->pool, v->len + 1);
    if (token_json == NULL) {
        return NGX_ERROR;
    }

    ngx_cpystrn(token_json, v->data, v->len + 1);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "set_jwt token_json: %s", token_json);

    err = jwt_add_grants_json(token, (char *)token_json);
    if (err) {
        jwt_free(token);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                    "set_jwt jwt_add_grants_json: %s", strerror(err));
        return NGX_ERROR;
    }

    token_result = jwt_encode_str(token);
    jwt_free(token);
    if (token_result == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                    "set_jwt jwt_encode_str: %s", strerror(err));
        return NGX_ERROR;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "set_jwt token_result: %s", token_result);

    token_len = ngx_strlen(token_result);
    res->data = ngx_pnalloc(r->pool, token_len);
    if (res->data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(res->data, token_result, token_len);
    ngx_free(token_result);
    res->len = token_len;

    return NGX_OK;
}
