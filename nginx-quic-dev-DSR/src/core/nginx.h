
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGINX_H_INCLUDED_
#define _NGINX_H_INCLUDED_

#define ngx_unlikely(cond) __builtin_expect((cond), 0)
#define ngx_likely(cond)   __builtin_expect(!!(cond), 1)


#define nginx_version      1021003
#define NGINX_VERSION      "1.21.3"
#define NGINX_VER          "nginx/" NGINX_VERSION

#ifdef NGX_BUILD
#define NGINX_VER_BUILD    NGINX_VER " (" NGX_BUILD ")"
#else
#define NGINX_VER_BUILD    NGINX_VER
#endif

#define NGINX_VAR          "NGINX"
#define NGX_OLDPID_EXT     ".oldbin"


#endif /* _NGINX_H_INCLUDED_ */
