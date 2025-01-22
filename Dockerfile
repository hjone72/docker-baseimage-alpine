# syntax=docker/dockerfile:1

FROM alpine:3.20 AS rootfs-stage

# environment
ENV ROOTFS=/root-out
ENV REL=v3.21
ENV ARCH=x86_64
ENV MIRROR=http://dl-cdn.alpinelinux.org/alpine
ENV PACKAGES=alpine-baselayout,alpine-keys,apk-tools,busybox,libc-utils

# install packages
RUN \
  apk add --no-cache \
  bash \
  xz

# build rootfs
RUN \
  mkdir -p "$ROOTFS/etc/apk" && \
  { \
  echo "$MIRROR/$REL/main"; \
  echo "$MIRROR/$REL/community"; \
  } > "$ROOTFS/etc/apk/repositories" && \
  apk --root "$ROOTFS" --no-cache --keys-dir /etc/apk/keys add --arch $ARCH --initdb ${PACKAGES//,/ } && \
  sed -i -e 's/^root::/root:!:/' /root-out/etc/shadow

# set version for s6 overlay
ARG S6_OVERLAY_VERSION="3.2.0.2"
ARG S6_OVERLAY_ARCH="x86_64"

# add s6 overlay
ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz /tmp
RUN tar -C /root-out -Jxpf /tmp/s6-overlay-noarch.tar.xz
ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-${S6_OVERLAY_ARCH}.tar.xz /tmp
RUN tar -C /root-out -Jxpf /tmp/s6-overlay-${S6_OVERLAY_ARCH}.tar.xz

# add s6 optional symlinks
ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-symlinks-noarch.tar.xz /tmp
RUN tar -C /root-out -Jxpf /tmp/s6-overlay-symlinks-noarch.tar.xz && unlink /root-out/usr/bin/with-contenv
ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-symlinks-arch.tar.xz /tmp
RUN tar -C /root-out -Jxpf /tmp/s6-overlay-symlinks-arch.tar.xz

# Runtime stage
FROM scratch
COPY --from=rootfs-stage /root-out/ /
ARG BUILD_DATE
ARG VERSION
ARG MODS_VERSION="v3"
ARG PKG_INST_VERSION="v1"
ARG LSIOWN_VERSION="v1"
ARG WITHCONTENV_VERSION="v1"
LABEL build_version="Linuxserver.io version:- ${VERSION} Build-date:- ${BUILD_DATE}"
LABEL maintainer="TheLamer"

ADD --chmod=755 "https://raw.githubusercontent.com/linuxserver/docker-mods/mod-scripts/docker-mods.${MODS_VERSION}" "/docker-mods"
ADD --chmod=755 "https://raw.githubusercontent.com/linuxserver/docker-mods/mod-scripts/package-install.${PKG_INST_VERSION}" "/etc/s6-overlay/s6-rc.d/init-mods-package-install/run"
ADD --chmod=755 "https://raw.githubusercontent.com/linuxserver/docker-mods/mod-scripts/lsiown.${LSIOWN_VERSION}" "/usr/bin/lsiown"
ADD --chmod=755 "https://raw.githubusercontent.com/linuxserver/docker-mods/mod-scripts/with-contenv.${WITHCONTENV_VERSION}" "/usr/bin/with-contenv"

# environment variables
ENV PS1="$(whoami)@$(hostname):$(pwd)\\$ " \
  HOME="/root" \
  TERM="xterm" \
  S6_CMD_WAIT_FOR_SERVICES_MAXTIME="0" \
  S6_VERBOSITY=1 \
  S6_STAGE2_HOOK=/docker-mods \
  VIRTUAL_ENV=/lsiopy \
  PATH="/lsiopy/bin:$PATH"

# Docker Build Arguments
ARG RESTY_IMAGE_BASE="alpine"
ARG RESTY_IMAGE_TAG="3.21"
ARG RESTY_VERSION="1.27.1.1"

# https://github.com/openresty/openresty-packaging/blob/master/alpine/openresty-openssl3/APKBUILD
ARG RESTY_OPENSSL_VERSION="3.0.15"
ARG RESTY_OPENSSL_PATCH_VERSION="3.0.15"
ARG RESTY_OPENSSL_URL_BASE="https://github.com/openssl/openssl/releases/download/openssl-${RESTY_OPENSSL_VERSION}"
# LEGACY:  "https://www.openssl.org/source/old/1.1.1"
ARG RESTY_OPENSSL_BUILD_OPTIONS="enable-camellia enable-seed enable-rfc3779 enable-cms enable-md2 enable-rc5 \
  enable-weak-ssl-ciphers enable-ssl3 enable-ssl3-method enable-md2 enable-ktls enable-fips \
  "

# https://github.com/openresty/openresty-packaging/blob/master/alpine/openresty-pcre2/APKBUILD
ARG RESTY_PCRE_VERSION="10.44"
ARG RESTY_PCRE_SHA256="86b9cb0aa3bcb7994faa88018292bc704cdbb708e785f7c74352ff6ea7d3175b"
ARG RESTY_PCRE_BUILD_OPTIONS="--enable-jit --enable-pcre2grep-jit --disable-bsr-anycrlf --disable-coverage --disable-ebcdic --disable-fuzz-support \
  --disable-jit-sealloc --disable-never-backslash-C --enable-newline-is-lf --enable-pcre2-8 --enable-pcre2-16 --enable-pcre2-32 \
  --enable-pcre2grep-callout --enable-pcre2grep-callout-fork --disable-pcre2grep-libbz2 --disable-pcre2grep-libz --disable-pcre2test-libedit \
  --enable-percent-zt --disable-rebuild-chartables --enable-shared --disable-static --disable-silent-rules --enable-unicode --disable-valgrind \
  "

ARG RESTY_J="1"

# https://github.com/openresty/openresty-packaging/blob/master/alpine/openresty/APKBUILD
ARG RESTY_CONFIG_OPTIONS="\
  --with-compat \
  --without-http_rds_json_module \
  --without-http_rds_csv_module \
  --without-lua_rds_parser \
  --without-mail_pop3_module \
  --without-mail_imap_module \
  --without-mail_smtp_module \
  --with-http_addition_module \
  --with-http_auth_request_module \
  --with-http_dav_module \
  --with-http_flv_module \
  --with-http_geoip_module=dynamic \
  --with-http_gunzip_module \
  --with-http_gzip_static_module \
  --with-http_image_filter_module=dynamic \
  --with-http_mp4_module \
  --with-http_random_index_module \
  --with-http_realip_module \
  --with-http_secure_link_module \
  --with-http_slice_module \
  --with-http_ssl_module \
  --with-http_stub_status_module \
  --with-http_sub_module \
  --with-http_v2_module \
  --with-http_v3_module \
  --with-http_xslt_module=dynamic \
  --with-ipv6 \
  --with-mail \
  --with-mail_ssl_module \
  --with-md5-asm \
  --with-sha1-asm \
  --with-stream \
  --with-stream_ssl_module \
  --with-stream_ssl_preread_module \
  --with-threads \
  "
ARG RESTY_CONFIG_OPTIONS_MORE=""
ARG RESTY_LUAJIT_OPTIONS="--with-luajit-xcflags='-DLUAJIT_NUMMODE=2 -DLUAJIT_ENABLE_LUA52COMPAT'"
ARG RESTY_PCRE_OPTIONS="--with-pcre-jit"

ARG RESTY_ADD_PACKAGE_BUILDDEPS=""
ARG RESTY_ADD_PACKAGE_RUNDEPS=""
ARG RESTY_EVAL_PRE_CONFIGURE=""
ARG RESTY_EVAL_POST_DOWNLOAD_PRE_CONFIGURE=""
ARG RESTY_EVAL_POST_MAKE=""

# These are not intended to be user-specified
ARG _RESTY_CONFIG_DEPS="--with-pcre \
  --with-cc-opt='-DNGX_LUA_ABORT_AT_PANIC -I/usr/local/openresty/pcre2/include -I/usr/local/openresty/openssl3/include' \
  --with-ld-opt='-L/usr/local/openresty/pcre2/lib -L/usr/local/openresty/openssl3/lib -Wl,-rpath,/usr/local/openresty/pcre2/lib:/usr/local/openresty/openssl3/lib' \
  "

LABEL resty_image_base="${RESTY_IMAGE_BASE}"
LABEL resty_image_tag="${RESTY_IMAGE_TAG}"
LABEL resty_version="${RESTY_VERSION}"
LABEL resty_openssl_version="${RESTY_OPENSSL_VERSION}"
LABEL resty_openssl_patch_version="${RESTY_OPENSSL_PATCH_VERSION}"
LABEL resty_openssl_url_base="${RESTY_OPENSSL_URL_BASE}"
LABEL resty_openssl_build_options="${RESTY_OPENSSL_BUILD_OPTIONS}"
LABEL resty_pcre_version="${RESTY_PCRE_VERSION}"
LABEL resty_pcre_build_options="${RESTY_PCRE_BUILD_OPTIONS}"
LABEL resty_pcre_sha256="${RESTY_PCRE_SHA256}"
LABEL resty_config_options="${RESTY_CONFIG_OPTIONS}"
LABEL resty_config_options_more="${RESTY_CONFIG_OPTIONS_MORE}"
LABEL resty_config_deps="${_RESTY_CONFIG_DEPS}"
LABEL resty_add_package_builddeps="${RESTY_ADD_PACKAGE_BUILDDEPS}"
LABEL resty_add_package_rundeps="${RESTY_ADD_PACKAGE_RUNDEPS}"
LABEL resty_eval_pre_configure="${RESTY_EVAL_PRE_CONFIGURE}"
LABEL resty_eval_post_download_pre_configure="${RESTY_EVAL_POST_DOWNLOAD_PRE_CONFIGURE}"
LABEL resty_eval_post_make="${RESTY_EVAL_POST_MAKE}"
LABEL resty_luajit_options="${RESTY_LUAJIT_OPTIONS}"
LABEL resty_pcre_options="${RESTY_PCRE_OPTIONS}"

RUN \
  echo "**** install temp packages ****" && \
  apk add --no-cache --virtual .build-deps \
  build-base \
  coreutils \
  curl \
  gd-dev \
  geoip-dev \
  libxslt-dev \
  linux-headers \
  make \
  perl-dev \
  readline-dev \
  zlib-dev \
  ${RESTY_ADD_PACKAGE_BUILDDEPS} && \
  echo "**** install runtime packages ****" && \
  apk add --no-cache \
  alpine-release \
  bash \
  ca-certificates \
  catatonit \
  coreutils \
  curl \
  findutils \
  jq \
  netcat-openbsd \
  procps-ng \
  shadow \
  tzdata \
  gd \
  geoip \
  libgcc \
  libxslt \
  tzdata \
  zlib \
  ${RESTY_ADD_PACKAGE_RUNDEPS} \
  && cd /tmp \
  && if [ -n "${RESTY_EVAL_PRE_CONFIGURE}" ]; then eval $(echo ${RESTY_EVAL_PRE_CONFIGURE}); fi \
  && cd /tmp \
  && curl -fSL "${RESTY_OPENSSL_URL_BASE}/openssl-${RESTY_OPENSSL_VERSION}.tar.gz" -o openssl-${RESTY_OPENSSL_VERSION}.tar.gz \
  && tar xzf openssl-${RESTY_OPENSSL_VERSION}.tar.gz \
  && cd openssl-${RESTY_OPENSSL_VERSION} \
  && if [ $(echo ${RESTY_OPENSSL_VERSION} | cut -c 1-5) = "3.0.15" ] ; then \
  echo 'patching OpenSSL 3.0.15 for OpenResty' \
  && curl -s https://raw.githubusercontent.com/openresty/openresty/master/patches/openssl-${RESTY_OPENSSL_PATCH_VERSION}-sess_set_get_cb_yield.patch | patch -p1 ; \
  fi \
  && if [ $(echo ${RESTY_OPENSSL_VERSION} | cut -c 1-5) = "1.1.1" ] ; then \
  echo 'patching OpenSSL 1.1.1 for OpenResty' \
  && curl -s https://raw.githubusercontent.com/openresty/openresty/master/patches/openssl-${RESTY_OPENSSL_PATCH_VERSION}-sess_set_get_cb_yield.patch | patch -p1 ; \
  fi \
  && if [ $(echo ${RESTY_OPENSSL_VERSION} | cut -c 1-5) = "1.1.0" ] ; then \
  echo 'patching OpenSSL 1.1.0 for OpenResty' \
  && curl -s https://raw.githubusercontent.com/openresty/openresty/ed328977028c3ec3033bc25873ee360056e247cd/patches/openssl-1.1.0j-parallel_build_fix.patch | patch -p1 \
  && curl -s https://raw.githubusercontent.com/openresty/openresty/master/patches/openssl-${RESTY_OPENSSL_PATCH_VERSION}-sess_set_get_cb_yield.patch | patch -p1 ; \
  fi \
  && ./config \
  shared zlib -g \
  --prefix=/usr/local/openresty/openssl3 \
  --libdir=lib \
  -Wl,-rpath,/usr/local/openresty/openssl3/lib \
  ${RESTY_OPENSSL_BUILD_OPTIONS} \
  && echo 'line 227' \
  && make -j${RESTY_J} \
  && make -j${RESTY_J} install_sw \
  && echo 'line 230' \
  && cd /tmp \
  && curl -fSL "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${RESTY_PCRE_VERSION}/pcre2-${RESTY_PCRE_VERSION}.tar.gz" -o pcre2-${RESTY_PCRE_VERSION}.tar.gz \
  && echo "${RESTY_PCRE_SHA256}  pcre2-${RESTY_PCRE_VERSION}.tar.gz" | shasum -a 256 --check \
  && tar xzf pcre2-${RESTY_PCRE_VERSION}.tar.gz \
  && cd /tmp/pcre2-${RESTY_PCRE_VERSION} \
  && echo 'line 236' \
  && CFLAGS="-g -O3" ./configure \
  --prefix=/usr/local/openresty/pcre2 \
  --libdir=/usr/local/openresty/pcre2/lib \
  ${RESTY_PCRE_BUILD_OPTIONS} \
  && CFLAGS="-g -O3" make -j${RESTY_J} \
  && CFLAGS="-g -O3" make -j${RESTY_J} install \
  && echo 'line 243' \
  && cd /tmp \
  && curl -fSL https://openresty.org/download/openresty-${RESTY_VERSION}.tar.gz -o openresty-${RESTY_VERSION}.tar.gz \
  && tar xzf openresty-${RESTY_VERSION}.tar.gz \
  && cd /tmp/openresty-${RESTY_VERSION} \
  && if [ -n "${RESTY_EVAL_POST_DOWNLOAD_PRE_CONFIGURE}" ]; then eval $(echo ${RESTY_EVAL_POST_DOWNLOAD_PRE_CONFIGURE}); fi \
  && eval ./configure -j${RESTY_J} ${_RESTY_CONFIG_DEPS} ${RESTY_CONFIG_OPTIONS} ${RESTY_CONFIG_OPTIONS_MORE} ${RESTY_LUAJIT_OPTIONS} ${RESTY_PCRE_OPTIONS} \
  && echo 'line 250' \
  && make -j${RESTY_J} \
  && make -j${RESTY_J} install \
  && cd /tmp \
  && if [ -n "${RESTY_EVAL_POST_MAKE}" ]; then eval $(echo ${RESTY_EVAL_POST_MAKE}); fi \
  && echo 'line 255' \
  && rm -rf \
  openssl-${RESTY_OPENSSL_VERSION}.tar.gz openssl-${RESTY_OPENSSL_VERSION} \
  pcre2-${RESTY_PCRE_VERSION}.tar.gz pcre2-${RESTY_PCRE_VERSION} \
  openresty-${RESTY_VERSION}.tar.gz openresty-${RESTY_VERSION} \
  && echo 'line 260' \
  && apk del .build-deps \
  && mkdir -p /var/run/openresty && \
  echo "**** create abc user and make our folders ****" && \
  groupmod -g 1000 users && \
  useradd -u 911 -U -d /config -s /bin/false abc && \
  usermod -G users abc && \
  mkdir -p \
  /app \
  /config \
  /defaults \
  /lsiopy && \
  echo "**** cleanup ****" && \
  rm -rf \
  /tmp/*

RUN apk add --no-cache \
  gd \
  geoip \
  libgcc \
  libxslt \
  tzdata \
  zlib \
  ${RESTY_ADD_PACKAGE_RUNDEPS} \
  && cd /tmp \
  && if [ -n "${RESTY_EVAL_PRE_CONFIGURE}" ]; then eval $(echo ${RESTY_EVAL_PRE_CONFIGURE}); fi \
  && cd /tmp \
  && curl -fSL "${RESTY_OPENSSL_URL_BASE}/openssl-${RESTY_OPENSSL_VERSION}.tar.gz" -o openssl-${RESTY_OPENSSL_VERSION}.tar.gz \
  && tar xzf openssl-${RESTY_OPENSSL_VERSION}.tar.gz \
  && cd openssl-${RESTY_OPENSSL_VERSION} \
  && if [ $(echo ${RESTY_OPENSSL_VERSION} | cut -c 1-5) = "3.0.15" ] ; then \
  echo 'patching OpenSSL 3.0.15 for OpenResty' \
  && curl -s https://raw.githubusercontent.com/openresty/openresty/master/patches/openssl-${RESTY_OPENSSL_PATCH_VERSION}-sess_set_get_cb_yield.patch | patch -p1 ; \
  fi \
  && if [ $(echo ${RESTY_OPENSSL_VERSION} | cut -c 1-5) = "1.1.1" ] ; then \
  echo 'patching OpenSSL 1.1.1 for OpenResty' \
  && curl -s https://raw.githubusercontent.com/openresty/openresty/master/patches/openssl-${RESTY_OPENSSL_PATCH_VERSION}-sess_set_get_cb_yield.patch | patch -p1 ; \
  fi \
  && if [ $(echo ${RESTY_OPENSSL_VERSION} | cut -c 1-5) = "1.1.0" ] ; then \
  echo 'patching OpenSSL 1.1.0 for OpenResty' \
  && curl -s https://raw.githubusercontent.com/openresty/openresty/ed328977028c3ec3033bc25873ee360056e247cd/patches/openssl-1.1.0j-parallel_build_fix.patch | patch -p1 \
  && curl -s https://raw.githubusercontent.com/openresty/openresty/master/patches/openssl-${RESTY_OPENSSL_PATCH_VERSION}-sess_set_get_cb_yield.patch | patch -p1 ; \
  fi \
  && ./config \
  shared zlib -g \
  --prefix=/usr/local/openresty/openssl3 \
  --libdir=lib \
  -Wl,-rpath,/usr/local/openresty/openssl3/lib \
  ${RESTY_OPENSSL_BUILD_OPTIONS} \
  && make -j${RESTY_J} \
  && make -j${RESTY_J} install_sw \
  && cd /tmp \
  && curl -fSL "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${RESTY_PCRE_VERSION}/pcre2-${RESTY_PCRE_VERSION}.tar.gz" -o pcre2-${RESTY_PCRE_VERSION}.tar.gz \
  && echo "${RESTY_PCRE_SHA256}  pcre2-${RESTY_PCRE_VERSION}.tar.gz" | shasum -a 256 --check \
  && tar xzf pcre2-${RESTY_PCRE_VERSION}.tar.gz \
  && cd /tmp/pcre2-${RESTY_PCRE_VERSION} \
  && CFLAGS="-g -O3" ./configure \
  --prefix=/usr/local/openresty/pcre2 \
  --libdir=/usr/local/openresty/pcre2/lib \
  ${RESTY_PCRE_BUILD_OPTIONS} \
  && CFLAGS="-g -O3" make -j${RESTY_J} \
  && CFLAGS="-g -O3" make -j${RESTY_J} install \
  && cd /tmp \
  && curl -fSL https://openresty.org/download/openresty-${RESTY_VERSION}.tar.gz -o openresty-${RESTY_VERSION}.tar.gz \
  && tar xzf openresty-${RESTY_VERSION}.tar.gz \
  && cd /tmp/openresty-${RESTY_VERSION} \
  && if [ -n "${RESTY_EVAL_POST_DOWNLOAD_PRE_CONFIGURE}" ]; then eval $(echo ${RESTY_EVAL_POST_DOWNLOAD_PRE_CONFIGURE}); fi \
  && eval ./configure -j${RESTY_J} ${_RESTY_CONFIG_DEPS} ${RESTY_CONFIG_OPTIONS} ${RESTY_CONFIG_OPTIONS_MORE} ${RESTY_LUAJIT_OPTIONS} ${RESTY_PCRE_OPTIONS} \
  && make -j${RESTY_J} \
  && make -j${RESTY_J} install \
  && cd /tmp \
  && if [ -n "${RESTY_EVAL_POST_MAKE}" ]; then eval $(echo ${RESTY_EVAL_POST_MAKE}); fi \
  && rm -rf \
  openssl-${RESTY_OPENSSL_VERSION}.tar.gz openssl-${RESTY_OPENSSL_VERSION} \
  pcre2-${RESTY_PCRE_VERSION}.tar.gz pcre2-${RESTY_PCRE_VERSION} \
  openresty-${RESTY_VERSION}.tar.gz openresty-${RESTY_VERSION} \
  && apk del .build-deps \
  && mkdir -p /var/run/openresty
#    && ln -sf /usr/local/openresty/bin/openresty /usr/sbin/nginx
#    && ln -sf /dev/stdout /usr/local/openresty/nginx/logs/access.log \
#    && ln -sf /dev/stderr /usr/local/openresty/nginx/logs/error.log

# Add additional binaries into PATH for convenience
ENV PATH=$PATH:/usr/local/openresty/luajit/bin:/usr/local/openresty/nginx/sbin:/usr/local/openresty/bin

# add local files
COPY root/ /

ENTRYPOINT ["/init"]
