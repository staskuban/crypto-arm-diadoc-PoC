# Based on upstream docker/Dockerfile of https://git.digtlab.ru/trusted/cryptoarm/server
# (commit af98d55e1974b87275b7fef97a20a6c32fb6f63b). Local changes, marked "local:":
#   - the base image is pinned by tag and digest (1.4.25 == `latest` on 2026-09-24);
#   - no `# syntax=` line: the builtin BuildKit frontend handles RUN --mount / COPY --chmod, so the
#     build needs no unpinned frontend image;
#   - the CSP distribution is bind-mounted into the install step, so it is in no image layer;
#   - upstream's shell-form CMD is replaced by start.sh (exec-form ENTRYPOINT): secrets from files,
#     certmgr errors logged, the server exec'd as the child of `init` (compose `init: true`);
#   - read-only root filesystem (I6, compose `read_only` + tmpfs): the CSP configuration is copied to
#     /etc/opt/cprocsp_default (start.sh seeds the tmpfs /etc/opt/cprocsp from it) and the server's
#     PKI store cache `cash.json` (opened relative to the working dir /) is a symlink into the tmpfs
#     /var/lib/cryptoarm-server;
#   - TRUSTED_LICENSE / CRYPTOPRO_LICENSE default to "" because the server's
#     isValidEnv() exits when they are unset; LOG_LEVEL defaults to warn,error because the
#     `log` level prints the first 8 characters of the API key on every request.
# local: pinned base image (M7). To upgrade: `docker buildx imagetools inspect <image>:<tag>`,
# replace tag and digest, rebuild, run the smoke and signer integration tests.
FROM registry.digtlab.ru/trusted/cryptoarm/server:1.4.25@sha256:065293ad1cee669b5a90331f6d8d2d22ab19ebe88de21c5f2853cf3f9c1ca741

# local: bind mount instead of ADD, so the tgz never lands in a layer.
RUN --mount=type=bind,source=cryptopro/linux-amd64_deb.tgz,target=/tmp/linux-amd64_deb.tgz \
    mkdir /tmp/src && cd /tmp/src && \
    tar -xf /tmp/linux-amd64_deb.tgz && \
    linux-amd64_deb/install.sh && \
    cd linux-amd64_deb && \
    dpkg -i `ls | grep cprocsp-pki-cades` && \
    cd /bin && \
    ln -s /opt/cprocsp/sbin/amd64/cpconfig && \
    rm -rf /tmp/src

RUN mkdir -p /var/opt/cprocsp_default && cp -r /var/opt/cprocsp/* /var/opt/cprocsp_default/

# local: read-only root filesystem support (I6), see header. Without the tmpfs mounts (older compose
# file) both paths are plain writable dirs of the container layer, as before.
RUN cp -pR /etc/opt/cprocsp /etc/opt/cprocsp_default && \
    mkdir -m 0700 /var/lib/cryptoarm-server && \
    ln -s /var/lib/cryptoarm-server/cash.json /cash.json

# local: entrypoint, see header and start.sh.
COPY --chmod=0755 start.sh /usr/local/bin/cryptoarm-start
ENV TRUSTED_LICENSE="" CRYPTOPRO_LICENSE="" LOG_LEVEL="warn,error"
WORKDIR /
ENTRYPOINT ["/usr/local/bin/cryptoarm-start"]
CMD ["node", "dist/main.js"]
