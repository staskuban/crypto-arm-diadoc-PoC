# Based on upstream docker/Dockerfile of https://git.digtlab.ru/trusted/cryptoarm/server
# (commit af98d55e1974b87275b7fef97a20a6c32fb6f63b). Local changes, marked "local:":
#   - an empty TRUSTED_LICENSE logs a warning instead of aborting the start chain, so
#     CSP setup and key install still run and the real error comes from the server
#     ("Trusted Crypto license is invalid", verified 2026-09-24: no signing without it);
#   - TRUSTED_LICENSE / CRYPTOPRO_LICENSE default to "" because the server's
#     isValidEnv() exits when they are unset.
FROM registry.digtlab.ru/trusted/cryptoarm/server:latest

ADD cryptopro /tmp/src
RUN cd /tmp/src && \
    tar -xf linux-amd64_deb.tgz && \
    linux-amd64_deb/install.sh && \
    cd linux-amd64_deb && \
    dpkg -i `ls | grep cprocsp-pki-cades` && \
    cd /bin && \
    ln -s /opt/cprocsp/sbin/amd64/cpconfig && \
    rm -rf /tmp/src

# local: optional TRUSTED_LICENSE, see header.
COPY setup-trusted-license-optional.sh /usr/local/bin/setup-trusted-license-optional
RUN chmod 0755 /usr/local/bin/setup-trusted-license-optional
ENV TRUSTED_LICENSE="" CRYPTOPRO_LICENSE=""

RUN mkdir -p /var/opt/cprocsp_default && cp -r /var/opt/cprocsp/* /var/opt/cprocsp_default/

CMD sh -c '\
    if [ -z "$(ls -A /var/opt/cprocsp/ 2>/dev/null)" ]; then \
        cp -r /var/opt/cprocsp_default/* /var/opt/cprocsp/; \
    fi && \
    /cryptopro/scripts/setup_license "$CRYPTOPRO_LICENSE" && \
    /cryptopro/scripts/setup_tsp_license "$CRYPTOPRO_TSP_LICENSE" && \
    /cryptopro/scripts/setup_ocsp_license "$CRYPTOPRO_OCSP_LICENSE" && \
    /usr/local/bin/setup-trusted-license-optional "$TRUSTED_LICENSE" && \

    if [ -d /certs/root ] && [ -n "$(find /certs/root -maxdepth 1 -type f -name "*.cer" 2>/dev/null | head -1)" ]; then \
        find /certs/root -maxdepth 1 -type f -name "*.cer" -exec /opt/cprocsp/bin/amd64/certmgr -install -all -store mroot -file {} \; 2>/dev/null || true; \
    fi && \
    if [ -d /certs/user ] && [ -n "$(find /certs/user -maxdepth 1 -type f \( -name "*.pfx" -o -name "*.p12" \) 2>/dev/null | head -1)" ]; then \
        find /certs/user -maxdepth 1 -type f \( -name "*.pfx" -o -name "*.p12" \) -exec /opt/cprocsp/bin/amd64/certmgr -inst -all -store uMy -file {} -pfx -silent \; 2>/dev/null || true; \
    fi && \

    if [ -n "$ROOT_CERTS_BASE64" ]; then \
        echo "$ROOT_CERTS_BASE64" | tr "," "\n" | while IFS= read -r cert_b64; do \
            [ -n "$cert_b64" ] && { \
                cert_file="/tmp/root_cert_$$.cer"; \
                echo "$cert_b64" | base64 -d > "$cert_file" 2>/dev/null; \
                [ -f "$cert_file" ] && [ -s "$cert_file" ] && \
                    /opt/cprocsp/bin/amd64/certmgr -install -all -store mroot -file "$cert_file" 2>/dev/null || true; \
                rm -f "$cert_file"; \
            }; \
        done; \
    fi && \
    if [ -n "$CERT_PFX_BASE64" ]; then \
        idx=0; \
        echo "$CERT_PFX_BASE64" | tr "," "\n" | while read pfx_b64; do \
            [ -n "$pfx_b64" ] && { \
                pfx_file="/tmp/cert_$$_${idx}.pfx"; \
                echo "$pfx_b64" | base64 -d > "$pfx_file" 2>/dev/null; \
                pin=""; \
                [ -n "$CERT_PFX_PIN" ] && pin=$(echo "$CERT_PFX_PIN" | cut -d"," -f$((idx+1))); \
                [ -n "$CERT_PFX_PIN" ] && [ -z "$(echo "$CERT_PFX_PIN" | grep ",")" ] && pin="$CERT_PFX_PIN"; \
                if [ -f "$pfx_file" ] && [ -s "$pfx_file" ]; then \
                    if [ -n "$pin" ]; then \
                        /opt/cprocsp/bin/amd64/certmgr -inst -all -store uMy -file "$pfx_file" -pfx -silent -pin "$pin" 2>/dev/null || true; \
                    else \
                        /opt/cprocsp/bin/amd64/certmgr -inst -all -store uMy -file "$pfx_file" -pfx -silent 2>/dev/null || true; \
                    fi; \
                fi; \
                rm -f "$pfx_file"; \
                idx=$((idx+1)); \
            }; \
        done; \
    fi && \
    npm start'