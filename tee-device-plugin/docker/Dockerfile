FROM ubuntu:18.04

RUN mkdir -p /usr/lib64 && \
    mkdir -p /vendor/bin && \
    mkdir -p /data

COPY *.so* /usr/lib64/
COPY tlogcat /usr/bin/
COPY --chown=root tee-device-plugin /vendor/bin/
COPY *.sec /data/

RUN chmod +x /vendor/bin/tee-device-plugin && \
    ln -sf /usr/lib64/* /lib/aarch64-linux-gnu/

CMD ["/vendor/bin/tee-device-plugin"]
