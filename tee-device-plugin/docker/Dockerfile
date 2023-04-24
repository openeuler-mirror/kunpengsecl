FROM ubuntu:18.04

RUN mkdir -p /usr/lib64 && \
    mkdir -p /vendor/bin && \
    mkdir -p /data

# copy binaries
COPY --chown=644:root *.so* /usr/lib64/
RUN ln -sf /usr/lib64/* /lib/aarch64-linux-gnu/

# copy program
COPY --chown=755:root tlogcat /usr/bin/
COPY --chown=755:root tee-device-plugin /vendor/bin/
COPY --chown=600:root *.sec /data/

CMD ["/vendor/bin/tee-device-plugin"]
