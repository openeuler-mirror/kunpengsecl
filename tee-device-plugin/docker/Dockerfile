FROM openeuler-22.03-lts-sp1

RUN mkdir -p /vendor/bin && \
    mkdir -p /data

COPY *.so /usr/lib64/
COPY tlogcat /usr/bin/
COPY --chown=root tee-device-plugin /vendor/bin/
COPY *.sec /data/
COPY entrypoint.sh /

RUN chmod +x /vendor/bin/tee-device-plugin /entrypoint.sh

CMD ["entrypoint.sh"]
