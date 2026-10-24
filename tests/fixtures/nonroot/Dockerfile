ARG BASE
FROM ${BASE}
RUN mkdir /owned && chown 1234:1234 /owned && printf 'root only\n' > /root-only && chmod 600 /root-only
USER 1234:1234
WORKDIR /owned
RUN test "$(id -u)" = 1234 && test "$(id -g)" = 1234 && ! cat /root-only && printf 'nonroot\n' > proof
USER 0:0
RUN test "$(id -u)" = 0 && test "$(cat /root-only)" = 'root only'
USER 1234:1234
CMD ["/bin/cat", "/owned/proof"]
