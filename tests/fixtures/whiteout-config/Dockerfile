ARG BASE
FROM ${BASE}
RUN mkdir -p /weld/tree && printf 'old\n' > /weld/tree/old && printf 'gone\n' > /weld/deleted && printf 'old\n' > /weld/recreated
RUN rm -rf /weld/tree /weld/deleted /weld/recreated && mkdir /weld/tree && printf 'new\n' > /weld/tree/new && printf 'replacement\n' > /weld/recreated
ENV WELD_CONFIG=preserved
WORKDIR /weld
LABEL org.runpod.weld.fixture=whiteout-config
EXPOSE 8080/tcp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/bin/cat"]
CMD ["/weld/recreated"]
