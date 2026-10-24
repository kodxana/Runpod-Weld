ARG BASE
FROM ${BASE} AS producer
COPY input.txt /source.txt
RUN mkdir /out && cp /source.txt /out/artifact && printf 'private\n' > /stage-only
FROM scratch
COPY --from=producer /out/artifact /artifact
CMD ["/artifact"]
