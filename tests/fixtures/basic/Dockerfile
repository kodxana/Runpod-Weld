ARG BASE
FROM ${BASE}
ARG MESSAGE=hello
ENV WELD_MESSAGE=${MESSAGE}
WORKDIR /weld
COPY input.txt /weld/input.txt
COPY . /weld/context/
RUN printf '%s\n' "$WELD_MESSAGE" > result.txt && test ! -e context/ignored.txt
CMD ["/bin/cat", "/weld/result.txt"]
