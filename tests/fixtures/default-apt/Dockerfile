ARG BASE
FROM ${BASE}
RUN apt-get update && apt-get install -y --no-install-recommends hello && hello > /hello-output && apt-get remove -y hello && ! command -v hello && rm -rf /var/lib/apt/lists/*
RUN printf 'default apt install and removal succeeded\n' > /apt-proof
CMD ["/bin/cat", "/apt-proof"]
