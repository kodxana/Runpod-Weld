FROM ubuntu:24.04 AS dependencies
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y hello python3-venv
RUN python3 -m venv /opt/venv

FROM dependencies AS builder
WORKDIR /src
COPY app.py /src/app.py
RUN /opt/venv/bin/python -m py_compile /src/app.py

FROM dependencies AS runtime
WORKDIR /app
COPY --from=builder /src/app.py /app/app.py
ENV WELD_TEST=multi-stage
CMD ["/opt/venv/bin/python", "/app/app.py"]
