FROM ubuntu:24.04
RUN apt-get update && apt-get install -y hello python3-venv
RUN python3 -m venv /opt/venv
WORKDIR /app
ENV WELD_TEST=ubuntu24-fd1024
COPY app.py /app/app.py
RUN /opt/venv/bin/python /app/app.py
CMD ["/opt/venv/bin/python", "/app/app.py"]
