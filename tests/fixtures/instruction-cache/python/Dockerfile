FROM alpine
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN printf 'IC_EXEC_%s\n' dependencies; cat /app/requirements.txt > /app/installed.txt; head -c 32 /dev/urandom | od -An -tx1 > /app/dependency-nonce
COPY app.py /app/app.py
RUN printf 'IC_EXEC_%s\n' application; cat /app/installed.txt /app/app.py > /app/result; head -c 32 /dev/urandom | od -An -tx1 > /app/application-nonce
CMD ["python", "/app/app.py"]
