FROM alpine
WORKDIR /app
COPY package-lock.json /app/package-lock.json
RUN printf 'IC_EXEC_%s\n' dependencies; mkdir -p /app/node_modules; cp /app/package-lock.json /app/node_modules/installed.json; head -c 32 /dev/urandom | od -An -tx1 > /app/dependency-nonce
COPY index.js /app/index.js
RUN printf 'IC_EXEC_%s\n' application; cat /app/node_modules/installed.json /app/index.js > /app/result; head -c 32 /dev/urandom | od -An -tx1 > /app/application-nonce
CMD ["node", "/app/index.js"]
