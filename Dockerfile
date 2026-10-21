# SR203 HTTP/0.9 response-fixing proxy — stdlib only, no dependencies.
FROM python:3.12-slim

# Run as an unprivileged user.
RUN useradd --system --no-create-home --uid 10001 sr203
WORKDIR /app
COPY sr203-proxy.py /app/sr203-proxy.py

USER sr203

# Defaults; override via environment (see docker-compose.yml / .env).
ENV SR203_LISTEN=0.0.0.0:8099 \
    SR203_TARGET=192.168.0.1:80
EXPOSE 8099

# Liveness: can we open the listen port?
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python3 -c "import os,socket; h,p=os.environ.get('SR203_LISTEN','0.0.0.0:8099').rsplit(':',1); socket.create_connection(('127.0.0.1',int(p)),2).close()" || exit 1

# -I: isolated mode (ignore env/user site, safer startup).
ENTRYPOINT ["python3", "-I", "/app/sr203-proxy.py"]
