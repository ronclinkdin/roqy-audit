# clean twin: pinned digest, no pipe-to-shell, no remote ADD, pinned installs
FROM python:3.12-slim@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY app/ /app/
WORKDIR /app
USER nobody
CMD ["python", "app.py"]
