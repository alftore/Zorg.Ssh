# Terrapin-Scanner (https://github.com/RUB-NDS/Terrapin-Scanner, Apache-2.0), built from source at a pinned release
# inside the image, so nothing is downloaded to or run on the host. The clone must end on exactly this commit, so
# a moved tag fails the build. Go checks every module against go.sum. relay.py is a copy of the one in python-ssh:
# it lets the scanner in this container reach a server on the test host, for hosts where containers can't connect out.
FROM golang:1.25-alpine AS build
ARG TERRAPIN_TAG=v1.1.3
ARG TERRAPIN_COMMIT=5947c1a699c64a4d3cad4a20aac0a9fd40b19483
RUN apk add --no-cache git \
 && git clone --quiet --branch "$TERRAPIN_TAG" https://github.com/RUB-NDS/Terrapin-Scanner /src \
 && cd /src \
 && test "$(git rev-parse HEAD)" = "$TERRAPIN_COMMIT" \
 && grep -q "Apache License" LICENSE \
 && CGO_ENABLED=0 go build -trimpath -o /terrapin-scanner .

FROM python:3.13-slim
COPY --from=build /terrapin-scanner /usr/local/bin/terrapin-scanner
COPY --from=build /src/LICENSE /usr/share/licenses/terrapin-scanner/LICENSE
COPY relay.py /app/relay.py
EXPOSE 22
CMD ["python", "-u", "/app/relay.py"]
