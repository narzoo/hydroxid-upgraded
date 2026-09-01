FROM golang:1.24-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/hydroxide ./cmd/hydroxide

FROM alpine:3.22

RUN apk add --no-cache bind-tools ca-certificates proxychains-ng

COPY --from=builder /out/hydroxide /usr/local/bin/hydroxide
COPY docker/entrypoint.sh /usr/local/bin/hydroxide-entrypoint

RUN chmod +x /usr/local/bin/hydroxide-entrypoint

ENV HYDROXIDE_TOR_HOST=n8n-tor \
    HYDROXIDE_TOR_PORT=9050 \
    HYDROXIDE_PROXYCHAINS_CONF=/etc/proxychains.conf \
    HYDROXIDE_COMMAND=serve \
    HYDROXIDE_ARGS="-smtp-host 0.0.0.0 -imap-host 0.0.0.0 -carddav-host 0.0.0.0"

ENTRYPOINT ["/usr/local/bin/hydroxide-entrypoint"]
CMD ["serve"]
