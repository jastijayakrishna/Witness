FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /hubbleops ./cmd/hubbleops
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /gate ./cmd/gate

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && mkdir -p /data/wal
COPY --from=builder /hubbleops /usr/local/bin/hubbleops
COPY --from=builder /gate /usr/local/bin/gate
ENTRYPOINT ["hubbleops"]
