FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /proxy ./cmd/proxy

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && mkdir -p /data/wal
COPY --from=builder /proxy /usr/local/bin/proxy
ENTRYPOINT ["proxy"]
