FROM golang:1.25-bookworm AS builder

RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go generate ./... && CGO_ENABLED=0 GOOS=linux go build -o /blackbox-tracer .

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /blackbox-tracer /usr/local/bin/blackbox-tracer

ENTRYPOINT ["/usr/local/bin/blackbox-tracer"]