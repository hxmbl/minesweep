# Build stage
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o minesweep ./cmd/minesweep

# Final stage
FROM alpine:3.21

# git: --diff, --staged and --history read the repository.
RUN apk add --no-cache ca-certificates git

WORKDIR /app

COPY --from=builder /app/minesweep /usr/local/bin/minesweep
COPY docker/action-entrypoint.sh /usr/local/bin/minesweep-action

# Rules, policy, and profiles are embedded in the binary; no asset files needed.

ENTRYPOINT ["minesweep"]
CMD ["/data"]
