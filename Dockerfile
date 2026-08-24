# Build stage
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o minesweep ./cmd/minesweep

# Final stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /app/minesweep /usr/local/bin/minesweep

# Rules, policy, and profiles are embedded in the binary; no asset files needed.

ENTRYPOINT ["minesweep"]
CMD ["/data"]
