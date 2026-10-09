FROM golang:1.27-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o identity-service ./cmd/api

FROM alpine:latest

RUN apk --no-cache add ca-certificates \
    && adduser -D -u 10001 app

WORKDIR /app
COPY --from=builder /app/identity-service .

# 8000 is public (sign-in), 8001 is internal only (docs/adr/0003).
ENV HOST=0.0.0.0 \
    PUBLIC_PORT=8000 \
    INTERNAL_PORT=8001

USER app
EXPOSE 8000 8001

CMD ["./identity-service"]
