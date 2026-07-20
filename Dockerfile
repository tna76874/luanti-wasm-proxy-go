FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o proxy main.go

FROM alpine:3.19
RUN apk add --no-cache iptables tzdata

WORKDIR /app
COPY --from=builder /app/proxy /app/proxy
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
