FROM golang:1.24-alpine as builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o authService ./cmd/app

FROM alpine:latest

WORKDIR /root/

COPY --from=builder /app/authService .

EXPOSE 8081

CMD ["./authService"]
