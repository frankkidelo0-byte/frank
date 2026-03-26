FROM golang:1.21-alpine

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod ./

RUN go mod tidy

RUN go mod download

COPY . .

RUN go build -o aeroshield .

EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 8443

CMD ["./aeroshield"]

