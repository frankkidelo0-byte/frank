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
FROM pierrezemb/gostatic
COPY . /srv/http/
CMD ["-port","8080","-https-promote", "-enable-logging"]
