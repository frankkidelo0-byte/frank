FROM golang:1.21-alpine
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN go build -o aeroshield .
EXPOSE 8080
CMD ["./aeroshield"]
