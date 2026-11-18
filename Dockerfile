FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /cf-traefik-forward-auth .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /cf-traefik-forward-auth /cf-traefik-forward-auth
EXPOSE 8080
ENTRYPOINT ["/cf-traefik-forward-auth"]
