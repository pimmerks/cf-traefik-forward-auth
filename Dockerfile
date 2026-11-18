# The build stage runs on the builder's own architecture and cross-compiles,
# so multi-platform builds do not need emulation.
FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /cf-traefik-forward-auth .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /cf-traefik-forward-auth /cf-traefik-forward-auth
EXPOSE 8080
ENTRYPOINT ["/cf-traefik-forward-auth"]
