# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/oauth-token-refresher ./cmd/oauth-token-refresher

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/oauth-token-refresher /usr/local/bin/oauth-token-refresher
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/oauth-token-refresher"]
