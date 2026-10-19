# Local and e2e builds. Releases use Dockerfile.release with binaries built by GoReleaser.
FROM golang:1.27.2 AS build
ARG TARGETOS TARGETARCH VERSION=dev COMMIT=none
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/jwks-bridge ./cmd/jwks-bridge

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/jwks-bridge /jwks-bridge
USER 65532:65532
EXPOSE 8080 8443 9090
ENTRYPOINT ["/jwks-bridge"]
CMD ["serve"]
