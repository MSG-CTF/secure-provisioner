# Build with --build-arg GO_IMAGE=<reviewed golang image digest>.
ARG GO_IMAGE=golang:1.26.0
FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -o /image-agent ./cmd/image-agent
FROM scratch
COPY --from=build /image-agent /usr/local/bin/image-agent
ENTRYPOINT ["/usr/local/bin/image-agent"]
CMD ["--idle"]
