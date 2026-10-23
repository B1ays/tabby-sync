# syntax=docker/dockerfile:1
# For production, pin both base images by digest (Renovate/Dependabot keep
# the digests current).
FROM golang:1.27.3-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
# Reproducible, static, no cgo.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid=" -o /out/syncd ./cmd/syncd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/syncd /syncd
USER nonroot:nonroot
ENV TABBYSYNC_LISTEN=:8080
EXPOSE 8080
ENTRYPOINT ["/syncd"]
CMD ["serve"]
