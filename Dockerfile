FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO stays enabled: tigerbeetle-go links its static tb_client library.
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/maritime-intelligence ./cmd/maritime-intelligence

FROM gcr.io/distroless/base-debian12:nonroot
COPY --from=build /out/maritime-intelligence /maritime-intelligence
USER nonroot:nonroot
ENTRYPOINT ["/maritime-intelligence"]
