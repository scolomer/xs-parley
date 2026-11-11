FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/xs-parley-relay ./cmd/xs-parley-relay

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/xs-parley-relay /xs-parley-relay
ENV XSP_LISTEN=:8080
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/xs-parley-relay"]
