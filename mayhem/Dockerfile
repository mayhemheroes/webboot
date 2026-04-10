FROM --platform=linux/amd64 golang:1.26 AS builder

COPY . /webboot
WORKDIR /webboot/mayhem

RUN go install github.com/dvyukov/go-fuzz/go-fuzz@latest github.com/dvyukov/go-fuzz/go-fuzz-build@latest
RUN go get github.com/dvyukov/go-fuzz/go-fuzz-dep
RUN go get github.com/AdaLogics/go-fuzz-headers
RUN apt-get update && apt-get install -y clang

RUN go-fuzz-build -libfuzzer -o fuzzWebboot.a && \
    clang -fsanitize=fuzzer fuzzWebboot.a -o fuzzWebboot.libfuzzer

FROM debian:bookworm-slim
COPY --from=builder /webboot/mayhem/fuzzWebboot.libfuzzer /
