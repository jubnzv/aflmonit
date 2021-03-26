# aflmonit

A simple dashboard for the [AFL](https://github.com/google/AFL) fuzzer.

The utility is assembled into a single binary using [embed](https://golang.org/pkg/embed/) feature from Go 1.16. This makes it convenient to deploy it.

## Building from source

```bash
git clone https://github.com/jubnzv/aflmonit
cd aflmonit
go build ./cmd/monit/aflmonit.go
```

## Usage

Transfer the `aflmonit` binary to the server and run it, specifying the path to the AFL output directory:

```bash
./aflmonit --path=/home/test/output
```

See the full list of the options with `aflmonit --help`.
