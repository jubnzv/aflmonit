# aflmonit

A simple dashboard for the [AFL](https://github.com/google/AFL) that is assembled into a single binary using [embed](https://golang.org/pkg/embed/) feature from Go 1.16.

## Usage

```
usage: aflmonit [<flags>]

Flags:
  --help                Show context-sensitive help (also try --help-long and --help-man).
  --debug               Enable additional output
  --path="."            Path to AFL directory
  --hostname="0.0.0.0"  Server hostname
  --port=PORT           Server port
  --version             Show application version.
```
