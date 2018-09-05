# Go

A collection of small libraries to be used by internal Go services. This is
_not_ an SDK: the libraries here are un-opinionated, small and composable. They
do not depend on each other (or on anything else).

## Documentation

GoDoc for all these modules is extensive and authoritative. Read it!

## Featuring...

- [`github.com/github/go/chatterbox`](https://github.com/github/go/tree/master/chatterbox): a
  client for [chatterbox](https://github.com/github/chatterbox) that allows go
  programs to send messages into chat.
  
- `github.com/github/go/errors`: an idiomatic errors package that adds support
  for backtraces and error wrapping. Based on Dave Cheney's original module.
  
- `github.com/github/go/haystack`: A package that reports errors to 
  [haystack](https://github.com/github/haystack) via HTTP or output stream, with
  blocking and nonblocking modes.
  
- `github.com/github/go/log`: A structured logging package inspired by 
  [zap](https://github.com/uber-go/zap).

- `github.com/github/go/middleware`: a bunch of framework-agnostic middlewares.
  Includes Recovery, Default Headers, Statistics and Chaining middlewares. All
  these are self-contained and can be used with by manual handling, Negroni and
  any other reasonable web framework.
  
- `github.com/github/go/monitor`: a library of small monitoring services. Right
  now only includes a checker for unbounded goroutine growth. This is an
  important checker to have on production services!
  
- `github.com/github/go/statsd`: a DataDog-compatible StatsD client that does
  buffering, async reporting, downsampling and tagging. The main "feature" of
  this client is that it can report a metric in ~650ns and allocating 0 bytes
  on the heap. This is a very important feature.

- `github.com/github/go/statsd/ps`: a tiny function that periodically reports
  process statistics via an StatsD client.

## You may also like...

Although this repository contains a small selection of packages, you will
probably need to pull in external dependencies to add missing functionality to
your apps and services.

As always, use your taste and common sense, but here's a small selection of
useful packages which are idiomatic and well written:

### HTTP stuff

- `github.com/julienschmidt/httprouter`: fast, simple and integrates well with
  the default HTTP stack. A great choice.

- `github.com/gorilla/websocket`: the best WS implementation in Go.

- `github.com/urfave/negroni`: a middleware library which works very well in
  practice.

### Testing

- `github.com/stretchr/testify/assert`: it makes testing much less painful.
  Some people say it's not idiomatic, but frankly, tests don't need to be
  idiomatic.
