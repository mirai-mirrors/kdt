#!/bin/bash
# This is a script to automatically create musl-linked
# executables so kdt can run on any system (any linux
# system*), regardless of the included libc. This doesn't
# do command existence checking, so it WILL fail if you're
# missing the dependencies!

_main () {
  rm -rf dist
  mkdir dist
  echo "Building with \`cargo build --release --target=x86_64-unknown-linux-musl\`..."
  cargo build --release --target=x86_64-unknown-linux-musl
  echo "Successfully built musl release for kdt!"

  echo "Packing into .tar.gz..."
  mkdir kdt
  cd kdt
  cp ../../target/x86_64-unknown-linux-musl/release/kdt .
  cd ..
  tar -czf "kdt_$(cargo get version --pretty).tar.gz" ./kdt/
  mv "kdt_$(cargo get version --pretty).tar.gz" dist
  echo "Successfully packed executable into tar archive! View it at ./dist/kdt_$(cargo get version --pretty).tar.gz."
  rm -rf kdt
}

_main
