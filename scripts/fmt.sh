#!/bin/bash
# Since our our `rustfmt.toml` uses some nightly formatting features, you can
# invoke this shell script as shorthand for everything you'd normally need to
# manually do (configure rustup, add the nightly profile, etc...)

_command_exists () {
  command -v "${1}" 2>/dev/null >&2
}

_main () {

  # get rustup if it's not installed
  if ! _command_exists "rustup"; then
    # panic if `curl` isn't installed
    if ! _command_exists "curl"; then
      echo "You need to install \`curl\`."
      exit 1
    fi
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  fi
  # alias for easy usage
  alias rustup="$HOME/.cargo/bin/rustup"

  echo "Updating nightly toolchain..."
  rustup toolchain install nightly-x86_64-unknown-linux-gnu &>/dev/null
  echo "Updated nightly toolchain!"
  echo "Updating cargo-clippy..."
  rustup component add clippy &>/dev/null
  echo "Updated cargo-clippy!"
  echo "Using clippy to fix common mistakes..."
  rustup run stable cargo clippy
  echo "Clippy is done!"
  echo "Formatting code..."
  rustup run nightly cargo fmt
  echo "Formatted code!"
}

_main
