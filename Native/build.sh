#!/bin/sh
set -eu

native_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(dirname "$native_dir")
platform=${1:-device}

if [ -n "${CARGO:-}" ]; then
    cargo_bin=$CARGO
elif [ -x "$repo_dir/.toolchains/cargo/bin/cargo" ]; then
    export CARGO_HOME="$repo_dir/.toolchains/cargo"
    export RUSTUP_HOME="$repo_dir/.toolchains/rustup"
    cargo_bin="$CARGO_HOME/bin/cargo"
elif command -v cargo >/dev/null 2>&1; then
    cargo_bin=$(command -v cargo)
elif [ -n "${HOME:-}" ] && [ -x "$HOME/.cargo/bin/cargo" ]; then
    # Xcode launched from Finder may not inherit the user's shell PATH.
    cargo_bin="$HOME/.cargo/bin/cargo"
else
    echo "Rust Cargo was not found; install Rust or set CARGO to its executable" >&2
    exit 1
fi

# Cargo honors CARGO_TARGET_DIR, including relative paths. Resolve it once so
# the archive copy reads the same directory as the build from any caller cwd.
if [ -n "${CARGO_TARGET_DIR:-}" ]; then
    case "$CARGO_TARGET_DIR" in
        /*) target_dir=$CARGO_TARGET_DIR ;;
        *) target_dir="$(pwd -P)/$CARGO_TARGET_DIR" ;;
    esac
else
    target_dir="$native_dir/target"
fi
export CARGO_TARGET_DIR="$target_dir"

case "$platform" in
    device)
        target=aarch64-apple-ios
        sdk=iphoneos
        output_dir="$native_dir/build/iphoneos"
        ;;
    simulator)
        target=aarch64-apple-ios-sim
        sdk=iphonesimulator
        output_dir="$native_dir/build/iphonesimulator"
        ;;
    *)
        echo "usage: $0 [device|simulator]" >&2
        exit 2
        ;;
esac

export SDKROOT
SDKROOT=$(xcrun --sdk "$sdk" --show-sdk-path)
export IPHONEOS_DEPLOYMENT_TARGET=17.4
"$cargo_bin" build --locked --release --target "$target" --manifest-path "$native_dir/Cargo.toml"
mkdir -p "$output_dir"
# Preserve the archive's timestamp on a no-op build so Xcode can skip relinking.
archive="$target_dir/$target/release/libgpsnative.a"
if ! cmp -s "$archive" "$output_dir/libgpsnative.a"; then
    cp "$archive" "$output_dir/libgpsnative.a"
fi
echo "$output_dir/libgpsnative.a"
