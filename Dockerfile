# Rust as the base image
FROM rust:1.82-bullseye as build

# Create a new empty shell project
RUN USER=root cargo new --bin dummy-rcon-server
WORKDIR dummy-rcon-server

# Copy cargo files
COPY ./Cargo.toml ./Cargo.toml

# Build only the dependencies to cache them
RUN cargo build --release
RUN rm src/*.rs

# Copy the source code
COPY ./src ./src

# Build for release.
RUN rm -f ./target/release/deps/dummy_rcon_server*
RUN cargo build --release

# The final base image
FROM debian:bullseye-slim

# Setup workdir
WORKDIR /dummy-rcon-server/

# Copy from the previous build
COPY --from=build /dummy-rcon-server/target/release/dummy-rcon-server .

# Run the binary
CMD ["./dummy-rcon-server"]
