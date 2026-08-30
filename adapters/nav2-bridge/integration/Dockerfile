FROM ros:jazzy-ros-base
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      clang libclang-dev curl build-essential pkg-config \
      ros-jazzy-nav2-msgs python3-colcon-common-extensions ros-jazzy-ament-cmake \
    && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
ENV PATH=/root/.cargo/bin:$PATH
ENV CARGO_TARGET_DIR=/tmp/target
