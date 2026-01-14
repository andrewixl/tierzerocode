#!/bin/sh
# Build script with SBOM and provenance attestations for Docker Scout

# Linux/macos
# chmod +x build.sh
# ./build.sh

# Manual Command:
# docker buildx build \
#   --platform linux/amd64 \
#   --attest type=sbom \
#   --attest type=provenance \
#   --tag docker.io/andrewixl/tierzerocode:latest \
#   --push \
#   .

# Set the image name (default from docker-compose.yml)
IMAGE_NAME="${IMAGE_NAME:-docker.io/andrewixl/tierzerocode:latest}"
TAG="${TAG:-latest}"

# Build with SBOM and provenance attestations
docker buildx build \
  --platform linux/amd64 \
  --attest type=sbom \
  --attest type=provenance \
  --tag "${IMAGE_NAME}:${TAG}" \
  --push \
  .

echo "Build complete with SBOM and provenance attestations!"
echo "Image: ${IMAGE_NAME}:${TAG}"
