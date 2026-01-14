# Build script with SBOM and provenance attestations for Docker Scout
# PowerShell version for Windows
# .\build.ps1

# Set the image name (default from docker-compose.yml)
$IMAGE_NAME = if ($env:IMAGE_NAME) { $env:IMAGE_NAME } else { "docker.io/andrewixl/tierzerocode" }
$TAG = if ($env:TAG) { $env:TAG } else { "latest-dev" }

Write-Host "Building Docker image with SBOM and provenance attestations..."
Write-Host "Image: ${IMAGE_NAME}:${TAG}" -ForegroundColor Cyan

# Build with SBOM and provenance attestations
docker buildx build `
  --platform linux/amd64 `
  --attest type=sbom `
  --attest type=provenance `
  --tag "${IMAGE_NAME}:${TAG}" `
  --push `
  .

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nBuild complete with SBOM and provenance attestations!" -ForegroundColor Green
    Write-Host "Image: ${IMAGE_NAME}:${TAG}" -ForegroundColor Cyan
} else {
    Write-Host "`nBuild failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}
