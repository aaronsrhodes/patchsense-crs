# =============================================================================
# patchsense-crs Docker Bake Configuration
# =============================================================================
# Builds the base image containing PatchSense + Python dependencies.
# =============================================================================

variable "REGISTRY" {
  default = "ghcr.io/aaronsrhodes"
}

variable "VERSION" {
  default = "latest"
}

function "tags" {
  params = [name]
  result = [
    "${REGISTRY}/${name}:${VERSION}",
    "${REGISTRY}/${name}:latest",
    "${name}:latest"
  ]
}

group "default" {
  targets = ["prepare"]
}

group "prepare" {
  targets = ["patchsense-base"]
}

target "patchsense-base" {
  context    = "."
  dockerfile = "oss-crs/base.Dockerfile"
  tags       = tags("patchsense-base")
}
