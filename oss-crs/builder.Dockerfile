# =============================================================================
# patchsense-crs Builder Dockerfile (target_build_phase)
# =============================================================================
# Compiles the target and submits build outputs using libCRS.
# Required even for a validator-only CRS (framework expects a build phase).
# =============================================================================

ARG target_base_image
ARG crs_version

FROM ${target_base_image}

# Install libCRS
COPY --from=libcrs . /libCRS
RUN /libCRS/install.sh

COPY bin/compile_target /usr/local/bin/compile_target

CMD ["compile_target"]
