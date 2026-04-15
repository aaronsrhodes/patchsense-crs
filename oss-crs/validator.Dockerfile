# =============================================================================
# patchsense-crs Validator Dockerfile (crs_run_phase)
# =============================================================================
# RUN phase: receives patches from the exchange dir, runs PatchSense semantic
# validation on each, and re-submits only confirmed root-cause fixes.
# =============================================================================

ARG target_base_image
ARG crs_version

FROM patchsense-base

# Install libCRS (CLI + Python package)
COPY --from=libcrs . /libCRS
RUN pip3 install /libCRS \
    && python3 -c "from libCRS.base import DataType; print('libCRS OK')"

# Copy validator scripts into the already-installed patchsense-crs location
COPY validator.py /opt/patchsense-crs/validator.py
COPY sarif_parser.py /opt/patchsense-crs/sarif_parser.py

ENV PYTHONPATH=/opt/patchsense-crs

CMD ["python3", "/opt/patchsense-crs/validator.py"]
