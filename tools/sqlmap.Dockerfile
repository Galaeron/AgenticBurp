# Local sqlmap image for the containerised SQLi confirmation leg.
# Built locally (not pulled) so no untrusted image enters the supply chain, and
# so the offensive tool lives only inside a throwaway Linux container -- never on
# the host disk where endpoint protection quarantines it. Version-pinned, same
# rationale as ffuf.Dockerfile.
#
#   docker build -t harness/sqlmap:1.10.9 -f tools/sqlmap.Dockerfile tools
#
# The harness invokes it via tool_runner.run("harness/sqlmap:1.10.9", [...]); the
# image tag matches validators.sqlmap.container_image in the local config overrides.
FROM python:3.12-slim
RUN pip install --no-cache-dir sqlmap==1.10.9
# Non-root: the tool never needs host privileges.
RUN useradd -m runner
USER runner
ENTRYPOINT ["sqlmap"]
