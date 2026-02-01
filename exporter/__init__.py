# Marks exporter/ as a regular package so `python -m exporter.main` works.
# docker-compose launches this service via that exact invocation — removing
# this file would break the container entrypoint.
