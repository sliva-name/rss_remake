FROM postgres:17.11-bookworm
RUN apt-get update \
 && apt-get install --yes --no-install-recommends postgresql-17-pgaudit \
 && rm -rf /var/lib/apt/lists/* \
 && install -d -o postgres -g postgres -m 0755 /var/log/dg-audit
