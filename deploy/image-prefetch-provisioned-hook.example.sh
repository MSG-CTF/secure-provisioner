#!/bin/sh
# Install root-owned. Call only from the trusted VM provisioning completion job.
# That job atomically writes the root-owned receipt using its provider/API and
# authenticated bootstrap identity; never forward an HTTP request body here.
set -eu
exec /usr/bin/python3 /usr/local/libexec/image_prefetch_enroll.py accept-provisioned \
  --policy /var/lib/secure-provisioner/image-prefetch/enrollment.json \
  --registry /etc/secure-provisioner/clusters.json \
  --output /var/lib/secure-provisioner/image-prefetch/nodes.json \
  --receipt /var/lib/secure-provisioner/image-prefetch/provisioned.json \
  --runtime-user secure-provisioner \
  --apply
