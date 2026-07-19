# Changelog

## 0.1.3

- Canonicalize the resolved MQTT CA to strict multiline PEM before ESPHome compilation.
- Prevent folded YAML certificate blocks from producing firmware rejected by mbedTLS.

## 0.1.2

- Snapshot the selected YAML and `secrets.yaml` byte-for-byte for every build.
- Validate the resolved MQTT CA as X.509 PEM before compilation.
- Regenerate ESPHome build configuration after secret changes.

## 0.1.1

- Verify final manifest bytes with the exact Home Assistant parser before publication.
- Prevent signing-key changes during active builds.

## 0.1.0

- Initial private-alpha amd64 Builder with Home Assistant Ingress.
