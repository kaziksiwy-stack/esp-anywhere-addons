# ESP Anywhere Builder

The add-on reads YAML files from `/config/esphome` through a read-only Home Assistant configuration mapping. Original files are never modified.

The signing key and GitHub token are stored with mode `0600` under the add-on-owned `/data` directory. They are never included in add-on options or logs. Use a fine-grained GitHub token restricted to `kaziksiwy-stack/esp-anywhere-ota` with Contents and Releases write access.

Ingress is administrator-only. No network port is exposed by the add-on configuration.
