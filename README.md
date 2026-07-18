# ESP Anywhere Add-ons

Home Assistant OS add-on repository for ESP Anywhere.

## ESP Anywhere Builder

An experimental private-alpha Builder with a Home Assistant Ingress panel. It reads ESPHome YAML from `/config/esphome`, builds an isolated working copy, signs OTA firmware with an Ed25519 key stored only in add-on data, and publishes to an administratively allowlisted GitHub repository.
