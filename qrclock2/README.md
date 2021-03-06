Solution to "qrclock2" by Mark Proxy
====================================

We are presented with a network service, listening on TCP port 13
(daytime protocol).

Connecting to it, we receive a large, unicode-rendered QR code:

```
█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
████ ▄▄▄▄▄ ███▄▄█▀█▄█▀▀ ██▀█▄▄▄▀▀▀█ ██▀ █▄█▀▀▀██ ▄█  ▄█ █ ▀█▄▄▀█ ▀ ▄█  █▄█▄▄▀ ▀█▀  █▄█▄█▄▀▀▀ ▀ █▀▄█▄ ▄▀  ▀██▄█ ▄▄▄▄▄ ████
████ █   █ █ █ ▄█▄ █▄███▀███  █▀▄▀█▀  ▀▀ ▄▄██ ▄█ ▀█ ▄█▀██▀▄ █▄█ ▄ ▄█▄▄█▀ ▄█ ▀█ ▀ ▀ ▄▀█▀▄ ▀ ▀ ██▀██▀▄▄█▀ ▄█  ▀█ █   █ ████
████ █▄▄▄█ ██▀▄ █▀█▀ ▀▄ ▄▀▀▀██ ▄▄▄  ▀ █▄  ▀█ ███▄ ▄▀█▄█▄ ▄▄▄ ▀▄  ▄  ▀▀███▀█▄▀▀█▀ █ ▄▄▄ ▀  ▄▄   ▀  ▀▀▀ █ ▀ ▀▀██ █▄▄▄█ ████
████▄▄▄▄▄▄▄█▄▀▄█▄▀ █ █▄▀ █▄▀▄█ █▄█ ▀ █▄█▄▀▄█ █ ▀▄▀ ▀ █▄▀ █▄█ █ ▀ █ █ ▀ █▄█▄▀▄▀ ▀▄█ █▄█ ▀ █▄▀▄▀▄▀ ▀ ▀ ▀ ▀▄▀▄█ █▄▄▄▄▄▄▄████
█████▀▀▄ ▀▄ █▀▄▀▀█▄▄▄▄█▀▀█ ▄▀   ▄▄▄▀█ ▄▀ ▀█▀▄ █▀ ▄█  █ ▄ ▄▄▄ ▄█▀▀▄█▀█▄▄ ██ ██ ▄▄█▄ ▄▄▄▄ ▀ ▀ ▀▄█ ▀█ ██ ▀█▀▄▄█▀██▀▀  ██████
████▀▀█ ▄▄▄ ▀▀▄ ▄▄█▀▄▄ █▀▄ ▀▀▀▄▀  ▀ █▄▀▀▀█ ▀ ▀ ▀█ ▄█▄▀ █ ██▄  ▄▄ ▀▄▀ ▄▀█ █ ██▀▀▀▀ ▀▄█▄██ ▄  █▀▀▀█▀▀ ▀▄▄▀ ▄▄▄▄  ▀▄▀██▀████
████▄ ▄▄█▄▄▀▄█▀▀▄█   ▄▀▀▀▀  ▄█ ▀█▄ █▄█▄█▀ ███ █ ▄ ▀▄ █▀ ▄██▄▀█▄▀▄▀▀█▄▄ █▀▄▀▀▄  █  ▄▄▄▄ ██▄▀▄▄█  ▄ ▄▄█ ▄▄  ▄█ ▀██▄█  █████
████▄▄ █▄▀▄▄  ▀▄▀█▀█▄▀█▄▄██ █ █▀▀▀█▄ █▄▀   ██ ▀ ▀  █▄▀▄██▄ ▄▄▄▀█   █▀ ███▄▀ █▀  ▀█▀▀  █   ██▄▄▄▀ ▄▄▀  ▀█▀█ ▀█▀ █▄▄▀▀ ████
████▄▀▀ ▄▄▄▄  █▀▀█ ▄▀███▄▄▀▀ ▄█▀███▀▀▀ ▄█   █ ▄   ▄▀▄█▄▀█▄ █▀█▄▀▀█ ▀█ ▄▄  ▄ ▀█▀▄█▄▄▀▄▄█ ██▄██ █▀█▀██▄▀▄▀▀▀ █  ▀ █ ▀▄▄████
█████▄▄██▄▄▄▄▄▄▀▄▀▄▀▀▀▀▀ ▀█▄ ▀▀▀  ▄ ▀▄▄█▀█▀▀ ▄█▀▄▄ ▀ █ ▀▄▀█  ▀ ▀██▄▄▄▀▄█▀█▄▀ ▀  ▄██▀▀ ▄ ▀▀▄▀▄▀▄▄▀█▄  ▄▀▀▄ ▄▄▀ ▄▀▄▄▀▀ ████
█████ ▄ █▀▄██▀ █ ▄█▀     ▀ █▄  ▄▀▀ ▄▄  ▄█    ▀▄▄ █ ▀▀▀▄██▀▀▀▄▀▄  ▀▄▀▄▄▀ ▀██▄██▀▄▀ ▄▄  ▄▀▀▀█▄█▀▀▀▄█▀▄ █▀▄▀█▄▄▄ █▀▄█ ▀▄████
████▄██▄██▄██  █▄ ▄▄▄▀ ▀███▄█▄█ █ ▀▄█▄▀ ▄ █ ▄▄█▄▀ ▄▄▄▄██ ▀▄▄▄█▀▀▄█  ▀▀▀▄ █▀█   █  ▄ █ ██▀▄  ██ ▀▄█▀▄▄▄▄▀▀▀▄ █▀▀█▄▄▄ █████
████ ▀  █▄▄██ ▀ █  ▀ ▄▀ ▄▀▄█▀█▄█▄█ ▄▀█ ▄  █▀▀▄ ▄█▀ ▄█▀ █ ▀██▀▀▀▀ ▀▄ ▄▄▄ █▀ █ ▀▀ ▄▀ ▄▀▄ ▄█▀ █▀▄▄▀▄▄  █▄▀███▄▄▄ ▀▀█▄ ▄▄████
████▀  █ ▄▄▄ ▀ █▄█▀▀ ▀▀█▀█▄█▄  ▄▄▄   █▄▀█▄▀▄█▀▄█▄ ▄▀▀█▄  ▄▄▄ ▄▄▀▀█ █▀█▄█▄█▀█▄▀█ ▀█ ▄▄▄ ▀▀███ ▄ ▀ ▀▄▄▀██ ▀▄▄  ▄▄▄ █ ▀ ████
████▄ ▀  █▄█ █▄▀█▄ ▀█ ██ ▄▀▀ ▄ █▄█ ▀ ▀█▄▀ █ ▄█▄ ▀▄ ▀▀▄ ▄ █▄█ ▀▄ ▀▀▄▀▄███ ▀█▀ ▀█ ▀▄ █▄█ ▀▀▄ ▄▀█▀▄  ▀ █▀   ██▄ █▄█ ██ ▄████
████ ▀ █ ▄▄▄ ▄█▀▀█▀▀▄▀█ █▀ ▄▄ ▄▄  ▄█▀▄▀ ▄▄ █ ▄  ▄▄▄▄▄▄▀█▄   ▄█▀███▄ ▄█ ▄▀ ▀▀ █▄██▄    ▄▀▀▀  ▄█ ▀▀█▄▀ ▀ ▀▄▀   ▄▄▄ █ ▀ ████
████▄ ▀█▀▀▄▄█▀█▀ █▄ ▀██ ▄▄██ ▀▀██▄▀ ▀▄▄▄ ▄ ▀ ▀▀█▀█▀▀ ███  █▄▀▄▀ ▀▀▀▄▀ ▄██▀ █▄ █▄▄█▀██▄▄ ▀ ▀▄▄▄█▀██ ▄█ █ ▀▄ █▀ ▄██▄▀█ ████
██████ ██ ▄▀▄▀ ▀▄██▄▀▀▀█▀▄▄▀▄ ██▀ █▄▄▄▄ █▄ ▄▀▄█▄▄▄▀▄▀▀▄█▀ █▀▀███▀▀█▄▄▀▀▄▄ ██▄  █  █    ▄ ▀ ▀▀▀ ▀█ █▀▀   ▀█▄▄ ▄█▄ ▀ █▀████
████▄▀▄▀  ▄▄▀▀█▀ █▄ ▀▀▄█ █▀ ▀████▄ ▀▄▀  ▀▀▄▀▀██ ▄▀▀█ ███▄▀█▄ ███▀▀▀ ▄█▀ ███▀▄▀▄▀▀▄ ▀▄▀▄▄▄▄  ██ ▀▄█▄ ▄▀ ▄▀█▀  ▄ █  ▀ █████
████ ▄█ ▀▄▄▄▀▀█ ▄▄█ █ █▀▀▀ █ ██ ▄██ ▄▀█ ██▄ ▄ █▄█   ▀▀█ ▄▀█  ██ █▄██▀ ▄█▄ ▄▄ ▀█▀ ██▄  ▀▀ ▀█▀  ▄ ▀█  ▀▀▀▀ ▀▄█▄ ▀▄▀▀▀▀█████
████▄▄▀▄█ ▄█▄▀ ▄█ ▀▀  ▄▀█▀ ▀▀▀▀▀▀▄██ ▄▀▄▄▄█  ▀█▀▄ █▄█▄█▀▀ ██▄█ ▄▄▀▀▄▄▀ ▀ ▄▄ ▀▀█▄▄█   █▄█ ▄▀ █ ▄██ ▀▄ ▀ █▀█▀  ▄▀▀▄▄  ▄████
████▄  ▄ ▀▄█▄██  █▀▄ ▄█ ███▄▀▀▄▄▀ ▄▀█▄▄▀▀█▄▀█▀▀▄▀▄█ ▄▀██ ▄ ▀█ █▄██▄▀▄▄▀█▄  ▀▄▀ ▀▄▄█ ▄▀█  ▀▀ ▄▀ ▀ ▄▀▀ ▄▄ ▄ ▄▀█▄▀▀▀▄▀▄▀████
████ █▀▀ ▄▄▀▄▄ █▀▄ ███▄▀▀ █▄ ▄ ▄▄▄████▄▀▄▀ ▀█  █▄   ▄▄██▄█▀▀█▄▀▄▄  ▄ █▄▀ █ █ █▀▄▀▀▄ ▄█ ▄ ▄█▄▄▄ ▄█ ▄▄ ▄ ▄ ▄ █▀▀▀▀▀█▄▄█████
████▀▀ ▄▄█▄▀▄█▀▀▀▀▀█▄█ ▄▀█ ▄▄▄██▀▄ ▄▀▄▄█  █▀██ ▀ ▄▀█▀█▄▄ ▀▄▄▄▀   ▄  ▄▀▄██ ▀█ ▄ ▀  ███  ▄ ▀  ▀█ ▀ █ ▄▀ ▄ ▀█▄▄█▄▄▄ ▀█▀█████
██████ ▀██▄▄  ▄▀ ▀ ▀ ▀▀█ ▄▀▀▀███▄▄ █  ███▀█  ▀█▄▄▄▀▄  █▄▀▀▀ ███▄▀ █  ▄▄ █ ▄▄█▀█ █▄ ▄█▄▄█▄▀▄ ▄█ ▀▄ ▄▄▄ ▀▄  ▄█▄▀ ▀▀▄   ████
████ █    ▄█▀██ ▀█▄ ▀▀ ██▄▄▀▄ ▀ ██ ▄ ▄▀█▄ ▀█  ▄ ██▄▀▄██ ██▀█ ▀█▀███▀▀     ▄ ▀▀▀█▀█ ▄▀ ▀ ▀▀▀▀▀▄▄  ▄▀ ▀▀▀  ▄ ▄▄▀▀▀ ▀ ▄▀████
████▀▄█  ▄▄▄  █▄█▀▀▀ █▀▀▀██▀   ▄▄▄ ▀█▀▀ █▀███ ▄█▀▀▀▄▄ ▀▀ ▄▄▄ ▀▀▄█▀▄█▄  ▄█▀█ █▄▀ ▄  ▄▄▄ ▀ ▄  ▀█ ▄▀▀▀▄▀▀▀█ ▀▄▄ ▄▄▄ █▄▀ ████
████▀█▀  █▄█ ▀ ▀▄  ▄█▀██▀  ▄▀█ █▄█ ▄▀▄  ██▀▀  ███▀  ██▄█ █▄█ ▀█ ███▀▄ ▀    ▀▀▀ ██▀ █▄█ █ ▀ ▄█▀  ▀ █▄▀▀▄▄▄ ▄▀ █▄█ ▀▀▀▄████
████▄▄ ▀  ▄▄▄▀▄▀▀ ▄█▀ ▀██▀▄▄ ▀▄  ▄ █▀▄▀▀▄ ▀▀▀█ ███  ▀█▄▀▄▄▄  █▀▀ ▀   ▄▄ ▄██   ▄█ ▄ ▄▄▄ ▄ ▄▀▄█▀ ▄▄▄██▀██▀▄█▄       ▄ ▀████
████▀  ▄▄ ▄▀▀▀▄ ▀ ▄█▀█  █▀ ▀▀ █ ▄▀ ▄ ▄██▀▀▀▀▄▀█▄   ▄▄▄█▀▄ ▄ ▀   ▀█▀▀▄███▄▀ ▀ ▄▄ █ █▀ ▄ ▄ ▄▄ ▀▀▄█▄███ ▀ ▀▀█▄▄▄▀▀ ▄▀███████
████ ▀ ▀ ▀▄█▄ ▀█▄▀▀▀▄▄▄▀█▄ █▄▄█▀▄ ▀▀ ██ ▄██▀ █▀▄ ▄█▄▀█ █▄▀▄▀▀██▄█▀█▄▄ ▄█▀▄█▄██  ▀█▀▄   ▀ ▄▀ ██ █▄▀▄█ ▀▄█▄   ▀ █▀▄█▄▀ ████
█████▀▄  ▄▄▀██▄█▀  ▀ █▄ ▀█▄ █▀▄▄ █ ▀▀▄▄▀▀▄▄▀▀▄▀ ██▄ ▄██▀██▀█▄█▄ ▄▀▄▄ ▄ ██ ▄▄  █   ▀▄ █▄▄▀▀█ ▀▀▄  ▀▄▀▀██▄▀▄▄▀ █ ▀▀ ▀▄ ████
████▄▀▀ ▄▄▄ ▀ █▀▄▄▀█ ▀▀  ▀▀▄▀█▀▄▀▄█▄▀▀▄█▄▄  █▄█▄▀ ▄  ▄▀▀ ▄▀█ ▀▄ ▀██▄▀▄ ▄▄▄▀▄█▀▄███ ▀▄█▀█▀█    ▄ ▄ ▄█ ▀▀▀ █ ▄█▀ ▀▄▄▄▄▄████
██████▀▄  ▄ ▀█▄█▀▀██▀▄▄█▄███ ██▄ ▀▄ ▀▄▀ ▄ ▄▄▄█ █▀▄  ▀█ ▄▄ ▄ ▀  ▀▀███▀ ▄▀██▄▄█▀▄▀▄██▀▄  ▀▀▄▄███ ▄▀█  ▀ ▄▀▄█▄▀▀ █▄██ █ ████
████ ▀▄▀ ▀▄█▀ █ ▄▄█▄▀▄█▄█▄█▀▄█ ▄▄▄▄█  ▀█▄   ▀██  ███ █▀▀  ▀▀ ▀▀ ▄    █ ▄ █▄█▄ ▀ ▀▀   ▀▄▄▄▄█▄▄███ ▀▄█▄▄▄▄ █▄    ▄▄█▀▄█████
██████ ██▀▄▄ █▀ ▀ ▄▄█▄▀  ▄█  ▀ ▄▀▀██▄ ▄▀ ▀▀▄  █▀▄██▀▀▄█▄ ▄█▄  ▄█▀▄ ▀  ▄█ ▄ ▀ ▀▄▄ ▄  ▄ ▀▄ ▄ ▀▀ ▄ ▄ █  ▄▄█ ▄▄ ▀█▀▄▄▀██▀████
█████▄██▀▄▄▀▀█ ▄█  ▄▄▀█ █▄█ █ ▄▄▄▄▄ █   ▀▀▀ ▄  ▄█▀▀ ▄▀ █▀▀█▄▀▀ ▄ ▀ ▄███  █▀▄████  ▀▄▀█   ▄██  ▀▄▀ ▀█▄ █ ███▄▀ ██ ▄▀▄█████
████  ▀▄█▄▄▀██▄ █▀  █ ▄  █ █ ▀ ▀▀█▄▄█▄ █▄▄█ ▄ ▄▀▄▀▀▀█ █▀█ █▄▄▄▄██ █▀ ▀▀▀▀▀   █▀ ▀██▀▀▀   ▀█▀▀█▀  █ ▀▄▄▀ ▀ ▄ ▀▄▀ ▄ ▀█▄████
████ ███ █▄██▄▀▀   ▄ ▄▀▀▀▀▀▄▄█▀▀▄▄▄██▄▄█▄▄▀█ ▄▀█▀▄▄▀█ █ ▄▀▀▀ ▄▄▀ █▄█▄ ▄ ▄  █▄▄▀▀▀█  ▄██▀█ ▄▄▄▄▄ █▄▀█ ▀█▄ ▀▄▄█ ▀▀▄▀█ █████
████  █▀ ▄▄▄ ▀▀▀▄▄█▄  ██▀██ █▀ ▄▄▄ █ ▀█ ▀▀█▀ ▄▄ █▀ ██▄   ▄▄▄ █▄▄▀ █ ██ █  ▄█▄▀▀ █▄ ▄▄▄  ▀█ ▀█▄▄▀▀▄ ▄▀▀  ▄█ ▄ ▄▄▄   ▄▄████
█████▄ ▄ █▄█ ▀▄ █▀▀ ▀ ▄▄▄█▄█▀▀ █▄█ ▀█▄▀   █▀ ▄▄ ▀▀ ▀  ▀█ █▄█ ▄▀█▄▄▀▄█▄█ ▀█▄▀▀▀▄▀▄  █▄█ ▀█▀█  █▄ ▄█ █▀█▀   █  █▄█ █ █▀████
████ ▀▄█▄ ▄ ▄▄█▄  ▀▄█▀▀▀██▄▀█   ▄▄▄▀ ▀▀ ▄█▄█ █▄▀▄▄▀▄▄▄ █▄▄ ▄ ▀▄█▀ █▄▀█  ▄▀█▀█ ▄▀▀▀ ▄▄  ▄ █▄  █  █▀▀ █▄▄▀ █  ▄ ▄▄  ▄█▀████
████▀██▀██▄▄▄  ▀ █   ▀ ▀▀█▀█ █ ▄▀  ▄▀██▄█▀ ██ █▄▄▄█ ▀▀▄██▀███▄█▀█▀▄▀█▀▀▄▄▀█ ▀▄███ █▄▀ █   ▄  █ ▀█▄██▀▄█▄▀█▀▄█ ▄ ▀▄ ▄ ████
████▄▄ ▀█▄▄ █▄▄█ ▀▄   ▀▄▄ ▄█▄▀█▀█▀▄██▀ ▄▀ █▄█▄▀▀▀▀█ ▀█▄███▄  ▀▄▀██ ▄███ ▄▄▀▄█ ▀█▀▄ ▀█▄ ▄▀▄██ █ ▀ ▀▄▄▄██▀▀ ▄  █ █▄▀ ▀ ████
████▀█ █ ▀▄█▄ █▄ ▀█▀█▄ ▄█▀███▀▄▀█▀█▄█ ▄▀▄█▀▀█▄▄▀▄ █ █▀  ▀ ▀█▀ ▄ ▄▀▄▀▀█ ▀▀▄  ▀███▀▄▀ ▀   ██▀█▀▄▀█▄▄▄▀▀▀ ▀▀█▄██ ▄█▀██▄█████
█████ █ ▄█▄ ▄█▄██▄▄█▄▄  ▀▄ ▄█ ▀ ▄█▀▀▀▀█ ▄█▄▄▄ █▀▀██▄ ▀ ▀█▄▄▄█▄▄▀▄▄ ▄ ██ ▄ ███▀▀▀▄▄██▄▀▀█▀▀  ▄█▄█ ▀▄ ▀▀  ▄▀▄ █  ▄▄▄▀█▄████
█████ █▀ █▄▄   █▀█ ██████▀█ ▀█▄▄ ▀   ▀██▄▄ ▀ █  ▄▄▄▀▀ ██▄█▀ █▀█ █ █▄█▀ ▄▄█▄█ █ ▄▄ ▀██ █▄▀██▄▄ ▄▄▄ ▀    ▄▄█▀▄▀▄▀  ▀▀ ▀████
█████ █▀▀ ▄▄▀▄▀▀ ██  ▀█▄▀  ▄▀▀▄▄██████▄█  ██▀  █▀▄▄▄▀▀█▄▄▄▀▄▀█▄██ █▄▄ ▄▀▀▄   █▀   ▀▀▄▄▀▄ ▄▄ ▀▀▄▀█▀█▄▀▄▄  █▄ █ ██████▀████
████  ██▀ ▄▀█▀████▀  █▀█ ▀▀██▄ ▄▄██ ▄▀██▄▀▄█▄▄▀█ ▀ ██ ▄▀▀▄▀ ▀ ███▄▀▄▄ ▄  ▄▀█  █ ▄▄▀▄▀▀█▀▀▄ █  ▄ ▄█ ▄▄  ▄█ ▀ █▀▄▀ ▀ ▀ ████
████▀▄▄  █▄▀▄▀█▀█ ▄ ▀▄█ ██▀▄ ▀ ▄█▄ ▄▀ █▀▀▄  █▀▀ ▄ █ ▄▄██ ▄█▀ █▄▄▄  ▀▀▄█▄█ ▀██▄██▀▄ ██▄▄▀▀██▀▀▄   █▄▄▀▀█▀▀▄▄  █ ▄▄█ █ ████
████ █  █▄▄██▄  ▄  █▄    ▀▄█▄█▀▄   ▀▄█▀  ▀▀█ ▄█▀ ▀▄  ▀▄█▄█ ▀█  █ ▄  ▀███▀  ███ ████  ▀ █▀██  ▀ ▄   ▀ ▄  ▄███▄█▀█ ▄▀▄▀████
██████  █ ▄▄██▄▄█▄▄█▄▄▀▄ ▀█▀█ ▄▄█  ▄▄█▄ ▄▄ ▄▄█▀▀▄█▄█ █▀▀▀██▀█ ▀█▄▄▄█▀ ▀▄█ █▄▄▀▀ ▄ ▄▄  ▀▀ ▀█▀▄█▄█    ▀█▄▀██▄█▀█ █  ▀█▄████
████▄██▄██▄█▀▄█ ▀▀▄█▀▀▄ █▀█▀█▄ ▄▄▄ ▄█▀  █ ▄▄▀▄█▀ ▄▄ ▀▄▀█ ▄▄▄ █▄█▀ ▀ ▄▄▀▄▀ ▄ ▄█▀▄▀█ ▄▄▄ ▄ ▄▄▄▄ ▄ █    █▀  █   ▄▄▄ ██▀▄████
████ ▄▄▄▄▄ █▄  ▀█▄▄███ ▀███▄▀▀ █▄█ ▀ ▄ ▄▄▀  ██▄▄ █ ██▄▄  █▄█ ▄▄▄▄▀▄▀▀ ▀ ▄███▀  ▀▀  █▄█ █▀▀▀  █▄▀▄ ▀▄▀  ▄▄  █ █▄█ ██▄▀████
████ █   █ █ ▀█▄  ▄▀▀▀██▄█ ▀  ▄▄▄▄  █▄ ▄▀▀██ ██ █▄▄█  █▀▄   ▄▀▄▀▄▀ ▄▀█▄▀█▄▄▀ █▀█▀  ▄  ▄██ ▄██ ▄▀█▀  ▀ ▀▀█ ▄  ▄  ▄█▄▄█████
████ █▄▄▄█ ████ ██▄ ▄██▄ ▄    ▀█  ██ █▄ ▀▄ █▀▄███▀▄▄██▄▀▄▄ ▀ ▀ ▀ ▄ █▀  ▀█  ▄▀▀▄▀▀█ ▀ █  ▄  █▀▄ ▀ █▄ ▀█▀██▄▀█▀▀ ▄ ▄ ▄ ████
████▄▄▄▄▄▄▄█████▄█▄█▄█▄▄████▄▄▄▄█▄▄▄▄▄█▄▄█▄█▄▄█▄██▄▄█▄▄██▄█▄██▄▄▄██▄█▄▄█▄█▄██▄▄██▄█▄█▄█▄██▄▄█▄▄▄▄▄██▄▄▄▄▄▄█▄▄▄██▄▄███████
█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
```

A new text image is given roughly once every second. Scanning the image with a QR code reader, we get a base64 string:

```
H4sIAGdlb1sAA81Vu3HDMAztvYKaN4Jy8V0Kj+IZvAMKFpzAA2qSJLRIPECwBTWJ71jINImH9xE0
Xc/z5fPr8nFb7vW/1nSdb6fpzTvBci+80LZ/nsTtPrZ+zwutl1VS6BXA+tTuVoXD2Bjw/U5wN4dG
XVbHdeALxvlGeXB+UiHjd4kWsUbvQlZGEnYX1Mjhs11Cd6VDiJJVWl3ybXd5bHAe2MmiRR+ocEdM
K4VUOMAZVJBJr5E1yVVpNHlgZBxBtyleJRCu1wWCOcV2D18K2ZfhXW2RLX/LCI7/1rJyzHN6Z4yi
bIfAZVKTwtseNsHeygiwfvrLyATTRcukm3G7KR99s9Rl8DQW9tes2DtcwoPv5s2+IGqj2L8VyXqC
xVp/cI4H819Hhk44HXdVp0nfDCTfVx2bkaXxcgkSwMnT4uFf64zT8TdAh5nNrdoPVl9sVvIuh9+A
YDw++VmiA76NvU7+dL1ZJ988AuBrYAoAAA==
```

Which decodes to a smaller PNG file, with yet another QR
code. Scanning this QR code gives us:

`[Sat Aug 11 15:38:31 PDT 2018 i]`

So, it's a time-of-day service. However, that "i" at the end looks
wrong. It's out of place in a standard time stamp. Sampling a few more
images manually reveal that this letter changes, so there is probably
some information (perhaps even the flag itself) encoded in this stream.

In order to do bulk conversion, we have to automate the entire
process. First, we write a script that converts unicode QR codes to
`.png` files:

```
$ cat term2png.py

usage:
$ ./term2png.py output-from-netcat.txt nicely-rendered-image.png
```

Next, we need a way to automatically download and segment the data
stream from the network service. There is a VT100 code to clear the
screen in between each frame, so we use this to split the data
blocks. (They also have the same size, but that seems like a less
robust way to get the data).

```
$ cat fetcher.py

usage:
$ ./fetcher
```

Great, now we can create a steady stream of png files. Getting a local
QR code reader to work was actually surprisingly difficult, so instead
we use an online service to do the QR decoding:

```
#!/usr/bin/env python

import sys
import BeautifulSoup as bs
import requests

url = 'https://zxing.org/w/decode'
files = {'file': open(sys.argv[1], 'rb')}

r = requests.post(url, files=files)

print bs.BeautifulSoup(r.text).pre.text
```

Now we have all the building blocks in place! Let's put together the
entire pipeline:

```
#!/bin/zsh
set -e

# first, let ./fetcher run for a while to get the input data

for x in clock-{000..100}; do
    echo "[*] $x"
    ./term2png.py $x.dat $x.png
    ./qrdecode.py $x.png | base64 -d | zcat > $x-small.txt
    ./term2png.py $x-small.txt $x-small.png
    ./qrdecode.py $x-small.png > $x-small.txt
done
```

Now we can see what is in this data stream:

```
$ cat *-small.txt
[Sat Aug 11 15:38:30 PDT 2018  ]
[Sat Aug 11 15:38:31 PDT 2018 i]
[Sat Aug 11 15:38:32 PDT 2018 f]
[Sat Aug 11 15:38:33 PDT 2018 _]
[Sat Aug 11 15:38:34 PDT 2018 y]
[Sat Aug 11 15:38:35 PDT 2018 0]
[Sat Aug 11 15:38:36 PDT 2018 u]
[Sat Aug 11 15:38:38 PDT 2018 _]
[Sat Aug 11 15:38:39 PDT 2018 d]
[Sat Aug 11 15:38:40 PDT 2018 i]
[Sat Aug 11 15:38:41 PDT 2018 )]
[Sat Aug 11 15:38:42 PDT 2018 _]
[Sat Aug 11 15:38:43 PDT 2018 t]
[Sat Aug 11 15:38:44 PDT 2018 h]
[Sat Aug 11 15:38:45 PDT 2018 1]
[Sat Aug 11 15:38:46 PDT 2018 5]
[Sat Aug 11 15:38:47 PDT 2018 _]
[Sat Aug 11 15:38:49 PDT 2018 b]
[Sat Aug 11 15:38:50 PDT 2018 y]
[Sat Aug 11 15:38:51 PDT 2018 _]
[Sat Aug 11 15:38:52 PDT 2018 h]
[Sat Aug 11 15:38:53 PDT 2018 4]
[Sat Aug 11 15:38:54 PDT 2018 n]
[Sat Aug 11 15:38:55 PDT 2018 d]
[Sat Aug 11 15:38:56 PDT 2018 _]
[Sat Aug 11 15:38:57 PDT 2018 y]
[Sat Aug 11 15:38:58 PDT 2018 0]
[Sat Aug 11 15:39:00 PDT 2018 u]
[Sat Aug 11 15:39:01 PDT 2018 _]
[Sat Aug 11 15:39:02 PDT 2018 d]
[Sat Aug 11 15:39:03 PDT 2018 i]
[Sat Aug 11 15:39:04 PDT 2018 d]
[Sat Aug 11 15:39:05 PDT 2018 _]
[Sat Aug 11 15:39:06 PDT 2018 i]
[Sat Aug 11 15:39:07 PDT 2018 7]
[Sat Aug 11 15:39:08 PDT 2018 _]
[Sat Aug 11 15:39:09 PDT 2018 w]
[Sat Aug 11 15:39:10 PDT 2018 r]
[Sat Aug 11 15:39:11 PDT 2018 0]
[Sat Aug 11 15:39:12 PDT 2018 n]
[Sat Aug 11 15:39:14 PDT 2018 9]
[Sat Aug 11 15:39:15 PDT 2018  ]
[Sat Aug 11 15:39:16 PDT 2018  ]
[Sat Aug 11 15:39:17 PDT 2018 i]
[Sat Aug 11 15:39:18 PDT 2018 f]
[Sat Aug 11 15:39:19 PDT 2018 _]
[Sat Aug 11 15:39:20 PDT 2018 y]
[Sat Aug 11 15:39:21 PDT 2018 0]
[Sat Aug 11 15:39:22 PDT 2018 u]
[Sat Aug 11 15:39:24 PDT 2018 _]

```

Ah! the data stream simply spells out the flag:

`if_y0u_di)_thi5_by_h4nd_y0u_did_i7_wr0n9`

That's is, we are done.
