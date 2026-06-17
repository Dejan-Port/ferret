# Contributing to Ferret

Thanks for your interest. Ferret is early-stage but production-tested, and contributions are welcome.

## Reporting bugs

Open an issue at [github.com/Dejan-Port/ferret/issues](https://github.com/Dejan-Port/ferret/issues).

Include:
- Ferret version (`pip show ferret-agent`)
- Python version and OS
- Minimal reproduction steps
- Relevant logs (`journalctl -u ferret-agent -n 50` or `ferret --log-level DEBUG`)

For security vulnerabilities — **do not open a public issue**. Email [dkocic@servisport.org](mailto:dkocic@servisport.org) directly.

## Suggesting features

Open an issue with the `enhancement` label. Describe the use case, not just the feature — what problem are you trying to solve?

## Submitting a pull request

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Run the tests: `python -m pytest`
4. Open a PR with a clear description of what changed and why

### Code style

- Python 3.10+, no external formatters required
- Keep the agent lightweight — it runs on RPi, routers, PLCs
- No new dependencies without discussion
- No breaking changes to the WebSocket protocol without a version bump

### Areas where help is most welcome

| Area | What's needed |
|------|---------------|
| Windows agent | TUN support on Windows (wintun or similar) |
| QUIC transport | Replace WebSocket with QUIC for better performance |
| TAP mode | Layer 2 bridge (ethernet frames, not just IP) |
| Test coverage | Integration tests for the tunnel protocol |
| Packaging | `.deb`, `.rpm`, Homebrew formula |
| Documentation | Tutorials, deployment guides, video walkthroughs |

## Project structure

```
src/ferret/
  core.py          — WebSocket agent loop
  crypto.py        — ChaCha20-Poly1305, HKDF session keys
  hw_id.py         — hardware fingerprint (HMAC + machine.key)
  handlers/
    tun.py         — Layer 3 VPN (TunHandler)
    proxy.py       — TCP proxy
    ami.py         — Asterisk AMI
    sms.py         — GSM SMS via Asterisk
    ai.py          — Ollama Vision/OCR
  server/
    router.py      — FastAPI routes, WebSocket hub
    registry.py    — SQLite agent/token store
    token_gen.py   — HMAC-SHA256 token generation + validation
    acl.py         — per-agent ACL rules
    audit.py       — event audit log
  cli/
    agent.py       — ferret CLI entrypoint
    server.py      — ferret-server CLI
    tun_client.py  — ferret-tun VPN client
    db_crypt.py    — ferret-db LUKS encrypted storage
```

## License

By contributing, you agree that your contributions will be licensed under the same terms as the project (SSPL-1.0 for server components, AGPLv3 for agent components).
