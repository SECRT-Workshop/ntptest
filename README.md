# ntptest
**NTP Server Query and Date/Time Retrieval Tool**
*by [SECRT Workshop](https://secrtworkshop.org)*

`ntptest` queries NTP servers and returns time, stratum, clock offset, round-trip delay, jitter, and full packet diagnostic information. It is statically linked with no runtime dependencies — drop the binary on any compatible Linux system and run it.

---

## Usage

```
ntptest [OPTION]... HOST
```

**Quick examples:**
```bash
# Standard query
ntptest time.google.com

# Send 5 queries and report statistics
ntptest -c 5 -i 2 pool.ntp.org

# ISO 8601 UTC output
ntptest --utc --format="%Y-%m-%dT%H:%M:%SZ" time.cloudflare.com

# Full NTP packet breakdown
ntptest -v ntp.ubuntu.com

# Quiet mode — print timestamp only
ntptest -q time.google.com

# Raw NTP timestamp
ntptest -r time.google.com
```

## Options

| Option | Description |
|---|---|
| `-p, --port=PORT` | Connect to PORT (default: 123) |
| `-t, --timeout=SECS` | Response timeout in seconds (default: 5) |
| `-c, --count=N` | Send N queries and report min/avg/max statistics |
| `-i, --interval=SECS` | Interval between queries when using `--count` |
| `-f, --format=FMT` | Date/time format using `strftime(3)` |
| `-v, --verbose` | Show full NTP packet field breakdown |
| `-r, --raw` | Output raw NTP timestamp values |
| `--utc` | Display times in UTC instead of local time |
| `-q, --quiet` | Suppress decorative output; print time only |
| `--no-color` | Disable ANSI color output |
| `-4 / -6` | Force IPv4 or IPv6 only |
| `--source-port=PORT` | Bind outgoing socket to a specific local port |
| `--help` | Show full help and license information |
| `--version` | Show version information |

## Installation

**Debian / Raspbian / Ubuntu:**
```bash
sudo dpkg -i ntptest_1.0.0_amd64.deb   # x86-64
sudo dpkg -i ntptest_1.0.0_arm64.deb   # ARM 64-bit
sudo dpkg -i ntptest_1.0.0_armhf.deb   # ARM 32-bit
```

**Arch Linux:**
```bash
sudo pacman -U ntptest-1.0.0-1-x86_64.pkg.tar.zst
```

**Manual (any Linux):**
```bash
chmod +x ntptest
sudo mv ntptest /usr/local/bin/
```

## License

`ntptest` is free software, licensed under the **GNU General Public License v3.0 or later**.
You are free to use, modify, and redistribute it under those terms.
See [`LICENSE`](LICENSE) or [gnu.org/licenses](https://www.gnu.org/licenses/gpl.html) for the full text.

## A Note on Naming

There may be other tools out there that share the `ntptest` name — this project is in no way affiliated with, derived from, or intended to replace any of them. SECRT Workshop built this independently as its own implementation. We have full respect for the work of other developers in this space and have no intention of causing any confusion or conflict. If you have any concerns, please reach out to us directly.

## Contact & Support

**SECRT Workshop**
- Website: [secrtworkshop.org](https://secrtworkshop.org)
- Support: [support@secrtworkshop.org](mailto:support@secrtworkshop.org)
