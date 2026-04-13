# UniFi Protect NodeServer for ISY/PG3x

Integrates UniFi Protect cameras with the ISY/iOX home automation controller via PG3x. Each camera appears as a node with real-time motion and smart detection drivers that reflect live state — true while detection is active, false when it ends.

## Features

- Real-time motion and smart detection via WebSocket (no polling delay)
- Per-camera drivers: Motion, Person, Vehicle, Animal, Package
- Camera connection state monitoring
- Doorbell ringtone, ring volume, and repeat times control
- Ringtone names fetched dynamically from Protect and shown by name in ISY dropdowns
- Local API only — no Ubiquiti cloud required

## Requirements

- UniFi Protect controller (UDM Pro, UDM SE, UCK Gen2+, etc.)
- UniFi OS 2.0+
- A local admin account on the UniFi controller (not a Ubiquiti cloud account)

## Installation

Add the nodeserver in PG3x:

- **GitHub URL**: `https://github.com/csteenwyk/udi-unifiprotect-poly`
- **Executable**: `unifiprotect-poly.py`

## Configuration

Set the following in Custom Parameters:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `host` | IP or hostname of your UniFi controller | |
| `port` | HTTPS port | `443` |
| `username` | Local UniFi OS account username | |
| `password` | Local UniFi OS account password | |
| `verify_ssl` | Verify SSL certificate | `false` |

### Creating a local account

In the UniFi console, go to **Settings → Admins & Users → Add Admin** and create a local-access-only account. View Only or Protect Manager role is sufficient.

## Camera Node Drivers

| Driver | Description |
|--------|-------------|
| Connected | Camera is online and connected |
| Motion | Motion detected |
| Person | Person detected |
| Vehicle | Vehicle detected |
| Animal | Animal detected |
| Package | Package detected |
| Ring Volume | Doorbell ring volume (0–100%) |
| Repeat Times | Number of times the ringtone plays (1–5) |
| Ringtone | Current ringtone (shown by name) |

Detection drivers stay true for as long as the event is active. They clear automatically when Protect closes the event.

Ring Volume, Repeat Times, and Ringtone are only relevant for cameras with speakers (doorbells). They are updated on startup and when queried.

## Camera Node Commands

| Command | Description |
|---------|-------------|
| Set Ringtone | Choose a ringtone by name from the dropdown |
| Set Ring Volume | Set the doorbell ring volume (0–100%) |
| Set Repeat Times | How many times the ringtone plays per ring (1–5) |
| Query | Refresh all drivers from the Protect API |

## License

MIT — see [LICENSE](LICENSE)
