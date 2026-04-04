# UniFi Protect NodeServer for ISY/PG3x

Integrates UniFi Protect cameras with the ISY/iOX home automation controller via PG3x. Each camera appears as a node with real-time motion and smart detection drivers that reflect live state — true while detection is active, false when it ends.

## Features

- Real-time motion and smart detection via WebSocket (no polling delay)
- Per-camera drivers: Motion, Person, Vehicle, Animal, Package
- Camera connection state monitoring
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

Detection drivers stay true for as long as the event is active. They clear automatically when Protect closes the event.

## License

MIT — see [LICENSE](LICENSE)
