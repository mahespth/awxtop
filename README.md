# awxtop

Curses-based monitor for AWX / AAP controllers that shows controller topology
and recent jobs in a terminal UI. Works with:

- AAP 2.5+ via gateway (`https://gateway.example.com/`)
- AAP 2.4 / AWX directly against the controller (`https://controller.example.com/`)

## Author

Created by Mahesh Parthasarathy (mahespth).

## Installation

```bash
pip install .
```

This installs the `awxtop` console script.

## Usage

```bash
awxtop https://gateway.example.com --username admin
```

You can also pass a bearer token directly:

```bash
awxtop https://gateway.example.com --token MYTOKEN
```

When pointing directly at a controller without a gateway (AAP 2.4 / AWX), use
the controller URL, e.g. `awxtop https://awx.example.com --token ...`

### Gateway health view

Pass one or more gateways to enable the gateway health panel:

```bash
awxtop https://gateway.example.com --token MYTOKEN --gateway https://gateway.example.com
```

During the UI:
- Press `g` to toggle a rolling graph of gateway status.
- Press `G` to toggle the graph plus the accumulated error messages and counts.
  Press again to hide.
- Press `v` to view a job (full screen).
- Press `i` to toggle inline job info.
- Press `h` or `?` for the help popup listing keys.
- Press `q` or `ESC` to quit.

Use `--help` to see all flags, including TLS options and polling interval
controls.

## Project updates

See `MAINTAINERS.md` for maintainer info and submission guidelines.
