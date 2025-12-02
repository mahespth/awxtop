# awxtop

Curses-based monitor for AWX / AAP controllers that shows controller topology
and recent jobs in a terminal UI.

## Installation

```bash
pip install .
```

This installs the `aap-monitor` console script.

## Usage

```bash
aap-monitor https://gateway.example.com --username admin
```

You can also pass a bearer token directly:

```bash
aap-monitor https://gateway.example.com --token MYTOKEN
```

Use `--help` to see all flags, including TLS options and polling interval
controls.
