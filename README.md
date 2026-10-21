# Saphira QRMem

QRMem is a local shared-memory fabric for agents. It has sixteen screens; one
agent owns each screen for writing, while every connected agent may read every
screen. Every screen has three aligned 4096×4096 one-bit planes:

- red — one independently scannable QR Code for each of the 80 records;
- green — record occupancy;
- blue — records changed since the declared baseline.

The QR plane is visual, recoverable memory. A record keeps its logical address
`(fabric_id, screen, block, slot)` and one QR symbol is rendered for that exact
location. Logical blocks remain groups of five slots; visually, records occupy
a deterministic 10-column × 8-row grid.

## Quick start

Build once:

```sh
make
```

In one terminal, start the isolated development fabric:

```sh
./start_server.sh
```

It deliberately uses `/qrmem-dev` and `/tmp/qrmem-dev.sock`, not the default
fabric. Stop it with `Ctrl-C`.

Configure an MCP client to run:

```text
./build/saphira-qrmem --stdio --agent AGENT-NAME \
  --aperture /qrmem-dev --socket /tmp/qrmem-dev.sock --no-snapshot
```

The `--stdio` process is an MCP window; it must connect to an already-running
`--serve` process.

## Agent workflow

1. Call `qrmem_status` and choose an unowned screen.
2. Call `qrmem_join(screen=N, project="...")`.
3. Call `qrmem_write(screen=N, block=B, slot=S, type="word", text="...")`.
4. Use `qrmem_read` for one record, `qrmem_decode_region` for several, and
   `qrmem_index` when an indexed write supplied a key.
5. Call `qrmem_mark_baseline(screen=N)` when the current page is the reference
   state. Later writes mark only their own blue viewport.

There is one writer per screen. A claim on somebody else's screen is refused;
reads are never gated. Record UUIDs name records, while block and slot name
their current location. A move changes location but preserves UUID; a copy
mints a new UUID.

## See and scan a QR tile

Export and view a populated tile:

```sh
./capture_display_qr.sh 0:0:0
```

The helper writes a timestamped one-bit PBM beneath `/tmp`, verifies it with
`zbarimg` when installed, then opens it with `imv`. Set `QR_VIEWER` to use a
different viewer. It exports the red plane only: green and blue are meaningful
visual state but must not contaminate a phone-scannable image.

The raw CLI form is:

```sh
./build/saphira-qrmem --export-tile SCREEN:BLOCK:SLOT \
  --output /tmp/record.pbm --aperture /qrmem-dev
zbarimg --raw /tmp/record.pbm
```

## Verification

```sh
make check
```

This builds the standalone binary, checks for forbidden musl/database/TLS
dependencies, writes a record into a temporary RGB fabric, tests red/green/blue
semantics, exports a QR image, and independently decodes that image with ZBar.

## Current boundaries

This repository is intentionally local and experimental. Bearer capabilities,
coordinate-preserving legacy migration, training-frame manifests, full
image-to-record import/recovery, and physical-phone capture validation are not
yet implemented. Do not represent those as working features.

The current MCP control socket is a local same-user coordination mechanism; it
is not a hostile-same-UID security boundary.
