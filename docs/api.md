# API

The core exposes a local HTTP API with Server-Sent Events. All endpoints except
`/api/health` require a bearer token.

## Authentication

```
Authorization: Bearer <token>
```

The token is also accepted as a `?token=` query parameter (used by the
`EventSource` stream).

## Endpoints

### `GET /api/health`

Returns `{ name, version, disclaimer, geolocation }`.

### `GET /api/interfaces`

Returns `{ interfaces: [...], primary_cidr }`.

### `POST /api/scan`

Body:

```json
{
  "cidr": "192.168.1.0/24",
  "port_scan": true,
  "enrich": true,
  "timeout_ms": 1500,
  "ports": [80, 443, 22]
}
```

Returns `{ id, total, targets }`.

### `GET /api/scan/{id}`

Returns the scan state, progress and hosts.

### `GET /api/scan/{id}/events`

Server-Sent Events stream. Event types: `snapshot`, `progress`, `host`, `done`.

### `POST /api/scan/{id}/cancel`

Cancels a running scan.

### `GET /api/snapshots`

Lists stored snapshots.

### `GET /api/snapshots/latest`

Returns the latest snapshot.

### `GET /api/diff`

Returns the change list between the last two snapshots.

### `GET /api/export?format=csv|json|html|xml`

Downloads the latest snapshot in the requested format.

### `POST /api/wol`

Body: `{ "mac": "00:11:22:33:44:55", "broadcast": "255.255.255.255" }`.
