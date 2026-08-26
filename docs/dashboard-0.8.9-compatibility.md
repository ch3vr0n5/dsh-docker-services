# Dashboard 0.8.9 Compatibility Evidence

The `dsh-docker-services` plugin is admitted through the exact Dashboard
release artifact below, not a floating registry version.

| Field | Pinned value |
| --- | --- |
| Dashboard repository | `https://github.com/ch3vr0n5/dsh-dashboard.git` |
| Release source commit | `091f351c219c2d5acd775b6f09ccb036c125cf77` |
| Package identity | `dsh-dashboard@0.8.9` |
| Artifact SHA-256 | `524527b8139967c0967aaa86be1fbecd2fc6a151f6ffeb681f5510aeee86129b` |

The recorded artifact was made from a clean checkout at the source commit.
It is intentionally pinned: a different tarball—even one claiming the same
version—must not be used as compatibility evidence without refreshing this
record in review.

## Re-run the admission test

With the recorded artifact available:

```sh
DSH_DASHBOARD_TARBALL=/path/to/dsh-dashboard-0.8.9.tgz npm run test:dashboard-089
```

The command verifies the artifact digest and its package identity, then
installs all four packed `dsh-docker-services` artifacts plus that exact
Dashboard peer into a fresh temporary consumer and imports the public entry
points.

## Recreate an artifact deliberately

Only do this to refresh the evidence in a reviewed change:

```sh
git clone https://github.com/ch3vr0n5/dsh-dashboard.git dsh-dashboard-0.8.9
git -C dsh-dashboard-0.8.9 checkout 091f351c219c2d5acd775b6f09ccb036c125cf77
git -C dsh-dashboard-0.8.9 diff --exit-code
corepack pnpm --dir dsh-dashboard-0.8.9 install --frozen-lockfile
corepack pnpm --dir dsh-dashboard-0.8.9 pack --pack-destination /tmp/dashboard-artifact
shasum -a 256 /tmp/dashboard-artifact/dsh-dashboard-0.8.9.tgz
```

Record the resulting digest above, review the change, and re-run the admission
test. This keeps the peer-range assertion (`>=0.7.0 <0.9.0`) backed by a real,
specific 0.8.9 artifact rather than by an unverified range expansion.
