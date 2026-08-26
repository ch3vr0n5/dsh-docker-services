# Dashboard 0.8.9 compatibility evidence

`dsh-docker-services` is admitted by rebuilding Dashboard from its exact source
commit in a clean temporary checkout, not by trusting a floating registry
package or an unexplained local tarball.

| Field | Pinned value |
| --- | --- |
| Repository | `https://github.com/ch3vr0n5/dsh-dashboard.git` |
| Source commit | `091f351c219c2d5acd775b6f09ccb036c125cf77` |
| Package | `dsh-dashboard@0.8.9` |
| `package.json` SHA-256 | `48298381ca568c53f38cd5eafa43f089a6470e978d8e3a612babe1d861ecd6b8` |
| `pnpm-lock.yaml` SHA-256 | `d850f6b0558020a53591300be528fae51d7f19ca3f815a22b61223f7084e7a2d` |
| `pnpm-workspace.yaml` SHA-256 | `7be9e4597f2eca13fe33abfb8691354aa41bb5e698fe4171a45ae265137099d6` |
| pnpm | `11.19.0`, installed from this repository's integrity-pinned npm lock |

The gate verifies the source commit and source-file digests, installs from the
frozen Dashboard lockfile with dependency lifecycle scripts disabled, builds
and packs the exact source, verifies package identity, and installs that result
beside all four local release artifacts in a clean consumer.

Run it after `npm run pack:all`:

```sh
npm run test:dashboard-089
```

CI runs this independently on Node 22.19.0 and 24.0.0. Updating the peer
admission requires a reviewed commit/hash/toolchain refresh here and in the
gate. This keeps `>=0.7.0 <0.9.0` backed by reproducible exact-source evidence.
