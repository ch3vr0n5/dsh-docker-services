# Releasing

1. Update versions and release notes.
2. Install npm 11.12.1, run `npm run verify:lock`, `npm ci --ignore-scripts`, then
   `npm run ci` on the pinned Node versions. Lock verification requires a
   registry URL and SHA-512 integrity for every fetched package; `devEngines`
   fails closed on another npm version.
3. Run `npm run test:container`. Inspect all four artifacts; each must contain
   compiled entrypoints and the full license, with no tests, `.env`, state,
   node_modules, configuration, or fixture secret. The clean consumer test must
   import plugin client/controller/proxy exports and resolve both bins. The CI
   `test:dashboard-089` gate must rebuild the exact admitted Dashboard source
   with the pinned pnpm/frozen lock and pass the clean consumer on Node 22/24.
4. Run `npm run sbom:generate && npm run sbom:verify`. CI repeats this with the
   digest-pinned Syft 1.30.0 image, emits one CycloneDX SBOM per artifact, binds
   each artifact/SBOM digest in `manifest.json`, verifies package identity and
   generator version, and retains the five files as a release artifact.
5. Sign/tag the reviewed commit and publish shared, controller, proxy, then plugin.
   Publishing packages must not deploy the privileged controller.
6. Document protocol/config migration and retain prior controller compatibility
   for the stated migration window.
