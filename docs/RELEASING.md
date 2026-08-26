# Releasing

1. Update versions and release notes.
2. Install npm 11.12.1, run `npm run verify:lock`, `npm ci --ignore-scripts`, then
   `npm run ci` on the pinned Node versions. Lock verification requires a
   registry URL and SHA-512 integrity for every fetched package; `devEngines`
   fails closed on another npm version.
3. Run `npm run test:container`. Inspect all three artifacts; each must contain
   compiled entrypoints and the full license, with no tests, `.env`, state,
   node_modules, configuration, or fixture secret. The clean consumer test must
   import plugin client/controller exports and resolve the controller bin.
4. Sign/tag the reviewed commit and publish shared, controller, then plugin.
   Publishing packages must not deploy the privileged controller.
5. Document protocol/config migration and retain prior controller compatibility
   for the stated migration window.
