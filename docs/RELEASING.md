# Releasing

1. Update versions and the changelog/release notes.
2. Run `npm install --package-lock=false`, then `npm run ci` on Node 22 and Node 24.
3. Inspect `artifacts/dsh-docker-services-*.tgz` with `npm pack --dry-run` or
   `tar -tzf`; it must contain compiled plugin files and no `.env`, state,
   node_modules, controller configuration, or test fixture secret.
4. Sign/tag the commit and publish only the plugin workspace after review.
   The privileged controller is deployed separately from source or a reviewed
   container image; publishing a DSH plugin must not deploy controller code.
5. Include breaking protocol/configuration changes in the release notes and
   retain prior controller support during the documented migration window.
