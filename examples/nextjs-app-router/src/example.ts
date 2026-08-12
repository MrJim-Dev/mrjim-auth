/**
 * Stable, dependency-light entry point for contract tests and documentation
 * tooling. The Next App Router pages live under `src/app`; these pure helpers
 * keep the example's permission and request-boundary behavior easy to test.
 */
export {
  hasPermission,
  navigationForPermissions,
  navigationItems,
  type NavigationItem,
} from "./lib/navigation.js";
export {
  credentialsFrom,
  readJsonObject,
  readObject,
  recoveryFrom,
  requiredText,
  type AuthFields,
  type RecoveryFields,
} from "./lib/route-contracts.js";
