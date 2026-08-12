export interface NavigationItem {
  readonly href: string;
  readonly label: string;
  readonly permission?: string;
}

export const navigationItems: readonly NavigationItem[] = [
  { href: "/profile", label: "Profile" },
  { href: "/invoices", label: "Invoices", permission: "invoice.read" },
  { href: "/admin/users", label: "Admin", permission: "auth.users.manage" },
];

export function hasPermission(permissions: readonly string[], required: string): boolean {
  const segments = required.split(".");
  const resourceWildcard = segments.length > 1 ? `${segments.slice(0, -1).join(".")}.*` : `${required}.*`;
  return permissions.includes(required) || permissions.includes("*.*") || permissions.includes(resourceWildcard);
}

export function navigationForPermissions(permissions: readonly string[]): readonly NavigationItem[] {
  return navigationItems.filter((item) => item.permission === undefined || hasPermission(permissions, item.permission));
}
