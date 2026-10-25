# Architecture

Hexagonal, grouped by capability. Core holds the rules and knows no technology; adapters
translate. Checked by `ArchitectureTest`.

```text
com.vpbank.dcp.auth
├── core/<capability>/          JDK only: service, its ports, commands/results, values
└── infrastructure/
    ├── adapter/in/web/...      HTTP in
    ├── adapter/out/<tech>/     HTTP partners (Customer, Keycloak, Notification)
    ├── persistence/            MySQL through Spring JdbcClient and plain SQL
    └── config/                 wiring and validated settings only
```

- A port (interface) exists only for something outside core: MySQL, an HTTP partner.
- No inbound `*UseCase` interfaces: the controller calls the service class.
- The database is **keys only** (no CHECK, no FOREIGN KEY). Value lists, paired columns and
  ownership are checked in code; only races are stopped by UNIQUE keys. See
  `authentication-service-src/docs/db-phases/README.md`.
- Migrations follow the design phases: `V1__identity.sql` is phase 1.
