# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Breaking

- `windows_scheduled_task`: `triggers` is now a Set of trigger objects
  (was a List), and the nested `days_of_week` is now a Set of strings
  (was a List) (#324). Configurations need no change — HCL list literals
  convert to sets — but a reorder of triggers or weekdays no longer
  produces a diff. Element references such as `triggers[0].type` no longer
  work on sets: use `tolist(triggers)[0].type` or `one(triggers).type`
  (the data source likewise exposes `triggers` as a set). Two triggers with
  identical attribute values now collapse to a single set element, so
  duplicate identical triggers must be disambiguated (e.g. distinct
  `start_boundary`) instead of listed twice. The `windows_scheduled_task`
  data source exposes the same shapes as sets. State upgrade: prior state containing List values is
  upgraded automatically (v0 -> v1: element values are preserved, only the
  collection kind changes). If a stale state needs manual repair, use
  `terraform state rm` followed by `import`.

- `windows_file`: `attributes` is now a Set of strings (was a List)
  (#324). Configurations need no change and a reorder of attributes no
  longer produces a diff. State upgrade: prior state containing a List is
  upgraded automatically (v0 -> v1, values preserved). If a stale state
  needs manual repair, remove it (`terraform state rm`) and re-import the
  file (content below the import ceiling is read back; otherwise the first
  apply rewrites the file and converges).

- `windows_directory`: the `ensure` attribute (`present`/`absent`) is
  removed (#319). The resource always manages presence: create adopts an
  existing directory, a directory removed out-of-band drops from state,
  and removal is done by destroying the resource (with
  `recursive_delete` controlling non-empty deletes). For
  `ensure = "absent"`, delete the entire `windows_directory` resource
  block and apply (or `terraform destroy -target
  windows_directory.<name>`); do not just delete the `ensure` line.
  State upgrade: prior state containing `ensure` is upgraded automatically
  (the attribute is dropped). The common `ensure = "present"` case converges
  on the next refresh/plan; if a stale state needs manual repair, use
  `terraform state rm` followed by `import`.

- `windows_certificate` data source: `most_recent` now defaults to `false`
  (#328). A subject lookup matching several certificates without an explicit
  `most_recent = true` is an ambiguous-lookup error instead of silently
  resolving to the most recently issued one. Configs relying on the old
  silent pick must set `most_recent = true` explicitly.

### Changed

- Data source hygiene, safe subset (#328):
  - `windows_local_users` / `windows_local_groups`: the shared per-element
    schema builders no longer panic on an unsupported attribute type; they
    return an error diagnostic instead, so a future attribute addition fails
    closed at schema build time.
  - `windows_hostname` Delete is now a pure no-op: no client call is issued
    on destroy (previously it delegated to the documented no-op
    `HostnameClient.Delete`). There is no `restore_on_destroy` flag on this
    resource — a computer name cannot be "un-renamed" — so destroy only logs
    a warning and drops the resource from state.
  - Provider schema validation is stricter: `port` must be 1-65535 and `host`
    must be non-empty when explicitly configured (both still Optional; null
    keeps the `WINDOWS_HOST` / `WINDOWS_PORT` env fallbacks). The `timeout`
    duration parsing diagnostic in Configure is unchanged (already covered).
  - Collection data source IDs are documented as query-IDs (hex SHA-256 of
    the normalised filter set) in the `id` descriptions of
    `windows_network_adapters`, `windows_local_groups` and
    `windows_installed_software`.
  - Verified, no change needed: no singleton data source sets a literal
    `"current"` ID in provider code (remaining `current` strings are test
    labels, import IDs and acc-test resource names).
  - Deferred with notes: schema `Default`s for data source inputs
    (`policy_store`, certificate `store_location`/`store_name`) are blocked —
    `terraform-plugin-framework` v1.19.0 data source attributes have no
    `Default` field (only resource schemas do), so the Go-resolved Read
    fallbacks stay; canonical observed member names as Computed attributes
    and `Configure`-time acceptance helpers are deferred as larger churn.

- Plan-time validation is stricter (fail fast at plan instead of at apply)
  (#324):
  - `windows_firewall_rule`: `local_port`/`remote_port` entries must be
    `Any`, a numeric port (`80`), or a numeric range (`8000-8100`).
  - `windows_file`: `attributes` entries must be one of `hidden`,
    `readonly`, `archive`, `system`, `temporary` (the `system`/`temporary`
    mutual exclusion is still enforced by the cross-field validator).
  - `windows_net_ip_address`: `prefix_length` must be 1-128 (the IPv4 1-32
    refinement against the address family is unchanged).
  - `windows_iis_app_pool`: `identity_username` must be non-empty and shaped
    like `DOMAIN\user` (including `BUILTIN\...` / `NT AUTHORITY\...`), a UPN
    (`user@domain`), or a bare local name.
  - `windows_scheduled_task` already validates `days_of_week` against the
    weekday enum and `triggers` size at plan time; no change there.
  - `windows_scheduled_task.triggers`, its nested `days_of_week`, and
    `windows_file.attributes` are now Sets (see Breaking above).

### Added

- New `windows_dsc_resource` resource (#293): generic gateway managing one
  instance of any DSC resource on the target host through
  `Invoke-DscResource` (`Test`/`Set`/`Get`). Every operation first checks
  the Local Configuration Manager (`Get-DscLocalConfigurationManager`) and
  fails closed with `lcm_conflict` (with remediation text) when the node
  uses Pull refresh mode or reports a busy/pending LCM state; LCM settings
  are never changed. The resource schema is fetched per operation with a
  scoped `Get-DscResource -Name -Module` query (never unfiltered) and
  property values are coerced and validated pure-Go (string/int/bool/list,
  one-level embedded objects, ValueMap allow-lists, mandatory/Key checks).
  Convergence is Test-driven (`Set` only on drift, verified by a follow-up
  `Test`, else `not_converged`). Property values travel on stdin as a JSON
  document plus a separate credential line rebuilt server-side into
  `PSCredential` objects; only module/resource names reach the script body
  (via `psQuote`). Credential `Get` output is redacted (null-dropped) into
  the informational `current_state_json`, which never drifts.
  `module_name`/`resource_name` are Required + ForceNew, `module_version`
  pins an exact version (else the highest installed, reported in
  `resolved_module_version`), `properties` is a Required dynamic object,
  `credential_properties_wo` is an Optional Sensitive WriteOnly map keyed by
  property name (+ `credential_properties_wo_version` rotation counter,
  mirroring `windows_service`), `destroy_properties` is an Optional dynamic
  object applied with `Set` on destroy (full replacement, e.g.
  `Ensure = "Absent"`; unset means state-only destroy).
  `in_desired_state` reports the last `Test` outcome and is always planned
  as true so a failed Test produces an update plan; `reboot_required` warns
  (the provider schedules no reboot). The ID is
  `<module>|<resource>|<sha256 of the canonical key-properties JSON>` (Key
  properties, else mandatory, else sorted-all). Import is unsupported (the
  gateway cannot reconstruct property authorship; write matching config and
  let the first apply adopt the state). `timeouts` default to 30m
  (create/update/delete) and 10m (read). No data source in v1.

- New `windows_ntp` resource and `windows_ntp` data source (#287):
  manages the Windows Time service (W32Time) time source singleton on the
  target host — sync `type` (`NTP`, `NT5DS`, `AllSync`, `NoSync`), the
  ordered NTP peer list (`W32Time\Parameters\NtpServer`, `addr,flags`
  space-separated, flags default `0x9` and normalised lower-case), the
  `special_poll_interval_seconds` (`NtpClient\SpecialPollInterval`,
  16-86400), the `reliable` flag (`Config\AnnounceFlags` `5`/`10`), the
  NTP server role (`NtpServer\Enabled`) and the max
  positive/negative phase corrections. Writes go through
  `Set-ItemProperty` (values via `psQuote`) followed by
  `w32tm /config /update` (exit-code gated) and an optional
  `w32tm /resync /rediscover` whose failure is a warning, never an
  error; every apply re-reads and verifies. The `W32Time` service is set
  to `Automatic` start and started unless `manage_service` is false (for
  operators whose `windows_service` resource owns W32Time). No
  locale-dependent `w32tm` text is ever parsed: the registry is the
  source of truth and `/query /source` is read as an opaque peer name.
  Peers are required for `NTP`/`AllSync` and forbidden for
  `NT5DS`/`NoSync` (plan-time); warnings cover domain-joined hosts not
  using `NT5DS`, Group Policy overrides, an enabled Hyper-V time-sync
  provider and the UDP/123 firewall implication of the server role. The
  resource ID is the host MachineGuid; delete is state-only unless
  `restore_on_destroy` re-applies the snapshot captured at creation (or
  import) time. Import by any non-empty ID (the live time source is
  adopted). The data source is the singleton read-only view (same type
  name, `timeouts.read`). `timeouts` default to 5m.

- New `windows_eventlog` resource and `windows_eventlog` data source
  (#289): manages the size and retention policy of an existing event log on
  the target host (classic logs such as `Application`, `System`, `Security`,
  and modern channels such as `Microsoft-Windows-PowerShell/Operational`)
  through the .NET `EventLogConfiguration` API (`Get-WinEvent -ListLog`
  plus `SaveChanges()`). The log name is matched literally (a `/` in a
  channel name is part of the name, never a path or wildcard). `name` is
  Required + ForceNew (the Terraform ID); `maximum_size_bytes` (multiple of
  64 KiB, at least 1 MiB, plan-validated) and `retention` (`overwrite` /
  `Circular`, `archive` / `AutoBackup`, `retain` / `Retain`), `enabled` and
  `log_file_path` are Optional+Computed — only configured attributes are
  assigned before `SaveChanges()`, and the re-read state verifies every
  configured property took effect. Frequencies: `enabled = false` on a
  classic log fails closed with `unsupported`; shrinking below the current
  file size warns (Windows applies it after the next clear or archive);
  sizes above 4 GiB on classic logs warn; `retain` on the `Security` log
  warns at plan time (`CrashOnAuditFail` can halt the host); a Group Policy
  `MaxSize` / `Retention` / `AutoBackupLogFiles` value is reported through
  `policy_override` with a warning (the GPO value wins at the next refresh).
  Read drops a log removed out-of-band from state (`not_found`);
  `record_count` / `file_size_bytes` are Computed-only informational
  counters that never drift. Delete is state-only by default; with
  `restore_on_destroy` it re-applies the pre-existing values captured into
  private state at creation (or import) time. Import by exact log name. The
  data source looks up by `name` and reuses the sibling resource default for
  `timeouts.read`. `timeouts` default to 5m.

- New `windows_iis_binding` resource (#285): manages one IIS binding on a
  site on the target host (`New-WebBinding -SslFlags` / `Remove-WebBinding`,
  `AddSslCertificate` / `RemoveSslCertificate`). Identity is
  `<site>|<protocol>|<bindingInformation>` (e.g.
  `web|https|*:443:example.com`, IPv6 bracketed). `site_name`, `protocol`,
  `ip_address` (default `*`, netip canonical), `port` and `host_header`
  (lower-case) are ForceNew; `require_sni` (`SslFlags` bit 0, https plus
  host required), `certificate_thumbprint` (40 hex, https required) and
  `certificate_store_name` (`My`/`WebHosting`) update in place (remove plus
  re-add in one script). Create checks site-exists, then the global
  conflict scan (`already_exists` with an import hint on the site,
  `conflict` naming the other site), then the certificate (present in
  `Cert:\LocalMachine\<store>` with a private key) and the HTTP.sys SSL
  ownership (`ssl_binding_conflict`); the certificate is added with
  binding rollback on failure and the site auto-starts when its
  `serverAutoStart` asks for it. Binding the SSH management port (provider
  port or probed `ManagementPath` `ServerPort`) is refused fail-closed
  with `would_lock_out` before anything is applied. Read matches the exact
  binding; Delete removes the certificate first, then the binding
  (idempotent). `timeouts` default to 10m. No data source in v1.

- New `windows_volume` resource and `windows_volume` data source (#292):
  last of the storage trio — formats one partition on a data disk on the
  target host (`Format-Volume` / `Get-Volume` / `Set-Volume`) and manages its
  volume label in place. Identity is the Get-Volume UniqueId (the
  `\\?\Volume{...}\` object path); the hosting `partition_id` is the
  `windows_partition` ID (`<disk_unique_id>|<guid>` on GPT,
  `<disk_unique_id>|<offset>` on MBR, parsed with the shared
  `ParsePartitionID` helper). Create resolves the disk and the partition by
  the GUID/offset key (never the scan-time number), refuses protected
  storage fail-closed (shared guard with #290/#291), refuses
  already-formatted partitions with `already_formatted` unless
  `allow_format_existing` is set, then formats quick by default (`full_format`
  selects a slow full format) and re-reads. `partition_id`, `file_system`
  (`NTFS`/`ReFS`/`exFAT`/`FAT32`, canonicalized at plan) and
  `allocation_unit_size` (power-of-two 512 B-2 MiB, narrowed per file
  system; `NTFS` 512-65536, `FAT32` 512-32768, `exFAT` 512-2097152, `ReFS`
  4 KiB or 64 KiB only) are ForceNew — changing `file_system` plan-warns
  that replacement reformats and destroys data — while `file_system_label`
  (32 chars for `NTFS`/`ReFS`, 11 for `exFAT`/`FAT32`) updates in place via
  `Set-Volume`. Read by UniqueId drops gone or unformatted (null/RAW)
  volumes from state; Delete is state-only with zero remote calls (volumes
  are never unformatted; the `delete` timeout knob stays exposed but
  unconsumed, like `windows_disk`). Import by UniqueId or drive letter
  (`E:`), resolving the hosting `partition_id` host-side. The data source
  looks up by exactly one of `drive_letter` (`C` allowed: reads never change
  the volume), `unique_id` or `file_system_label` (exact, case-insensitive;
  several matches are an error). `timeouts` default to 30m.

- New `windows_partition` resource (#291): manages one partition on a data
  disk on the target host (`New-Partition` / `Get-Partition` /
  `Resize-Partition` / `Set-Partition` / `Remove-Partition`), including its
  drive letter. Identity is `<disk_unique_id>|<guid>` on GPT and
  `<disk_unique_id>|<offset>` on MBR (never the scan-time partition number,
  which is informational only). Create refuses protected, offline, read-only
  or RAW disks (`disk_not_ready`), checks the largest free extent
  (`insufficient_space` carries it in the message), creates with
  `-AssignDriveLetter:$false` and then assigns the configured letter
  explicitly (upper-cased `D`-`Z`; `A`/`B`/`C` rejected; in use is a
  `drive_letter_in_use` error). `size_bytes` grows in place (shrink refused
  with `shrink_not_supported` in v1); `use_maximum_size` is create-only and
  later growth is not automatic; `offset_bytes`, `gpt_type`
  (`basic_data`/`msr`/`recovery` or GUID, GPT only) and `mbr_type`
  (`IFS`/`FAT32`/`FAT32_LBA`/`EXTENDED`/`NTFS`, hex or decimal byte, MBR
  only) force replacement. The boot/system/EFI/MSR/recovery/pagefile guard
  fails closed with `protected_storage`. Delete destroys the partition and
  its data (docs recommend `lifecycle { prevent_destroy = true }`); a
  missing partition is success. Import by `id`. `timeouts` default to 15m.
  No data source in v1.

- New `windows_disk` resource and `windows_disk` data source (#290):
  adopts a physical disk on the target host (`Get-Disk` / `Set-Disk` /
  `Initialize-Disk`) by exactly one of `unique_id` (the stable identity and
  Terraform ID, preferred), `serial_number`, `location` or `number`
  (scan-time assignment that can shift across reboots, so using it warns).
  Zero matches are an error, several are an `ambiguous_disk` error. The
  resource never creates or destroys disk hardware: Create adopts the disk,
  initializes it to `partition_style` (`GPT` or `MBR`) only when it is RAW
  (anything else with a different style is a `partition_style_mismatch`
  error), enforces `is_offline` / `is_read_only` in place, and Delete only
  drops the adoption from state with no remote call. Disks hosting the OS
  (`is_boot` / `is_system`), the active pagefile, the crash-dump target, or
  clustered disks are refused fail-closed with `protected_storage`, as is a
  disk whose placement cannot be determined (guard shared with #291/#292 in
  the new `internal/winclient/storage_common.go`: selector resolution,
  CIM MI_RESULT/HRESULT-first classification, pure-Go size parsing and GPT
  GUID constants). The resource ID and the data source ID are the disk
  `UniqueId`; `timeouts` default to 10m. Import by UniqueId.

- New `windows_timezone` resource and `windows_timezone` data source
  (#286): manages the system time zone of the remote Windows host, which is
  a singleton — the host always has exactly one, so Create and Update share
  one idempotent Set operation (`Set-TimeZone`, or `tzutil.exe /s
  "<id>_dstoff"` — gated on `$LASTEXITCODE` — when
  `daylight_saving_disabled` is true), Read refreshes from the live host and
  never removes the resource from state, and Delete makes no remote change
  unless `restore_on_destroy` re-applies the pre-existing values captured
  into private state at creation (or import) time. Windows IDs are used
  (e.g. `Romance Standard Time`); IANA IDs such as `Europe/Paris` are
  rejected at plan time with a hint. Exposes `display_name`,
  `base_utc_offset`, `supports_daylight_saving_time`, the live
  `current_utc_offset` (all formatted server-side in invariant culture) and
  `tzautoupdate_enabled`, which warns on every operation while the
  `tzautoupdate` service may move the zone out from under Terraform. The
  Terraform resource ID is anchored on the host MachineGuid. `timeouts`
  default to 5m on the resource and on the singleton data source.

- New `windows_local_groups` collection data source (#298): read-only
  inventory of every local group on the remote Windows host in a single
  round-trip — the sibling collection of `windows_local_group`. Every
  `groups` element carries the singular data source attribute set (`sid`,
  `name`, `description`) plus `is_builtin` (derived Go-side from the SID
  `S-1-5-32-*` BUILTIN prefix) and the `members` list (`name`, `sid`,
  `object_class`, `principal_source`), which is null unless
  `include_members` is true. `names` and `sids` double as exact-match
  filters (host-side `Where-Object`, sets) and as convenience outputs in
  group order; `name_regex` (RE2, Go-side), `include_builtin` (null defaults
  to true) and `include_members` (null defaults to false) narrow further.
  `groups` is sorted by name (case-insensitive), members by member SID; an
  empty match is a valid empty list. The data source ID is the hex SHA-256
  of the normalised filter set. Membership reuses a shared `Get-LgmMembers`
  projection: Tier 1 (`Get-LocalGroupMember`) captures the live
  `ObjectClass`, tiers 2/3 (`Win32_GroupUser`, `net localgroup`) report
  `Unknown`. Orphaned SIDs keep an empty member `name` on this path; the
  member resource keeps its own `""`-to-SID coercion untouched. Backed by
  the new `winclient.LocalGroupLister` interface (`List` on the existing
  `LocalGroupClient`); running on a domain controller (`DomainRole >= 4`)
  is a typed `unsupported_on_domain_controller` error.
  `timeouts.read` defaults to 10m like the other collection-family data
  sources.

- New `windows_domain_membership` data source (#299): singleton read-only
  view of the sibling resource's observed state — `part_of_domain`, the DNS
  `domain` (empty when workgroup-joined, never the workgroup name), the
  `workgroup` (empty when joined), `computer_name`, `dns_host_name` with
  `fqdn` as its alias, the NetBIOS `netbios_domain` (Win32_NTDomain with a
  first-DNS-label fallback, empty when not joined), the `domain_role`
  (Win32 0-5 mapped to its documented name; unknown values are a hard
  error), `pending_reboot`, the `secure_channel_ok` result (`null` when
  the host is not joined or when `check_secure_channel` is `false`), and
  the stable `machine_id` (HKLM MachineGuid) as the data source ID.
  `check_secure_channel` (Optional+Computed, default `true`) skips the
  `Test-ComputerSecureChannel` probe for inventory-only reads. Reuses the
  sibling resource's `winclient.DomainMembershipClient` via a new
  `ReadWithOptions` method (`Read` keeps its historical probed behavior, so
  the resource is untouched); `timeouts.read` defaults to 2m.

- New `windows_iis_app_pool` resource and `windows_iis_app_pool` data
  source (#283): manages an IIS application pool on the target host
  (`WebAdministration`: `New-WebAppPool`, `Get-ItemProperty` /
  `Set-ItemProperty IIS:\AppPools\<name>`, `Remove-WebAppPool`,
  `Start-WebAppPool` / `Stop-WebAppPool`). Every non-identity attribute is
  Optional+Computed — only configured attributes are enforced, unconfigured
  ones reflect the observed value (same semantics as
  `windows_firewall_profile`). A `SpecificUser` identity takes
  `identity_username` plus the WriteOnly `identity_password_wo`, which
  travels on stdin, never reaches state or logs, and is re-sent only when
  `identity_password_wo_version` changes (same pattern as
  `windows_local_user`). Runtime `state` (`Started` / `Stopped`) is enforced
  only when configured. Create refuses existing pools with an import hint
  (half-created pools are deleted best-effort); Delete refuses with `in_use`
  while sites or applications still reference the pool, listing them. This
  change also delivers the shared IIS helper (`internal/winclient/iis_common.go`):
  the PowerShell prelude (InvariantCulture, `Ensure-IIS` detection of
  W3SVC/WAS + `WebAdministration` with an actionable `iis_not_installed`
  error pointing at `windows_feature` `Web-Server`), the shared `Classify-IIS`
  fragment, IIS TimeSpan <-> minutes conversion, pool-name validation, and a
  3-attempt retry (short backoff) of writes that hit the
  `applicationHost.config` file-has-changed-on-disk flake.

- New `windows_iis_site` resource and `windows_iis_site` data
  source (#284): manages an IIS site on the target host
  (`WebAdministration`: `New-Item IIS:\Sites\<name> -Bindings @()`,
  `Get/Set-WebConfigurationProperty` for the root application
  (`applicationPool`, `enabledProtocols`, `preloadEnabled`), the root
  virtual directory (`physicalPath`) and the XPath-escaped site filters,
  `Set-ItemProperty IIS:\Sites\<name>` for `serverAutoStart`,
  `logFile.*` and `limits.*`, `Remove-Website`, `Start-Website` /
  `Stop-Website`). The site is always created with zero bindings — the
  `bindings` attribute is a Computed-only read-only view (`protocol` plus
  `binding_information`) owned by `windows_iis_binding` (#285).
  `name` is Required + ForceNew (the Terraform ID); `site_id` is
  Optional+Computed + ForceNew (when unconfigured IIS allocates the
  lowest free ID itself, 1-4294967295 when set); `physical_path` is
  Required and updated in place, with a host-side `%SystemDrive%`
  expansion plus a literal `Test-Path` existence check (`path_not_found`,
  never `mkdir`); every other setting is Optional+Computed — only
  configured attributes are enforced, unconfigured ones reflect the
  observed value (same semantics as `windows_iis_app_pool`). Create
  refuses existing sites with an import hint and colliding IDs with
  `id_conflict` (naming the conflicting site); a missing pool or path
  yields `app_pool_not_found` / `path_not_found`. A configured
  `state = "Started"` on a site with no bindings leaves the site
  `Stopped` with a warning (IIS cannot run an unbound site) instead of
  failing, and a plan modifier suppresses the resulting diff while the
  site stays unbound. `timeouts` default to 10m. Import by site name.

- New standalone `windows_network_adapters` collection data source (#295):
  read-only inventory of every adapter on the remote Windows host with no
  sibling resource — `name`, `interface_index`, `interface_description`,
  `mac_address`, the derived `status` (`Up`/`Disconnected`/`Disabled`/
  `NotPresent` from the `InterfaceOperationalStatus`/`MediaConnectState`/
  `AdminStatus` numeric triple), `admin_enabled`, `link_speed_bps`
  (`ReceiveLinkSpeed`), `media_type` / `physical_media_type` (documented
  NDIS names, `""` when unknown), `is_physical` / `is_virtual`, `vlan_id`,
  the `driver_*` fields, per-family `mtu_ipv4` / `mtu_ipv6` (`null` when the
  family is unbound — 0 is never a valid MTU), `dhcp_enabled`, the sorted
  `ipv4_addresses` / `ipv6_addresses` (canonical CIDR, host bits preserved,
  link-local kept), `default_gateways`, `dns_servers`, `network_category`,
  and the advisory `is_management` flag. Optional filters: `names` (exact,
  case-insensitive), `name_regex` (RE2), `mac_address` (any common
  spelling), `status`, `physical_only` and `include_hidden` (only the names
  and the two bools reach the host; the rest filter Go-side). A single
  round-trip collects `Get-NetAdapter` plus the bulk `Get-NetIPInterface` /
  `Get-NetIPAddress` / `Get-NetRoute` (default routes) /
  `Get-DnsClientServerAddress` / `Get-NetConnectionProfile` collections
  joined by interface index. `adapters` is sorted by `interface_index`; an
  empty match is a valid empty list. The data source ID is the hex SHA-256
  of the normalised filter set. Backed by a new
  `winclient.WindowsNetworkAdaptersClient` (`List`); `timeouts.read`
  defaults to 10m like the other net-family data sources.

- New standalone `windows_os_info` data source (#294): read-only view of
  the OS inventory of the remote Windows host with no sibling resource —
  `product_name`, `version`, `build_number` / `ubr` (combined as
  `full_build`), `display_version`, `edition_id`, the numeric `sku` with
  its `sku_name`, `installation_type`, `is_server` / `is_server_core`,
  `product_type` (Workstation/DomainController/Server), `architecture`
  (x86/x64/arm/arm64), `install_date`, `last_boot_time`, `system_drive`,
  `windows_directory`, `os_language`, `powershell_version`; the stable
  machine ID (HKLM MachineGuid) is exposed as the data source ID (`"current"`
  fallback when empty). Unknown SKU / product / architecture codes degrade
  to `""` instead of erroring. Backed by a new `winclient.OSInfoClient`
  (`Read` in a single round-trip via the shared `runEnvelope` helper);
  `timeouts.read` defaults to 1m. Also amends ADR-0009 with the standalone
  and collection data source conventions (plural collection names, new
  winclient file pair, sorted `ListNestedAttribute` outputs with empty as
  valid, dedicated `<R>Lister` interface) and records that the `_info`
  suffix ban only disambiguates sibling pairs.

- New standalone `windows_installed_software` collection data source
  (#296): read-only inventory of the Uninstall registry hives on the
  remote Windows host — `name`, `version`, `publisher`, `install_date`
  (YYYY-MM-DD, `""` when missing or unparseable), `install_location`,
  `product_code` (MSI ProductCode GUID normalised to upper-case with
  braces, `""` for non-MSI key names), `is_msi`, `architecture` (`x86`
  for the WOW6432Node hive, otherwise the host architecture),
  `scope` (`machine`/`user`) with `user_sid`, `estimated_size_kb`,
  `uninstall_string` / `quiet_uninstall_string` and `registry_key`.
  Optional filters: `name_regex`, `publisher_regex` (RE2, Go-side),
  `product_code` (any common spelling, the only filter pre-applied
  host-side), `include_system_components`, `include_updates` and
  `include_user_installs` (additionally enumerates the Uninstall keys of
  the loaded per-user hives under `HKU`). `packages` is sorted by name
  (case-insensitive), then version, then registry key; an empty match is
  a valid empty list, and `skipped_entries` counts keys skipped because
  their values were unreadable (DisplayName-less keys are silently
  omitted, not counted). The machine hives are shared with
  `windows_legacy_package` through the new
  `UninstallRegistryHivePaths` constant (kept aligned by test);
  `Win32_Product` is never queried. Backed by a new
  `winclient.WindowsInstalledSoftwareClient` (`List`, single
  round-trip); `timeouts.read` defaults to 10m like the other
  collection-family data sources.

- New `windows_local_users` collection data source (#297): read-only
  inventory of every local user account on the remote Windows host in a
  single round-trip — the sibling collection of `windows_local_user`.
  Every `users` element carries the singular data source attribute set
  (`sid`, `name`, `full_name`, `description`, `enabled`,
  `password_never_expires`, `user_may_not_change_password`,
  `account_never_expires`, `account_expires`, `last_logon`,
  `password_last_set`, `principal_source`) plus `is_builtin` (derived
  Go-side from the SID RID: numeric and below 1000), with `names` and
  `sids` convenience lists in the same order. Optional filters:
  `name_regex` (RE2 on the SAM name, case-sensitive unless prefixed
  with `(?i)`), `enabled` (null means all) and `include_builtin`
  (null defaults to true). `users` is sorted by name
  (case-insensitive); an empty match is a valid empty list. The data
  source ID is the hex SHA-256 of the normalised filter set. Backed by
  the new `winclient.LocalUserLister` interface (`List` on the existing
  `LocalUserClientImpl`, sharing the exact `Get-UserData` projection and
  Go-side mapping of the sibling `Read` — no new winclient file, a
  documented deviation from the ADR-0009 standalone rule; `LocalUserClient`
  and its fakes are untouched); running on a domain controller
  (`DomainRole >= 4`) is a typed `unsupported_on_domain_controller`
  error since the LocalAccounts cmdlets address the domain database
  there. `timeouts.read` defaults to 10m like the other
  collection-family data sources.

- New `windows_power_plan` resource and `windows_power_plan` data
  source (#288): manages the active power plan singleton on the target
  host — `plan` (a GUID or an alias: `balanced`, `high_performance`,
  `power_saver`, `ultimate_performance`, normalised to the canonical
  GUID at plan time) plus optional per-setting AC/DC overrides
  (`settings` of `subgroup`/`setting` GUIDs or `powercfg` aliases such
  as `SUB_DISK`/`DISKIDLE`, at least one of `ac_value`/`dc_value`,
  `>= 0`). Aliases resolve in Go (plan) and on the host via
  `powercfg /aliases` (subgroup/setting, cached per call); existence
  checks read WMI `root\cimv2\power` (`Win32_PowerPlan` `IsActive`),
  values are written with `powercfg /setacvalueindex|/setdcvalueindex`
  and the plan is activated with `powercfg /setactive` (exit-code
  gated; `Win32_PowerPlan.Activate()` is never called), then verified
  by re-reading `Win32_PowerPlan` + `Win32_PowerSettingDataIndex`.
  `powercfg /query` text is never parsed and GUID-only identity never
  touches the localised `ElementName` (surfaced as informational
  `plan_name`). Missing plans are a `plan_not_found` error unless
  `create_if_missing` duplicates the template
  (`powercfg /duplicatescheme`); DC values are stored even on hosts
  without a battery. The resource ID is the host MachineGuid; delete
  is state-only unless `restore_on_destroy` re-activates the snapshot
  plan and values captured at creation (or import) time, and a
  duplicated plan is deleted on destroy only when inactive.
  `timeouts` default to 5m. Import by any non-empty ID (the live plan
  is adopted). The data source is the singleton read-only view (active
  plan plus the full `plans` list) with `timeouts.read`.

### Fixed

- `windows_dsc_resource`: the provider no longer fails to compile on 32-bit
  targets (`386`, `arm`), which would have broken the next release
  (`math.MaxInt64` compared to a `uint`). Found by the GoReleaser snapshot
  run for #352.

- Transport: a parked SSH/pwsh session is now probed
  (`keepalive@openssh.com` channel request, 5s deadline) before it is
  reused (#342). A session dropped while idle (sshd `ClientAlive*`, NAT or
  firewall idle timeout, host reboot) is replaced by a fresh one before any
  byte of the request is sent, instead of failing with "outcome unknown" or
  hanging until the operation timeout on a half-open connection. On a
  failed probe every parked session is discarded, since they share the
  host's fate. This also makes `TestTransportRecoversFromDroppedSession`
  deterministic (#343).

- `windows_domain_membership`: `ou_path` and `server` are now
  ForceNew (RequiresReplace) instead of warn-and-ignore (#327).
  Changing either now plans a replacement (a new join) instead of
  silently persisting unapplied desire as state, and the `ModifyPlan`
  create-only warning is removed. `Update` now re-reads the live host
  to refresh the Computed attributes (`computer_name`,
  `pending_reboot`, `secure_channel_ok`) instead of copying prior
  state, so an out-of-band reboot or drift is reflected after apply.
  `Update` therefore requires host reachability: an unreachable host
  fails the update instead of keeping prior values, and drift that
  `Read` would drop from state (left domain, joined another domain
  outside a pending reboot) is an `Update` error.

- Secrets hardening (#323): `windows_registry_value` `value_string`
  and `value_binary` are now `Sensitive` (registry payloads may carry
  passwords, tokens or keys, so Terraform masks them in plans and
  state displays). There is no WriteOnly variant: values are read
  back on refresh. `windows_certificate` `pfx_password_wo` now
  `AlsoRequires` `pfx_base64_wo` (a password without its bundle is
  rejected at plan time) and forces replacement like the bundle it
  decrypts. Deliberately unchanged: account/user names stay
  non-Sensitive (only password material is Sensitive); `*_wo_version`
  counters keep their existing shapes (`windows_scheduled_task`
  keeps `Computed` + default `0` with `AtLeast(0)`, the others stay
  `Optional` + `AtLeast(1)`) so existing configurations keep
  applying; legacy (state-persisted) passwords keep value-based
  rotation and do not require a version counter.

- No network I/O in `windows_file` plan (#325): `ModifyPlan` never
  downloads `source_url`. A pinned `source_url_sha256` is used as-is
  for `content_sha256`; an unpinned URL leaves it unknown until apply
  fetches the payload, so an unreachable mirror no longer breaks or
  flaps `terraform plan`. Provider-side downloads (apply) now send
  `User-Agent: terraform-provider-windows`, retry transient failures
  (transport errors, HTTP 5xx) twice with a short backoff, fail fast on
  permanent ones (bad URL, HTTP 4xx, oversized body), and stay bounded
  by the resource `timeouts` (or the 10m download cap, whichever hits
  first). Enabling `source_url_insecure_skip_verify` additionally warns
  at apply time, where the download actually happens.

- Import verification via live Read with timeout (#326):
  `windows_firewall_rule` import now bounds its verify Read with the
  10m resource default (previously unbounded) and still fails closed
  when the rule is missing. `windows_hostname` import no longer trusts
  the ID blindly: it validates the non-empty machine-GUID shape
  (8-4-4-4-12 hex) and verifies the live host under the 10m default
  timeout, failing the import on unreachable hosts, GUID mismatches
  (another machine's ID), or empty reads; the observed live state (not
  the raw ID) seeds the imported state. `windows_feature`
  `install_state` (pure-Computed) no longer carries a schema `OneOf`
  validator: unexpected host spellings surface as a Read-time error
  diagnostic from the state projection instead of schema rejection.

## [0.4.0] - 2026-11-11

### Added

- New `windows_registry_key` resource and `windows_registry_key` data
  source (#280): the resource ensures a registry key exists, optionally
  purges unmanaged value names (`purge_unknown_values` with an explicit
  `managed_value_names` allow-list; the Default value is `""`), and
  optionally removes the key on destroy (`delete_key_on_destroy`, with
  `recursive` for subkey trees). Defaults are no-ops: unknown values are
  only reported in `unknown_value_names`, and the key is left in place on
  destroy. The key never carries value payloads — each `hive/path/name`
  keeps a single owner via `windows_registry_value` — and descriptions
  warn about Group Policy-managed `Policies` paths.

## [0.3.1] - 2026-11-07

### Fixed

- CI (`testacc-lab-container`): attach the `tfacc-win` container to a
  dedicated `tfacc-secondary` NAT network and export the new vNIC alias as
  `WINDOWS_TEST_INTERFACE`, so the `dns_client` / `net_ip_address` /
  `net_route` suites run instead of skipping (#242).

- `windows_net_route`: create and update no longer pass `-PolicyStore
  PersistentStore` to `New-NetRoute` / `Set-NetRoute` — that combination is
  rejected by Windows (`Invalid parameter`, system error 87), so no route
  could ever be created. Both cmdlets now run without `-PolicyStore`, which
  is the Windows default that writes the route to both stores and keeps it
  reboot-surviving; delete drops the filter as well so both copies are
  removed together. Found by running the acceptance suite against a
  secondary NIC (#242).
- Acceptance fixtures `TestAccWindowsDNSClient_Basic` and
  `TestAccWindowsNetIPAddress_Basic`: the update steps redefined an argument
  already set in the base config (`ipv4_server_addresses`, `prefix_length`),
  which HCL rejects — both tests could never pass. The fixtures now take
  the updated values as parameters (#242).

### Removed

- Acceptance skeletons `TestAccWindowsDomainMembership_{Basic,
  DriftDetection,UnjoinOnDestroy,DeleteIsNoOp}`: joining a domain is
  destructive and no CI environment provides a test domain, so they could
  never run. The join/unjoin/drift/delete lifecycle is covered by unit
  tests with a fake transport, and the plan-time guard tests
  (`InvalidDomain`, `MissingCredential`, `UnjoinNeedsStatePassword`) keep
  running in the acceptance suite. The corresponding allow-list entry is
  dropped from `.github/testacc-allowed-skips.json` (#242).

### Changed

- The minimum supported Terraform version is now documented as >= 1.11:
  WriteOnly attributes (e.g. `password_wo`, `content_wo`) require
  Terraform 1.11 and later (#239).

## [0.3.0] - 2026-11-03

### Resources

- New `windows_domain_membership` resource: joins the target host to an
  Active Directory domain (`Add-Computer`) and optionally unjoins it on
  destroy (`Remove-Computer`). The resource ID is the lower-cased domain DNS
  name; the join credential (`join_credential.username` plus exactly one of
  the state-persisted `password` or the WriteOnly `password_wo`) travels on
  stdin and never reaches the script body or logs. The create pre-flight
  refuses already-joined hosts (`already_joined` suggests import,
  `joined_to_other_domain` otherwise). `Add-Computer` runs without
  `-Restart`; when `restart` (default `false`) is set and a reboot is
  pending, a detached reboot is scheduled ~60s after the operation (deferred
  gate mirroring `windows_feature`). `ou_path` is create-only (warns on
  change, never read back); `server`, `restart` and the `unjoin_*` destroy
  behaviour update state-only with no remote action. Destroy is a no-op by
  default; `unjoin_on_destroy` (default `false`) unjoins into
  `unjoin_workgroup_name` (default `WORKGROUP`) and requires the
  state-persisted password because `password_wo` is unavailable at destroy
  time. Read drops the resource from state when the host left the domain
  out-of-band and tolerates a domain mismatch while a reboot is pending.
  Import adopts the domain DNS name and verifies the live join (#225).

- New `windows_certificate` resource: imports one X.509 certificate into a
  Windows certificate store on the target host (`Cert:\<location>\<store>`
  via `X509Certificate2` / `X509Certificate2Collection` + `X509Store.Add`).
  Exactly one payload: `certificate_pem` (stored in state in normalised
  form) or the WriteOnly `pfx_base64_wo` bundle plus `pfx_password_wo` and
  the `pfx_wo_version` rotation counter (changing only the bundle without
  bumping the version is a no-op). Payload and password travel on stdin and
  never reach state or logs. `store_location` (default `LocalMachine`) and
  `store_name` (default `My`), the payload and `exportable` (PFX only,
  default `false`) are ForceNew; only `friendly_name` updates in place and
  `delete_private_key` (default `true`) deletes the key on destroy. `Root`
  / `AuthRoot` stores warn (trust anchors), `CurrentUser` trusted roots are
  refused. Already-present thumbprints suggest import instead of failing
  opaquely; import adopts `<store_location>/<store_name>/<thumbprint>`
  (keyed certificates import with `pfx_wo_version = 1`, keyless ones with
  their normalised PEM) (#222).

- New `windows_net_route` resource: manages one persistent IP route on one
  network interface of the target host (`New-NetRoute` / `Set-NetRoute` /
  `Remove-NetRoute -PolicyStore PersistentStore`). Static routes to remote
  networks, on-link routes (next hop `0.0.0.0` / `::`) and manually managed
  default gateways. `interface_alias`, `destination_prefix` and `next_hop`
  are ForceNew (the prefix must be canonical masked CIDR, e.g. `10.0.0.5/24`
  is a plan-time error naming `10.0.0.0/24`; the next hop must share the
  prefix family, multicast/loopback rejected); only `route_metric`
  (0-9999, default 256) updates in place. Every mutating operation runs the
  management-path guard (`internal/winclient/mgmtpath.go`): deleting,
  replacing or re-metricing the exact management route is refused
  fail-closed with `management_path_at_risk`, as is a candidate that would
  hijack the SSH return path (more specific covering prefix, or the same
  prefix length with an equal-or-better effective metric via a different
  next hop or interface — ties fail closed); an undeterminable path fails
  closed with `management_path_unknown` unless
  `unsafe_skip_management_check` is set. Pre-flight refuses triplets owned
  by other protocols (`route_owned_by_other_protocol`) and suggests import
  for existing `NetMgmt` triplets (`already_exists`). Import adopts
  `<interface_alias>|<destination_prefix>|<next_hop>` for NetMgmt routes
  only (#231).

- New `windows_net_ip_address` resource: manages one static IP address on one
  network interface of the target host (`New-NetIPAddress` /
  `Set-NetIPAddress` / `Remove-NetIPAddress`). Several resources may target
  the same interface, one per address. `interface_alias` and `ip_address` are
  ForceNew (the address is stored canonically via `netip`); `prefix_length`
  and `skip_as_source` update in place. An IPv4 interface with DHCP still
  enabled needs `disable_dhcp` (tracked in private state, restorable on
  destroy with `restore_dhcp_on_destroy`); duplicate address detection rolls
  the address back. Every mutating operation consults the new shared
  management-path guard (`internal/winclient/mgmtpath.go`: `SSH_CONNECTION`
  primary plus `Get-NetTCPConnection` fallback, computed per risky operation
  and never cached), which refuses fail-closed with `management_path_at_risk`
  / `management_path_unknown` unless `unsafe_skip_management_check` is set.
  The default gateway is deliberately not managed (see `windows_net_route`).
  Import adopts `<interface_alias>|<ip_address>` for Manual-origin addresses
  only (#230).

- New `windows_firewall_profile` resource: tunes a Windows Defender Firewall
  profile (`Domain`, `Private` or `Public`) on the target host
  (`Get-NetFirewallProfile` / `Set-NetFirewallProfile -PolicyStore
  PersistentStore`). A profile always exists, so Create and Update share one
  operation that writes only the configured attributes; Delete makes no remote
  change by default, and with `restore_on_destroy` re-applies the pre-existing
  values captured into private state at creation (or import) time. An SSH
  lockout guard runs fail-closed inside every Apply: tightening the profile
  that carries the provider's own SSH session without an enabled inbound Allow
  TCP rule for the provider port is refused before anything is written.
  Group Policy owns the `ActiveStore` view (divergence documented), and
  GPO-managed `NotConfigured` tri-states are observed as unset rather than
  exposed (#223).

- New `windows_smb_share` resource: manages a single SMB share on the target
  host (`New-SmbShare` / `Set-SmbShare` / `Remove-SmbShare`) plus its
  share-level access entries (`Grant-` / `Block-` / `Revoke-SmbShareAccess`).
  `name` and `path` are ForceNew; the shared directory must already exist
  (manage it with `windows_directory`). When all four of `full_access`,
  `change_access`, `read_access` and `no_access` are omitted the host access
  list is unmanaged, otherwise all four are authoritative (empty revokes the
  level, out-of-band entries — including the `Everyone:Read` default — are
  revoked as stale, a principal may belong to at most one set, grants apply
  before stale revokes). Special (administrative) shares are reported but
  cannot be imported. `encrypt_data` defaults to `false`; enabling it is
  recommended for sensitive data (#221).

- New `windows_dns_client` resource: manages the DNS client settings of one
  network interface on the target host (`Set-DnsClientServerAddress` /
  `Set-DnsClient`). `interface_alias` is Required + ForceNew (exact,
  case-insensitive match; the id is the canonical alias). `ipv4_server_addresses`
  and `ipv6_server_addresses` are Optional + Computed lists in query order:
  `null` leaves the family unmanaged, `[]` resets it to automatic (DHCP) and a
  list replaces the static servers (pure-Go `net/netip` validators: family,
  uniqueness, no unspecified/multicast/broadcast/zone-ID, loopback allowed,
  IPv6 canonicalised with order preserved). `connection_specific_suffix` is
  Optional + Computed with DNS name rules, plus Optional + Computed
  `register_this_connection_address` / `use_suffix_when_registering` flags.
  `reset_on_destroy` (default `false`) resets the managed families to automatic
  and clears the suffix only when set. Static servers are read from the
  `Tcpip`/`Tcpip6` registry; computed `effective_ipv4` / `effective_ipv6` are
  DHCP-inclusive. Create and Update share one idempotent path (Update only
  re-sends configured changes); Read drops the resource when the interface is
  gone. Import by alias adopts both families (automatic imports as `[]`) (#229).

### Data Sources

- New `windows_certificate` data source: read-only lookup of an existing
  certificate by `thumbprint` or `subject` (exactly one), optionally
  narrowed by `store_location` / `store_name`, exposing the observed
  thumbprints, names, validity window, DNS names, key presence and friendly
  name without managing the entry. A subject lookup matching several
  certificates resolves to the most recently issued one when `most_recent`
  is true (the default); zero matches is an error. Reuses the sibling
  resource's `winclient.CertificateClient` (no new winclient code) and the
  sibling resource default for `timeouts.read` (#222).

- New `windows_net_route` data source: read-only lookup of an existing
  persistent route by `destination_prefix`, optionally narrowed by
  `interface_alias` and `next_hop`, exposing the observed interface, next
  hop, metrics, family and protocol. Several matches resolve to the lowest
  `effective_metric` winner with `match_count` telling how many matched;
  zero matches is an error. Reuses the sibling resource's
  `winclient.NetRouteClient.Lookup` (no new winclient code) and the sibling
  resource default for `timeouts.read` (#231).

- New `windows_net_ip_address` data source: read-only lookup of an existing
  static address by `ip_address` alone or together with `interface_alias`,
  exposing the observed interface, prefix length, origin, state, family and
  skip-as-source flag. Zero or several matches is an error listing the
  candidates. Reuses the sibling resource's
  `winclient.NetIPAddressClient.Lookup` (no new winclient code) and the
  sibling resource default for `timeouts.read` (#230).

- New `windows_firewall_profile` data source: read-only lookup of an existing
  firewall profile by `name`, exposing the observed settings (including
  GPO-managed `NotConfigured` tri-states as unset) without managing the
  profile. Reuses the sibling resource's `winclient.FirewallProfileClient.Read`
  (no new winclient code) and the sibling resource default for
  `timeouts.read` (#223).

- New `windows_smb_share` data source: read-only lookup of an existing share
  by `name`, exposing the observed properties, the four access lists and the
  `special` flag without managing the share. Reuses the sibling resource's
  `winclient.SmbShareClient.Read` (no new winclient code) and the sibling
  resource default for `timeouts.read` (#221).

- New `windows_dns_client` data source: read-only lookup of one interface's
  DNS client settings by `interface_alias`, exposing the static server lists
  (automatic families report `[]`), the DHCP-inclusive `effective_ipv4` /
  `effective_ipv6` lists, the suffix, the registration flags and the interface
  index/GUID without managing them. Reuses the sibling resource's
  `winclient.DnsClientClient.Read` and the sibling resource default for
  `timeouts.read` (#229).

## [0.2.0] - 2026-11-01

### Fixed

- `windows_service`: `service_password_wo` rotation never triggered — the
  WriteOnly value is null in state, so Terraform could not detect content
  changes and every `Update` either re-sent the password unconditionally or
  never rotated it. Rotation is now driven exclusively by the new
  `service_password_wo_version` counter (Int64, `Optional`, `AtLeast(1)`,
  following the `windows_local_user` `password_wo_version` precedent):
  changing the version forwards the configured secret to Windows, changing
  only `service_password_wo` without changing the version is a no-op, and a
  version change with no secret supplied fails closed instead of blanking
  the stored credential.
  `service_password_wo` now `AlsoRequires` the version, and the legacy
  `service_password` path is still value-compared for post-import recovery
  (#194).
  Action required: existing `service_password_wo` configurations must add
  `service_password_wo_version = 1` (change the value to rotate).
- `windows_service` CRUD is now bounded by a per-operation `timeouts` block
  (`create`/`read`/`update`/`delete`, 10m defaults): a stalled PowerShell/SSH
  session surfaces a timeout diagnostic instead of blocking Terraform
  indefinitely (#109, #121).
- `windows_firewall_rule` CRUD is now bounded by a per-operation `timeouts`
  block (10m defaults), for the same stalled-transport reason: a firewall
  rule change can sever its own SSH transport (#122, #123).
- The persistent PowerShell session no longer tears down, redials and
  re-executes a deterministically failing script: uncaught script errors on
  a healthy session are reported once, on the existing session, and only
  genuine transport failures trigger the re-establish-and-retry path
  (#124, #125).
- `windows_firewall_rule`, `windows_local_group_member`, `windows_local_user`,
  `windows_registry_value`, `windows_local_group`,
  `windows_environment_variable`, `windows_directory` and now
  `windows_hostname` CRUD are bounded by per-operation `timeouts` blocks
  (10m defaults), completing the campaign that started with
  `windows_service`: a stalled PowerShell/SSH session surfaces a timeout
  diagnostic instead of blocking Terraform indefinitely (#122/#123,
  #126/#132, #133/#135, #139/#141, #148/#149, #150/#151, #154/#156,
  #153/#155).
- Bumped `google.golang.org/grpc` v1.79.3 → v1.83.2 (indirect dependency
  via the plugin-framework transport): `govulncheck` reported three
  reachable vulnerabilities (GO-2026-6443 server panic on missing
  authority/Host headers, GO-2026-6348 HTTP/2 DATA fragmentation OOM,
  GO-2026-6061 xDS RBAC + HTTP/2 transport flaws); the scan is clean after
  the bump. Exposure in practice is local-only (Terraform CLI ↔ provider
  plugin over loopback) (#165).
- `windows_local_group` / `windows_local_user` Create pre-flight errors no
  longer interpolate the raw input name into a PowerShell double-quoted
  string; the already-exists message references the runtime `$existing`
  identity instead, so names containing `$` or backticks render verbatim
  (#167).
- `windows_legacy_package` downloads are integrity-gated at plan time: an
  `http://` `source_url` without `checksum` now fails planning (plaintext
  HTTP lets anyone on the network path substitute an installer that is then
  executed as the SSH user, typically an administrator). A `source_url`
  without any `checksum` warns even over HTTPS, and `md5:`/`sha1:`
  checksums warn as deprecated (both are broken for integrity purposes;
  removal reserved for a future minor). `sha512` is now accepted alongside
  `sha256`, and the resource docs record the threat model (#175).
- The SSH connect phase is now genuinely bounded by the provider `timeout`
  (TCP dial plus handshake, as documented): the handshake connection carries
  a deadline of `min(timeout, context deadline)`, lifted once the handshake
  completes, and cancelling the context aborts a stalled key exchange/auth
  promptly with a context error instead of hanging until the per-resource
  timeouts fire (#169).
- Cancelling a one-shot call no longer races with the SSH session's output
  copy goroutines: `runOneShot` closes the session and waits for
  `session.Run` before reading the captured buffers (#172).
- A transient failure establishing the first persistent session no longer
  pins the client to the slow one-shot transport: only a healthy SSH
  connection that fails the REPL handshake (positively indicating a host
  without `pwsh.exe`) falls back, now with a `tflog` warning recording the
  reason. Dial, handshake and context errors are returned as-is, so the
  operator sees the real cause and the next call still establishes the
  persistent session (#170).
- Target-side downloads (`windows_legacy_package` installer fetch and
  `windows_file` with `download_on = "target"`) share one TLS-safe
  implementation: PowerShell 7 uses the native `-SkipCertificateCheck`
  switch (the old `ServicePointManager` callback was a silent no-op there,
  so `insecure_skip_verify` had no effect), Windows PowerShell 5.1 adds
  TLS 1.2 to the existing protocols instead of replacing the set (TLS 1.0
  and 1.1 are never enabled anymore), and both the protocol set and the
  validation callback are restored afterwards instead of leaking into
  later operations of the shared session (#174).
- Release archives now ship `terraform-registry-manifest.json` both as a
  `<project>_<version>_manifest.json` release asset and inside
  `<project>_<version>_SHA256SUMS`, so the Terraform Registry records
  protocol 6.0 instead of assuming 5.0 (#176).
- Fixed PowerShell injection through Unicode single quotes: `psQuote` now
  doubles every character the PowerShell tokenizer treats as a single quote
  (U+0027, U+2018, U+2019, U+201A, U+201B), mirroring .NET's
  `EscapeSingleQuotedStringContent`. Previously only the ASCII apostrophe
  was escaped, so a value such as `x’; <code>; ’` terminated the string
  literal and executed arbitrary code as the SSH user. `psQuote` /
  `psQuoteList` moved to a dedicated `internal/winclient/psquote.go` with
  table-driven tests, and the last hand-rolled `'%s'` quoting
  (`REG_QWORD` value expression) is routed through `psQuote` (#173).
- `windows_local_user` (`password`/`password_wo`),
  `windows_scheduled_task` (`principal.password`/`principal.password_wo`)
  and `windows_service` (`service_password`/`service_password_wo`) now
  reject values containing carriage return or line feed characters at plan
  time: secrets are streamed over stdin and consumed with `ReadLine()`, so
  anything from the first line break on was silently truncated. The
  diagnostic suggests `trimspace()` for the common `file()` trailing-newline
  footgun and never echoes the secret value. No transport change, no
  `wo_version` counter change (#195).
- `windows_feature`, `windows_legacy_package`, `windows_scheduled_task`
  and `windows_winget_package` Read handlers are now bounded by a new
  `timeouts.read` value (30m/30m/5m/30m defaults, matching the other CRUD
  operations on each resource): a stalled PowerShell/SSH session during
  refresh surfaces a timeout diagnostic instead of blocking Terraform
  indefinitely (#196).
- All 11 data sources now expose a `timeouts { read }` block backed by
  `terraform-plugin-framework-timeouts/datasource/timeouts`: Read is bounded
  by the configured value, defaulting to the sibling resource default (30m
  for `windows_feature` / `windows_winget_package`, 5m for
  `windows_scheduled_task`, 10m for the other eight), so a stalled
  PowerShell/SSH session surfaces a timeout diagnostic instead of blocking
  plan forever. Omitting the block keeps the previous behavior bounded by
  the default (#197).
- `windows_feature` with `restart = true` no longer reboots the host
  mid-apply: `-Restart` is no longer passed to
  `Install/Uninstall-WindowsFeature`, whose synchronous reboot killed the SSH
  session before the result envelope was emitted — surfacing as `Create
  windows_feature failed / SSH transport error during "install" / winclient:
  powershell run: wait: remote command exited without exit status or exit
  signal` with nothing recorded in state. When the operation reports
  `RestartNeeded` and `restart` is true, the script now schedules a detached
  reboot ~60s out (`shutdown.exe /r /t 60`) after that resource's session
  teardown and state write (state removal on the Delete path). The window is
  per-resource: enable `restart = true` on at most one resource per apply (or
  apply reboot-requiring features last/separately), since a later in-flight
  SSH session on the same host can still be dropped by the reboot; scheduling
  is best-effort and never fails the already-successful operation
  (`restart_pending` still records the requirement so the operator can reboot
  manually, and a scheduling failure surfaces a warning). No reboot is
  scheduled when the operation does not require one (#200).
- `windows_file` downloads are integrity-gated at plan time, mirroring the
  `windows_legacy_package` posture (#175): an `http://` `source_url`
  without `source_url_sha256` now fails planning regardless of
  `download_on` (plaintext HTTP lets anyone on the network path substitute
  the payload before it is written to the host). A `source_url` without a
  digest still warns even over HTTPS, now worded around integrity
  verification instead of plan performance — a compromised mirror or
  account could otherwise ship a trojaned payload unnoticed — and
  `source_url_insecure_skip_verify` warns that without a pinned digest it
  voids the only remaining origin check. The resource docs record the
  threat model (#204).

### Added

- New `WINDOWS_TIMEOUT` environment fallback for the SSH dial/handshake
  timeout (Go duration, 30s default): env-only configurations (CI, Terraform
  Cloud) can now tune connection establishment without a provider-block
  attribute. An explicit `timeout` attribute still wins; malformed values
  fall back to the default (#130, #131).
- New `terraform CLI offline suite` CI job: `init`, `fmt -check`,
  `validate` and the mocked `terraform test` from `test/terraform-cli` now
  run on every PR without needing a Windows host or credentials (#134,
  #136).

### Performance

- The SSH transport no longer serialises every call onto a single
  PowerShell session: the client keeps a small bounded pool (new
  `max_sessions` provider attribute, `WINDOWS_MAX_SESSIONS` fallback,
  default 4, cap 32) and serves up to that many calls concurrently against
  one host. The same bound covers the one-shot `powershell.exe` fallback
  (hosts without `pwsh.exe`), so a plan can no longer turn into an
  unbounded dial storm. `max_sessions = 1` reproduces the previous
  behaviour. Stays under sshd's default `MaxSessions 10` out of the box
  (#180).

### Changed

- The `docs` workflow drift gate is now blocking: `go generate ./...`
  (tfplugindocs) on a clean checkout reproduces `docs/` byte-identically —
  the curated per-page content lives in the schema `MarkdownDescription`
  strings and in `examples/`, which the built-in templates render, so no
  per-resource template migration was needed — and any drift now fails CI
  instead of warning. Never hand-edit `docs/`; run `make docs` and commit
  the result (#199).

### Data Sources

- New `windows_file_acl` data source: read-only lookup of the NTFS security
  descriptor of an existing file or directory by `path`, exposing the observed
  `owner`, `owner_sid`, `target_type`, `inheritance_enabled`, `sddl` and
  `effective_access_rules` without managing the DACL. Reuses the sibling
  resource's `winclient.FileACLClient.Read` (no new winclient code) and the
  sibling resource default for `timeouts.read`. Partial fix for #206
  (`file` data source follows in a later PR).
- New `windows_directory` data source: read-only lookup of the observed
  state of an existing directory by `path`, exposing the observed
  `exists_children`, `item_count`, `last_write_time` and `attributes`
  without managing the directory. Reuses the sibling resource's
  `winclient.DirectoryClient.Read` (no new winclient code) and the sibling
  resource default for `timeouts.read`. Partial fix for #206 (`file` data
  source follows in a later PR, pending the content design decision).
- New `windows_legacy_package` data source: read-only lookup of an installed
  MSI/EXE package by `product_id` (MSI ProductCode GUID) or `display_name`
  (exact EXE `DisplayName`), exposing `installed`, `installed_version` and
  `install_date` without managing the package lifecycle. Reuses the sibling
  resource's `winclient.LegacyPackageClient.Read` (no new winclient code) and
  the sibling resource default for `timeouts.read`. Partial fix for #206
  (`file` data source follows in a later PR).
- New `windows_file` data source: metadata-only read-only lookup of an
  existing file by `path`, exposing the observed `content_sha256`,
  `size_bytes` and `last_write_time` without managing the file. Content is
  deliberately NOT exposed: returning file content from a data source would
  persist arbitrary host file bytes (frequently secrets, keys, configs) into
  terraform state on every read/plan, and winclient caps content with
  truncation anyway; metadata + digest covers the stated use cases
  (existence check, hash for triggers block, pre-deploy read). Reuses the
  sibling resource's `winclient.FileClient.Read` metadata path — the host
  computes the digest itself (`Get-FileSha256`, no bytes transferred) and
  the byte-transferring `ReadContent` path stays reserved for resource import
  (no new winclient code) — and the sibling resource default for
  `timeouts.read`. Completes all four data sources for #206.

## [0.1.1] - 2026-10-08

### Fixed

- Release archives restore the `386` and `arm` (GOARM 6) targets for
  `windows`, `linux` and `freebsd`, plus `freebsd/amd64` and
  `freebsd/arm64`. The build matrix had been reduced to
  `windows`/`linux`/`darwin` on `amd64`/`arm64` in v0.1.0, dropping the
  platforms shipped through v0.0.14 (#115).

## [0.1.0] - 2026-10-08

### Added

- New `test/terraform-cli` workspace exercising all 15 resources and 11 data
  sources through the Terraform CLI only (`init`/`fmt`/`validate`, mocked
  `terraform test`, plus `plan`/`apply`/output cross-checks/idempotence/
  `destroy` via `run-tests.sh --apply`). Flag-gated scenarios for container
  limitations (firewall, network packages, Windows feature, hostname rename).
  Live run against `tfacc-win`: 19/19 applied, 5/5 resource-vs-data checks
  PASS. Surfaced provider bugs #99, #100, #101, #102 (documented in the
  suite README with workarounds).

### Performance

- **Breaking (internal):** `internal/winclient.Client` now keeps at most one
  persistent PowerShell session open per client and reuses it across
  `RunPowerShell`/`RunPowerShellWithInput` calls, instead of dialing a fresh
  SSH connection and starting a fresh `powershell.exe` for every call. This
  amortises costly module imports (`windows_feature`'s `ServerManager` import
  alone is ~18s cold) across an entire Terraform run instead of paying them on
  every single call. Calls are serialised onto the shared session; a session
  found to be dead is transparently re-established once before the call is
  retried. `exit` inside a script now terminates the shared session rather
  than just that call — every resource was migrated off `exit 0` to a
  return-value pattern (`windows_feature`, `windows_scheduled_task`,
  `windows_legacy_package`, `windows_winget_package`), so a script that
  reports an error no longer tears down the session it is running in
  (#81).

### Fixed

- `windows_scheduled_task` could not be created with any `settings` block
  (#100): the configured ISO 8601 `settings.execution_time_limit` was passed
  straight to `New-ScheduledTaskSettingsSet -ExecutionTimeLimit`, which takes a
  `[TimeSpan]` ("Cannot convert value PT72H") — and since the attribute is
  Optional+Computed with a default, even an empty `settings` block failed. The
  generated PowerShell now converts the value with
  `[System.Xml.XmlConvert]::ToTimeSpan`. The value is stored as reported and
  compared by duration, so an equivalent spelling (`P3D` versus `PT72H`) does not
  drift. The attribute is validated as an XSD duration of days or less: year and
  month components are rejected because `ToTimeSpan` would silently approximate
  them as 365- and 30-day intervals. Trigger `execution_time_limit`/`delay` take
  no such conversion — they are string-typed CIM properties assigned verbatim —
  so they keep the full XSD grammar (`P3D`, `P1DT2H`, `P1M4DT2H5M`) and are
  compared verbatim. `PT0S` runs indefinitely on both, as documented by
  Microsoft.
- The persistent REPL session (#81) deadlocked on cold calls into chatty
  CIM/CDXML-backed cmdlets (`windows_local_user`, `windows_firewall_rule`
  reads use `Microsoft.PowerShell.LocalAccounts`/`NetSecurity`), hanging the
  provider until Terraform's own timeout. `readReplResponse` read stdout to
  completion before touching stderr; `x/crypto/ssh`'s `Session.StderrPipe`
  documents a fixed buffer shared between the two streams, so a response
  chatty enough on stderr to fill it before its stdout end marker blocked the
  remote side, with nothing draining stderr to relieve it. Both streams are
  now drained concurrently, matching how the pre-#81 transport handed
  `Stdout`/`Stderr` to `ssh.Session` as `io.Writer`s (drained by its own
  internal goroutines) rather than reading them out sequentially.
- The persistent REPL session (#81) also hung when redirected PowerShell
  output had no trailing newline (e.g. a CLIXML warning blob on stderr), so
  the bootstrap's end marker landed glued to that output on the same wire
  line. `readReplResponse` required an exact whole-line match and missed the
  marker, waiting forever on a session that never sends EOF (hanging the
  `identity-net`, `scheduling` and `storage` acceptance shards on later
  calls of already-used sessions). End markers are now recognised as a line
  suffix, keeping whatever precedes them verbatim as script output.
- The persistent session (#81) stalls on Windows PowerShell 5.1: the second
  or third stdin write of a reused `powershell.exe` session is accepted on
  the SSH channel but never reaches the child, which blocks in its stdin
  read forever with no EOF. Instrumented CI probes (remote transcript per
  REPL iteration, per-call byte deltas) localised the wedge to the 5.1
  console stdin stack under Win32-OpenSSH: identical framing under `pwsh`
  serves arbitrarily many sequential requests, and neither write pacing, an
  uncached stdin reader, nor the windows-2022 image changes the 5.1 outcome.
  The persistent session now runs under `pwsh.exe`; hosts without PowerShell
  7 transparently fall back to one `powershell.exe` process per call (the
  pre-#81 transport), which performs a single stdin write that always lands.

### Changed

- **Breaking:** the provider now connects to the target Windows host over
  **SSH** (its OpenSSH Server, invoking PowerShell) instead of WinRM. The
  `internal/winclient.Client` transport was rewritten on top of
  `golang.org/x/crypto/ssh`; the `RunPowerShell`/`RunPowerShellWithInput`
  API, the `-EncodedCommand`/stdin bootstrap, and every resource/data source
  on top of it are unchanged. The provider `port` attribute now defaults to
  `22`, and the `use_https` and `auth_type` provider attributes are removed.
  `masterzen/winrm` and its transitive NTLM/Kerberos dependencies were dropped
  from `go.mod`. The `testacc-windows` CI workflow now provisions the OpenSSH
  Server Windows capability on the runner instead of enabling WinRM.

### Added

- New resource `windows_directory`, which manages the presence, NTFS attributes
  (`hidden` / `readonly` / `system`) and absence of a directory on the target
  host. Content of the directory is never managed here: only the directory
  entry itself. Unlike `windows_file`, creating a `windows_directory` that
  already exists on the host is not an error, since a directory is naturally
  a shareable container; only a path that resolves to an existing file is
  rejected. Deleting a non-empty directory fails explicitly unless
  `recursive_delete = true`, so files not managed by Terraform are never
  silently discarded. Missing parent directories are created on demand unless
  `create_parent_directories = false`, in which case a missing parent is a
  typed, explicit error rather than a raw PowerShell exception. Pair it with
  `windows_file_acl`, which already accepts a directory target, for ownership
  and ACL management.

- New resource `windows_file_acl`, which manages the NTFS security descriptor of
  an existing file or directory: owner, DACL and inheritance protection. It
  never creates nor deletes the target, so it composes with `windows_file`,
  which preserves the security descriptor on every content update. Audit
  entries (SACL) are out of scope, and permissions are never applied
  recursively.

  `mode = "authoritative"` (the default) makes the explicit DACL exactly the
  declared `access_rule` blocks: an entry added out of band shows up as drift
  and is removed on the next apply. `mode = "additive"` enforces only the
  declared entries and leaves the rest of the DACL untouched and undiffed,
  which is what you want on a path whose permissions are partly owned by an
  installer. `Destroy` restores inheritance and strips the managed entries; it
  never deletes the secured file or directory.

  Identities are accepted as a SID, a qualified name or a bare local name, and
  are resolved on the target and **compared by SID**: renaming an account or
  qualifying it differently does not produce a spurious diff, and an orphaned
  SID left by a deleted account stays readable. Rights are compared on the
  effective access mask rather than on the `FileSystemRights` keywords, since
  the composite values overlap (`Modify` includes `Read`), and the comparison
  ignores the `Synchronize` bit, which Windows applies inconsistently: the same
  declared right lands as `0x20089` on a file but `0x120089` on a directory
  depending on which API wrote the entry.

  Observed data is exposed separately from the declarative blocks, as the
  computed `sddl` string and the `effective_access_rules` list (which includes
  inherited entries). No computed attribute lives inside an `access_rule`
  block, because Terraform cannot correlate the elements of a repeated block
  that carries computed values. `Read` reconciles rather than overwrites: a
  declared rule that matches the host is left exactly as it was written, so
  `Modify` is not rewritten into a keyword decomposition and a bare account
  name is not replaced by its qualified form.

  Two guard rails refuse a configuration that would lock an operator out: an
  `authoritative` resource with no `access_rule`, and
  `inheritance_enabled = false` with no allow entry, which would leave an empty
  effective DACL denying access to everyone including the owner.
  `preserve_inherited_on_protect` is honoured in `additive` mode but ignored
  (with a warning) in `authoritative` mode: Windows converts inherited entries
  into explicit ones only when the descriptor is committed, so the apply that
  creates those copies cannot reconcile them and no plan would ever be empty.

  Changing `owner` requires `SeTakeOwnershipPrivilege` and
  `SeRestorePrivilege`; leaving the attribute unset leaves ownership untouched
  and undiffed. The desired descriptor is streamed to the host as JSON on
  stdin, so no path, identity or right is ever interpolated into script text,
  and errors are classified from .NET exception types and Win32 codes read from
  `HResult` rather than from message text, which keeps the mapping working on a
  non-English host.

- New resource `windows_file`, which manages a single file on the target host:
  content, encoding and file attributes. Content can come from `content`
  (inline text), `content_base64` (binary), `source` (a file on the machine
  running Terraform) or `source_url` (HTTP/HTTPS), and secrets can be passed
  through the write-only `content_wo` / `content_base64_wo` attributes, which
  never reach the state or the plan and are rewritten when `content_wo_version`
  is bumped. Parent directories are created on demand, `overwrite = false`
  refuses to clobber a pre-existing file, and `attributes` enforces the
  `hidden` / `readonly` / `archive` / `system` / `temporary` flags.

  File bytes never travel in the PowerShell script: they are streamed as
  base64 on stdin and read back with `[Console]::In.ReadToEnd()`, which keeps
  quoting off megabyte payloads, avoids the fourfold blow-up of the UTF-16LE
  script encoding, and keeps content out of `-EncodedCommand`. Writes are
  atomic through a temporary file in the destination directory, so an
  interrupted apply or a full disk never leaves a truncated file. When the
  target already exists the swap uses `File.Replace`, which **preserves the
  existing security descriptor** — updating a file's content does not disturb
  an ACL managed elsewhere. Sharing violations, by far the most common failure
  mode on Windows, are retried with backoff before surfacing as `file_locked`.

  Drift detection compares SHA-256 digests rather than transferring content:
  `Read` only returns metadata, so `terraform plan` stays O(1) in bandwidth
  over any number of files and a file holding a secret is not pulled back on
  every refresh. The desired digest is computed at plan time, which is what
  makes a locally edited `source` file, or an out-of-band edit on the host,
  show up as a diff. A pinned `source_url_sha256` keeps the plan entirely
  local; without it the provider must fetch the URL on every plan and says so
  with a warning. `download_on = "target"` lets the Windows host download a
  large artifact itself and then requires the pinned digest, since the provider
  never sees those bytes.

  Importing uses the absolute path. Below 1 MiB the real content is read back
  during the import, so the first plan afterwards is clean instead of showing a
  phantom `"" -> "<content>"` diff against a file that already matches; above
  that ceiling the content is left empty and a warning explains that the first
  apply will rewrite the file.

  Ownership and ACLs are deliberately out of scope and will land as a separate
  `windows_file_acl` resource.

- Public-key and ssh-agent authentication. The provider gained
  `private_key` (PEM inline, sensitive), `private_key_path` (with `~`
  expansion), `private_key_passphrase` (sensitive) and `use_agent`, each with a
  `WINDOWS_*` environment fallback. Configured credentials are offered in the
  conventional OpenSSH order — explicit key, then ssh-agent, then password — so
  a host that refuses one method can still accept another. `password` is no
  longer required; any single method suffices.

### Security

- **Breaking:** the provider now **verifies the SSH host key** instead of
  accepting whatever the server presents. `ssh.InsecureIgnoreHostKey()` is gone
  from the default path. Verification uses either `known_hosts_path` (an
  OpenSSH `known_hosts` file, defaulting to `~/.ssh/known_hosts`) or the new
  `host_key` attribute, which pins the expected public key inline in
  `authorized_keys` form for CI and Terraform Cloud, where no `known_hosts`
  file exists. When neither is usable the provider **fails closed** rather than
  connecting unverified. A key that changes under an already-known host is
  reported as a possible man-in-the-middle, distinctly from a
  host-not-yet-known error.

  Without this check, authentication proved the client's identity to the server
  but nothing about who answered, so any host able to intercept the connection
  could have harvested credentials and the PowerShell payloads the provider
  sends — including secrets passed on stdin.

  **Upgrading:** add `host_key` (from `ssh-keyscan <host>`, fingerprint verified
  out of band) or point `known_hosts_path` at a populated file. Existing
  configurations will fail to connect until one of these is set. The escape
  hatch is `insecure_ignore_host_key = true`, which restores the previous
  behaviour, cannot be combined with `host_key` or `known_hosts_path`, and emits
  a warning on every plan and apply.

- The provider `port` attribute gained a `WINDOWS_PORT` environment fallback,
  so every connection attribute now has one — which is what the documentation
  already claimed. A value that is not a usable TCP port is ignored rather than
  dialed, leaving `New` to default to `22`.

### Fixed

- `windows_local_user`: `password_never_expires` always read back as `false`,
  producing `Provider produced inconsistent result after apply` for any account
  configured with `password_never_expires = true`. The read path took the value
  from `$User.PasswordNeverExpires`, but the `LocalUser` object returned by
  `Get-LocalUser` has no such member — it is a `New-LocalUser`/`Set-LocalUser`
  parameter only — so the expression always evaluated to `$null` and serialised
  as `false`, whatever had been written. The flag is now derived from the
  `ADS_UF_DONT_EXPIRE_PASSWD` (`0x10000`) bit of the account's ADSI `UserFlags`,
  which is exactly the bit the cmdlet parameter toggles, with a fallback to the
  `PasswordExpires`-is-null check. Because this was a read-side defect, the
  write-side workarounds it had accumulated (splitting the flags across separate
  `Set-LocalUser` calls, a follow-up `Disable-LocalUser`, a verify-and-retry
  loop, and an extra SSH round-trip to re-read state after Create/Update) are
  all removed: `Create` issues one `New-LocalUser`, `Update` one
  `Set-LocalUser`. This unblocks `TestAccWindowsLocalUser_DisabledAndFlags`.
- `windows_local_group_member` (data source): looking a member up by name failed
  with `member "<name>" not found in group "<group>"` even when the membership
  existed. `Get-LocalGroupMember` reports member names in the machine/domain
  qualified form (`MACHINE\user`), but the data source's Read matched them
  against the bare requested name with `strings.EqualFold`, which never matched.
  A new `memberNameMatches` helper now compares the bare account component (the
  part after the last `\`) with an exact-match fast path, so a bare `user`
  lookup resolves a qualified `MACHINE\user` result. The same helper is applied
  to the resource's `ImportState` name-based lookup for consistency. This
  unblocks `TestAccWindowsLocalGroupMemberDataSource_Basic`. (#73)
- `windows_scheduled_task`: trigger datetime boundaries (`start_boundary`,
  `end_boundary`) could come back from `Get-ScheduledTask` with a `+00:00`
  offset (e.g. `2026-01-01T08:00:00+00:00`) while the plan held the canonical
  `Z` form, causing Terraform to reject the apply with `Provider produced
  inconsistent result after apply` even though both denote the same instant. The
  `winclient` layer now canonicalizes every datetime it maps into state
  (`start_boundary`, `end_boundary`, and the read-only `last_run_time` /
  `next_run_time`) to UTC RFC3339 `Z` via a new `normalizeDT` helper in
  `stPayloadToState`, mirroring the PowerShell `Format-DT` behaviour. (#72)
- `windows_scheduled_task`: on a trigger type where an interval is not
  applicable (e.g. `weeks_interval` on a `Daily` trigger, `days_interval` on a
  `Weekly` trigger), the Computed attribute could stay `unknown` after apply,
  causing Terraform to reject the result with `Provider returned invalid result
  object after apply`. On a create the prior model *is* the plan, where an unset
  `Optional+Computed` interval is `unknown`; `buildTriggerObject` copied that
  `unknown` when Windows reported the interval as `0`. It now only preserves a
  prior interval value when it is *known* and otherwise resolves to `null`.
  Applies symmetrically to `days_interval` and `weeks_interval`. (#70)
- `TestAccWindowsLocalGroupMemberDataSource_Basic` hardcoded a lookup of the
  built-in `Administrator` account in the `Administrators` group. That account
  is disabled/renamed on GitHub-hosted `windows-latest` runners, so the data
  source read failed with `member "Administrator" not found in group
  "Administrators"`. The test now provisions its own throwaway group, user, and
  membership via the sibling resources and looks the pair up through the data
  source (mirroring the `windows_local_user` data-source fixtures), keeping it
  host-agnostic. Test-only fix. (#63)
- `windows_local_user` acceptance fixtures embedded the account name in the
  password literal (`"P@ssw0rd-Acc-" + name + "!"`). Windows password-complexity
  policy rejects any password containing the user's samAccountName, so create
  failed with `InvalidPasswordException` before the resource/data source was
  ever read (seen on `TestAccWindowsLocalUserDataSource_ByName` and `_BySID`).
  The data-source fixture and the two resource fixtures that still interpolated
  `name` now use fixed complexity-satisfying literals; the password is never
  asserted (ADR-LU-3). Test-only fix. (#62)
- `windows_scheduled_task`: creating a task in a non-root folder whose `path`
  carried a trailing backslash (e.g. `"\\TF\\"`) failed with `The filename,
  directory name, or volume label syntax is incorrect. (Exception from HRESULT:
  0x8007007B)` — `ITaskFolder::CreateFolder` rejects a folder name ending in a
  backslash. `Ensure-TaskFolder` now normalises the path with `TrimEnd('\')`
  before the `GetFolder`/`CreateFolder` calls (matching `Remove-EmptyFolder`),
  keeping the root path a no-op. Regressed after #54. This also unblocks
  `TestAccWindowsScheduledTaskDataSource_Basic`, which uses a trailing-backslash
  fixture path. (#61)
- Data-source `_NotFound` acceptance tests for `windows_registry_value`,
  `windows_service`, and `windows_scheduled_task` left `ExpectError: nil`
  while deliberately exercising a *not found* case. The provider returned the
  expected error, but with no error `regexp` the step treated it as a failure.
  Each test now sets an `ExpectError` regex targeting that data source's
  not-found diagnostic (e.g. `No Windows service named .* was found`), so the
  tests pass in `testacc-windows`. Test-only fix. (#56)
- `windows_local_user` data-source acceptance tests: the `_ByName` and
  `_BySID` fixtures built names as `"tf-acc-ds-name-"`/`"tf-acc-ds-sid-"`
  plus the default `tf-test` suffix, yielding 22- and 21-character names
  that exceeded the schema's `LengthBetween(1, 20)` on `name`, so the plan
  failed before reaching WinRM (`Invalid Attribute Value Length`). The
  prefixes are now `"ds-name-"`/`"ds-sid-"` (15/14 chars resolved), keeping
  the names unique and within the limit. (#55)
- `windows_scheduled_task`: folder creation called a non-existent COM method
  `CreateSubFolder` on `ITaskFolder`, so creating any task in a non-root folder
  failed with `[System.__ComObject] does not contain a method named
  'CreateSubFolder'`. `Ensure-TaskFolder` now uses the correct
  `ITaskFolder::CreateFolder`, which builds the entire nested folder tree in a
  single call; the creation stays idempotent via a `GetFolder` guard. This also
  unblocks `TestAccWindowsScheduledTaskDataSource_Basic`/`_NotFound`, which share
  the folder fixture. Mock-based unit tests could not catch this COM-runtime
  bug; a script-level regression guard now pins the correct method. (#54)
- `windows_local_group_member`: fixed an unterminated PowerShell regex
  literal (`'^-+`) in the member-listing script. The missing closing
  quote swallowed the rest of the script, so every read failed with a
  `WinRM transport error` (`Unexpected token 'The' ...`). Any read of the
  resource or data source was inoperative on the host; unit tests (mocks)
  did not catch it. Now `'^-+'` is properly closed. (#53)
- `windows_feature` data-source acceptance test: `TestAccWindowsFeatureDataSource_NotFound`
  had `ExpectError: nil` while the data source deliberately raises a diagnostic
  for a missing feature, so the framework treated the expected error as a
  failure. The step now matches the provider's actual detail wording via
  `regexp.MustCompile("No Windows feature named .* was found")`, mirroring the
  not-found idiom used by the sibling `firewall_rule` / `environment_variable`
  data-source tests. (#43)
- `windows_local_user` acceptance tests: the data-source suites no longer
  assume the built-in `Administrator` account (name / well-known RID-500 SID),
  which is disabled/renamed on GitHub-hosted `windows-latest` runners. Both
  `TestAccWindowsLocalUserDataSource_ByName` and `_BySID` now provision their
  own throwaway local user via the sibling resource and look it up through the
  data source, referencing the fixture's attributes (including the SID
  Windows assigns) so the tests are host-agnostic. (#42)
- `windows_scheduled_task` acceptance tests: corrected stale HCL that used
  singular `action {}` / `trigger {}` blocks. `actions`, `triggers`, and
  `principal` are nested attributes in the current schema and must use
  assignment syntax (`actions = [{ ... }]`, `principal = { ... }`), not block
  syntax — the block form fails config validation with `Blocks of type ... are
  not expected here` / `argument ... is required`. Updated the affected
  `TestCheckResourceAttr` state paths accordingly (e.g. `principal.user_id`,
  `actions.0.execute`). (#41)
- `windows_firewall_rule`: Create/Update no longer fail with
  `Cannot convert value "True" to type ...NetSecurity.Enabled`. The `-Enabled`
  parameter is an enum, not a `[bool]`, so the generated PowerShell now emits
  the `'True'`/`'False'` string tokens instead of `$true`/`$false`. (#40)
- winclient transport: PowerShell scripts are no longer inlined on the command
  line via `-EncodedCommand`. Only a fixed bootstrap is passed on the command
  line; the real script (UTF-16LE base64) is streamed on stdin, keeping the
  command line at a constant ~600 chars. This resolves `The command line is too
  long.` failures on larger scripts — notably the `windows_service`,
  `windows_firewall_rule`, `windows_local_group_member` and
  `windows_registry_value` data-source reads — while preserving UTF-16LE
  fidelity for non-ASCII values. (#39)
- The provider `timeout` attribute was documented as an "operation timeout",
  but it only ever bounded connection establishment (`net.Dialer.Timeout` and
  `ssh.ClientConfig.Timeout`). Command duration is bounded by the request
  context, i.e. the per-resource `timeouts {}` block. Behaviour is unchanged;
  the description now says what the attribute does, so raising it to
  accommodate a slow install is no longer mistaken for a fix.
- `Configure` rejected an unknown value for the string credentials but silently
  accepted one for `port`, `timeout`, `use_agent` and `insecure_ignore_host_key`,
  where it would collapse to the zero value — dialing port 22, or flipping host
  key verification — instead of failing. All connection attributes are now
  checked.
- Transport failures were reported with four different wordings across the
  resources (`powershell transport error`, `PowerShell transport error`,
  `transport error`, `SSH transport error`). They all say `SSH transport error`
  now, which is also what the transport actually is.

### Fixed (acceptance suite)

- `windows_scheduled_task` updates failed with "A parameter cannot be found
  that matches parameter name 'Description'". `Set-ScheduledTask` has no
  `-Description` parameter, unlike `Register-ScheduledTask` used on create. The
  description is now set on the task object and written back, and it is applied
  unconditionally so clearing it in the configuration clears it on the host.
  (#82)
- `windows_scheduled_task` import failed with a framework Value Conversion Error
  on `timeouts`. With no prior state to copy from, the attribute kept its Go
  zero value, whose object carries no attribute types, so the framework saw
  `tftypes.Object[]` where the schema declares
  `Object["create","delete","update"]`. Import now writes a null value carrying
  the schema's types, and both halves derive from one `timeouts.Opts` so they
  cannot disagree. (#83)


- `TestAccWindowsServiceDataSource_Basic` looked up a service named `SSH`,
  which does not exist: the SCM name for OpenSSH Server is `sshd` (`OpenSSH SSH
  Server` is only its display name). A leftover of the WinRM -> SSH rename,
  which also left the data block labelled `winrm`.
- `TestAccWindowsLocalGroupMemberDataSource_Basic` still failed after #73. The
  qualified-name lookup worked, but the data source then wrote the
  host-qualified name Windows returns (`HOST\\alice`) back into `member_name`,
  which is a **Required** argument, so it no longer matched the configuration.
  It now echoes the value as written; `member_sid` remains the resolved
  identity, and the resource's `member_name` is Computed and still holds the
  canonical form.

### Changed (CI)

- Acceptance pre-checks required `WINDOWS_PASSWORD` specifically, in 21
  duplicated copies. The public-key leg of the matrix clears that variable on
  purpose -- to prove the key alone authenticates -- so 69 of the 85 tests in the
  `rest` shard skipped there, and the failures among them were invisible. The
  suite now requires a host, a username and **at least one** credential, in a
  single shared `testAccRequireEnv` mirroring `winclient.buildAuthMethods`. The
  auth method the provider recommends is no longer the one it does not test.

- The acceptance suite is now sharded across runners (`feature`, `feature-ds`,
  `rest`), cutting wall clock from ~12min to ~6min. Two thirds of the runtime is
  `windows_feature`: `Get-WindowsFeature` imports the ServerManager module on
  every call (~18s) and each call gets a fresh SSH connection and
  `powershell.exe`, so Terraform's 5-6 reads per test pay it 5-6 times.
  Sharding rather than `t.Parallel()` because DISM and `Install-WindowsFeature`
  are machine-global and serialised by Windows; separate runners are separate
  machines. The floor is the slowest single test, so going further needs a
  persistent PowerShell session in `winclient`.
- Shard filters are anchored on `^TestAcc`, which also stops the acceptance job
  re-running the ~200 unit tests that `test.yml` already covers on ubuntu.
- Fixed the `publickey` leg, which never authenticated: `ssh-keygen -N '""'` is
  a PowerShell 5.1 workaround and under `pwsh` 7 passes two literal quotes as
  the passphrase, leaving the key encrypted and unusable under `BatchMode`.

### Documentation

- `README.md` still described the provider as WinRM-based, and its example
  configuration set the removed `auth_type` attribute — a copy-paste that no
  longer plans. It now covers the SSH transport, how to enable OpenSSH Server on
  the target, the three authentication methods, host key verification and the
  full set of `WINDOWS_*` variables.
- Added **ADR-0010** (SSH as the transport) and **ADR-0011** (verify host keys by
  default, and fail closed), recording the two decisions behind #78 and #79 —
  including the invariants `auth.go` must preserve and the known ssh-agent
  limitation on Windows.
- The KDust pipeline prompts (`.claude/agents/`, `.kdust/prompts/v2/`) still
  instructed agents to target "PowerShell Remoting (WinRM)" and to mock WinRM,
  so the next generated resource would have been specified against the old
  transport. They now describe the SSH client and its `RunPowerShell` surface.
- `CLAUDE.md` claimed CI fails on `docs/` drift; the `docs` workflow is
  deliberately a schema-validation gate with a non-blocking drift step. The note
  now matches the workflow, and `make test`'s documented timeout matches the
  `GNUmakefile`.
- Documented that ssh-agent authentication is unavailable when Terraform itself
  runs on Windows, since the agent is exposed as a named pipe rather than a Unix
  socket.

### Internal

#### Changed

- Data sources normalization: aligned acceptance test naming to `TestAccWindows<R>DataSource_<Case>`,
  removed the unused `client *winclient.Client` field from data sources that only need their typed sub-client,
  unified the `schema` import alias in `datasource_windows_environment_variable.go`,
  moved `windowsScheduledTaskDSModel` and friends from `resource_windows_scheduled_task.go` to
  `datasource_windows_scheduled_task.go`, and sorted `provider.DataSources()` alphabetically.
- Resources normalization: renamed hostname test files to match the project convention
  (`*_test.go` for unit, `*_acc_test.go` for acceptance), removed the unused `client *winclient.Client`
  field from 9 resources whose Configure stored it without ever reading it back, aligned
  `windows_local_group_member` acceptance test names to `TestAccWindows<R>_<PascalCase>`,
  and sorted `provider.Resources()` alphabetically.

### Data Sources

#### Added

- `windows_winget_package` data source: read-only lookup of a single
  winget-managed package on a remote Windows host via WinRM and the
  `Microsoft.WinGet.Client` PowerShell module. Reuses the twin resource's
  `winclient.WingetPackageClient.Read` pipeline (Equals(Id) filter,
  ARP-only detection, single retry on `source_unreachable`) and surfaces
  an explicit `not_found` Terraform error when the package is absent
  from both the catalog and ARP — data sources never silently
  produce empty state.

### Added

- **WriteOnly credential attributes (Tier 3, TPF v1.14.1)** on every
  resource that previously persisted plaintext passwords in
  `terraform.tfstate`:
  - `windows_local_user.password_wo` (paired with the existing
    `password_wo_version` rotation counter).
  - `windows_service.service_password_wo` (paired with the legacy
    `service_password`; no version counter is needed because the
    WriteOnly value is re-read from configuration on every plan and
    forwarded to `Set-Service` unconditionally — re-supplying the same
    value is naturally idempotent).
  - `windows_scheduled_task.principal.password_wo` (re-uses the
    existing `principal.password_wo_version` counter as the rotation
    trigger; the Update path was already version-gated so no
    server-side change was needed).

  All three new attributes are declared with `WriteOnly: true,
  Sensitive: true` and are **never written to `terraform.tfstate`** —
  the framework strips the value from state automatically after each
  CRUD response. They are mutually exclusive with their legacy
  state-persisted counterpart (`resourcevalidator.Conflicting` at the
  resource level for `local_user` / `service`, inline check inside
  `scheduledTaskPrincipalCrossFieldValidator` for `scheduled_task`
  because the attributes live inside a nested block).

  The legacy `password` / `service_password` / `principal.password`
  attributes are now flagged with a `DeprecationMessage` pointing at
  the WriteOnly replacement; `terraform plan` will surface the
  deprecation warning on every run until the operator migrates. The
  attributes themselves remain functional — removal is scheduled for
  v2.x.

  Migration is one-line per credential and does not require a state
  rewrite:

  ```hcl
  # Before (legacy, persisted in state)
  resource "windows_local_user" "svc" {
    name     = "svc-app"
    password = var.svc_password   # <- persisted
  }

  # After (Tier 3, never persisted)
  resource "windows_local_user" "svc" {
    name                = "svc-app"
    password_wo         = var.svc_password   # <- WriteOnly
    password_wo_version = 1                  # increment to rotate
  }
  ```

- **Structured `tflog.Debug` instrumentation on every CRUD hot path**
  for the eight resources that previously had zero `tflog` coverage
  (`windows_service`, `windows_scheduled_task`, `windows_registry_value`,
  `windows_local_user`, `windows_local_group`, `windows_feature`,
  `windows_legacy_package`, `windows_winget_package`). Payloads always
  include the natural identifier (name, id, sid, hive+path+name, or
  package_id+source) and never include sensitive values — passwords
  are represented exclusively by their `password_wo_version` counter.
  Notable: `windows_scheduled_task` Update logs a computed
  `password_rotated` boolean so operators can audit credential
  rotations from the log stream alone (no provider-level trace
  required).

- GitHub Actions CI pipeline (`.github/workflows/`):
  - `test.yml`: build + `go vet` matrix on Go 1.22 / 1.23, unit tests
    with race detector and coverage upload, and `golangci-lint v1.61`
    using the existing `.golangci.yml` ruleset. Triggered on every push
    to `main` and on pull requests.
  - `docs.yml`: regenerates `docs/` via `go generate ./...`
    (tfplugindocs) and fails the run if the worktree drifts. Acts as a
    hard gate against schema changes that forget to refresh the
    Markdown shipped to the Registry. Path-filtered to provider /
    examples / templates / tooling changes.
  - Acceptance tests (`TF_ACC=1`) are deliberately not run in CI — they
    require a live Windows host over WinRM and belong in a separate
    self-hosted runner / lab pipeline.
- `.github/dependabot.yml`: weekly grouped Go-module and
  GitHub-Actions updates. Major bumps on `terraform-plugin-framework`
  and `terraform-plugin-go` are explicitly ignored (manual review
  required because of breaking-change cadence).
- `.github/pull_request_template.md`: enforces a contributor checklist
  covering unit tests, linting, doc regeneration, CHANGELOG entry, and
  TF_ACC validation when applicable.

### Fixed

- **`windows_registry_value.hive`: invalid schema declared both
  `Required: true` and `Computed: true`.** Terraform itself rejected the
  combination at schema validation time
  (`cannot set both Computed and Required`), but the bug had remained
  hidden until tfplugindocs was wired into CI as part of Tier 2/4 — no
  step in the previous workflow ever ran
  `terraform providers schema -json` on the live provider. Fixed by
  removing the spurious `Computed: true`; the `hiveNormalizePlanModifier`
  contract (uppercase normalisation) is preserved unchanged because plan
  modifiers operate on the planned value regardless of `Computed`.

### Changed

- `go.sum` populated for the modules introduced in Tier 2
  (`terraform-plugin-framework-timeouts`, `terraform-plugin-docs`) and
  for `terraform-plugin-testing` (pinned to **v1.10.0** — the last
  release that targets Go 1.21+/1.22 without bumping the project
  toolchain to Go 1.25). The latter was already imported by three
  acceptance-test skeleton files under the `acceptance` build tag but
  had never been reflected in `go.mod`. Without this pin
  `go mod tidy` would resolve to the latest 1.16.x line which requires
  Go 1.25.8 and breaks the entire module graph for current consumers.
- `.github/workflows/docs.yml`: drift detection step is now
  `continue-on-error: true` while the per-resource templates under
  `templates/` are stubs. The schema-validation half of the workflow
  remains hard-blocking — it is what surfaced the
  `windows_registry_value.hive` bug above. See the inline header in
  the workflow for the migration plan.
- `.github/workflows/docs.yml`: pre-installs Terraform 1.9.8 via
  `hashicorp/setup-terraform@v3` so tfplugindocs picks up the binary
  from `PATH` instead of triggering its bundled `hc-install` download
  path, which fails on `terraform-plugin-docs <=v0.20.1` because of an
  expired GPG signing key.

### Security

- **`windows_service` and `windows_scheduled_task`: stop embedding plaintext
  passwords in PowerShell `-EncodedCommand` payloads.** Both resources used to
  render `service_password` / `principal.password` into the script body via
  `psQuote`, which meant the cleartext was visible to anyone with access to
  WinRM trace logs, IIS WMSvc traces, or any host-side `Set-PSDebug` /
  `Start-Transcript` output on the target. The script body is now scrubbed of
  password values: the plaintext is piped over stdin and read by the script
  through `[Console]::In.ReadLine()` (mirrors the existing `ADR-LU-3` pattern
  used by `windows_local_user`). Regression-guard unit tests assert the
  password is absent from the rendered script and present on stdin
  (`TestCreate_PasswordInjectedViaStdin_NotInScriptBody` and the equivalent
  Update / scheduled-task variants). No state-format or schema change; no
  user action required.

### Added

- Per-operation `timeouts {}` block on the four long-running resources —
  `windows_winget_package`, `windows_legacy_package`, `windows_feature` and
  `windows_scheduled_task` — backed by
  `terraform-plugin-framework-timeouts`. Users can now bound the wall-clock
  duration of `Create`, `Update` and `Delete` independently of the
  provider-level WinRM transport timeout. Defaults: 30 minutes for the three
  package/feature resources (large downloads, MSI/MSIX execution,
  AD-Domain-Services with sub-features), 5 minutes for scheduled tasks
  (CRUD via the `ScheduledTasks` PowerShell module is fast). The block is
  Optional+Computed; absent configuration keeps the default. Note: on
  `windows_legacy_package` the new wall-clock budget is layered on top of
  the existing installer-process `timeout_seconds` attribute; both are
  preserved (different scopes, not redundant).

- `tools/tools.go` and `generate.go` to pin and invoke
  `terraform-plugin-docs` (`tfplugindocs`). `make docs` (alias for
  `go generate ./...`) regenerates the registry-rendered documentation
  under `docs/` directly from the live provider schema, including the new
  `timeouts {}` blocks. The `tools` build tag keeps the generator out of
  the production binary.

- `windows_legacy_package` resource: manages the full lifecycle (install /
  update / uninstall) of Windows software distributed as legacy installers —
  Windows Installer `.msi` packages (via `msiexec.exe`) and `.exe` wrappers
  (InstallShield, NSIS, Inno Setup) via `Start-Process` — over WinRM.
  Complements `windows_winget_package` for software not available via winget
  or shipped as a local/internal binary. Source resolution from local
  `source_path` or fetched `source_url` (mutually exclusive, schema-enforced),
  with mandatory checksum verification (`sha256` / `sha1` / `md5`) before
  exec. MSI ProductCode is auto-extracted at Create when `product_id` is
  omitted. Detection reads both 64-bit and `Wow6432Node` Uninstall registry
  hives; EXE installs are located by `display_name_pattern` (wildcard /
  regex against `DisplayName`) or via an explicit `uninstall_command`. Default
  `valid_exit_codes = [0, 3010]` (3010 = soft reboot). In-place updates for
  `valid_exit_codes`, `timeout_seconds`, `log_path`, `environment` (marked
  sensitive — may carry license keys / proxy creds); all other attributes are
  ForceNew. Import supported by ProductCode GUID (MSI) or exact DisplayName
  (EXE). Drift on manual uninstall removes the resource from state and
  triggers re-create on next apply.

- `windows_winget_package` resource: manages the full lifecycle (install /
  update / uninstall) of a Windows software package via the Microsoft Windows
  Package Manager (`winget`) using the `Microsoft.WinGet.Client` PowerShell
  module over WinRM. Supports create, in-place version update, drift detection,
  deletion, and import. Package scope is always `SystemOrUnknown` (machine-level)
  with silent mode enforced and agreements auto-accepted. Covers 7 attributes:
  `package_id` (ForceNew), `source` (default `winget`; ForceNew), `version`
  (optional pinned version; in-place update), `override` (ForceNew; no control
  chars), `id` (composite `<source>:<package_id>`), `installed_version`
  (observed), and `name` (observed). Handles 9 error kinds with typed
  diagnostics: `module_missing`, `already_installed`, `version_not_available`,
  `blocked_by_policy`, `permission_denied`, `source_unreachable` (1 retry),
  `catalog_error`, `resource_in_use` (3× back-off retry), and `unknown`.
  Import format: `<source>:<package_id>` (first-colon split).

- `windows_firewall_rule` data source: reads the observed state of a Windows
  Defender Firewall rule by its stable technical `name` (InstanceID). Mirrors
  the resource schema in read-only form (no plan modifiers, no defaults beyond
  an implicit `policy_store = "PersistentStore"` applied at Read time). Returns
  an explicit error diagnostic when the rule is not found in the target policy
  store. Reuses the resource's `listFromStrings` helper and the
  `*winclient.FirewallRuleError` enrichment path for typed diagnostics.

- `windows_firewall_rule` resource: manages the full lifecycle of a Windows
  Defender Firewall with Advanced Security rule on a remote host via WinRM +
  PowerShell (`NetSecurity` module). Supports create, in-place update, drift
  detection, deletion, and import. Covers all 19 rule attributes including root
  properties (`direction`, `action`, `profile`, `edge_traversal_policy`,
  `group`, `policy_store`) and filter sub-objects (`protocol`, `local_port`,
  `remote_port`, `local_address`, `remote_address`, `program`, `service`,
  `interface_type`) retrieved via the `Get-NetFirewall*Filter` pipeline.
  Enum fields are normalised to canonical English values regardless of host
  locale (InvariantCulture pinning, ADR-FR-5). Empty filter lists are
  normalised to `["Any"]` to prevent permadiff (ADR-FR-6). Cross-field
  validators enforce profile exclusivity (CV-1) and port/protocol compatibility
  (CV-2). `name`, `group`, and `policy_store` are ForceNew. `GroupPolicy` and
  `RSOP` stores are read-only and return an explicit diagnostic. Import ID
  format: `<name>` (PersistentStore assumed) or `<policy_store>/<name>`.
  Requires Local Administrator on the target host.

- `windows_scheduled_task` resource and data source: manages the full lifecycle
  of a Windows Scheduled Task on a remote host via WinRM + PowerShell
  (ScheduledTasks module, Windows Server 2012+ / Windows 8+). Supports create,
  in-place update, drift detection, deletion, and import. Features include:
  recursive task-folder creation and pruning; configurable principal (including
  domain accounts with semantic write-only password and `password_wo_version`
  rotation counter, ADR-ST-3); up to 32 sequential executable actions; up to 48
  triggers of types `Once`, `Daily`, `Weekly`, `AtLogon`, `AtStartup`, and
  `OnEvent` (XML-injection route for OnEvent, ADR-ST-5); full task settings
  block (`New-ScheduledTaskSettingsSet`). Cross-field validators enforce
  password/logon-type mutual exclusion (EC-4/EC-5) and trigger type–field
  compatibility (EC-7). Import ID format: `<TaskPath><TaskName>` (e.g.
  `\MyFolder\MyTask`). Requires Local Administrator on the target host.



- `windows_environment_variable` resource and data source: manages (or reads)
  a single Windows environment variable (`machine` or `user` scope) on a remote
  host via WinRM + PowerShell. Uses the `.NET Microsoft.Win32.Registry` API for
  type-safe `REG_SZ` / `REG_EXPAND_SZ` storage (ADR-EV-1). Broadcasts
  `WM_SETTINGCHANGE` after every mutation so newly started processes inherit the
  change without a reboot; broadcast failure is non-fatal (ADR-EV-2). Reads
  always use `DoNotExpandEnvironmentNames` for stable drift detection with raw
  `%VAR%` tokens (ADR-EV-5). Import ID format: `<scope>:<name>` (e.g.
  `machine:JAVA_HOME`). Scope `machine` requires Local Administrator; `user`
  requires no elevation. The data source returns a Terraform error for
  non-existent variables (no silent empty state).

- Add 7 data sources mirroring resources: `windows_feature`, `windows_hostname`,
  `windows_local_group`, `windows_local_group_member`, `windows_local_user`,
  `windows_registry_value`, and `windows_service`. Each data source is read-only
  (no Create/Update/Delete/ImportState), uses Required or Optional+ExactlyOneOf
  lookup keys, returns all other attributes as Computed, and raises an explicit
  `AddError` diagnostic when the target object is not found (no silent empty
  state). Write-only or input-only attributes (`password`, `service_password`,
  `status`, `restart`, `source`) are intentionally absent. Full schema
  documentation generated in `docs/data-sources/`.

- `windows_registry_value` resource: manages a single named value (or the
  unnamed **Default** value) inside a Windows registry key on a remote host via
  WinRM + PowerShell, using the `.NET Microsoft.Win32.Registry` API directly
  for type-safe, robust access across all seven Windows registry value kinds
  (`REG_SZ`, `REG_EXPAND_SZ`, `REG_MULTI_SZ`, `REG_DWORD`, `REG_QWORD`,
  `REG_BINARY`, `REG_NONE`). Missing parent keys are created automatically and
  recursively at Create time; only the targeted value is removed at Delete time.
  `REG_DWORD` and `REG_QWORD` are expressed as decimal strings to avoid uint32
  overflow and `float64` precision loss (ADR-RV-3). `REG_BINARY` and `REG_NONE`
  use lowercase hex without separators (ADR-RV-4). `REG_EXPAND_SZ` reads raw
  `%VAR%` tokens by default (`expand_environment_variables = false`) for stable
  drift detection (ADR-RV-5). The resource ID is a composite
  `HIVE\PATH\NAME`; the Default value (`name = ""`) has a trailing-backslash
  ID. `hive` input is case-insensitive and normalised to uppercase (ADR-RV-6).
  Three-method client interface (`Set`/`Read`/`Delete`) with a type-conflict
  guard at both plan and runtime layers (ADR-RV-7, EC-3). All PowerShell
  parameters are psQuote-escaped; no user data is raw-concatenated into scripts.
  Structured error classification: `type_conflict`, `not_found`,
  `permission_denied`, `invalid_input`, `unknown`. Import supported via
  `terraform import windows_registry_value.<name> 'HIVE\PATH\NAME'`.

- `windows_local_user` resource: manages a Windows local user account (SAM
  database) on a remote host via WinRM and PowerShell
  (`Microsoft.PowerShell.LocalAccounts`, Windows Server 2016 / Windows 10+).
  The Terraform resource ID is the user **SID** (stable across renames);
  changing `name` issues `Rename-LocalUser -SID` in place — no resource
  replacement (ADR-LU-1). Supports `full_name`, `description` (48-char
  Windows limit, EC-8), `enabled`, `password_never_expires`,
  `user_may_not_change_password`, `account_never_expires`, and
  `account_expires` (RFC3339, future-only at Create, EC-13). Password is
  **Sensitive-only** in TPF 1.13.0 (write-only migration path documented for
  TPF ≥ 1.14.0); plaintext injected via stdin — never in
  `-EncodedCommand` payloads or WinRM trace logs (ADR-LU-3). Password
  rotation driven by `password_wo_version` counter (EC-6). Built-in accounts
  (RID 500/501/503/504) protected against deletion with a hard error
  (ADR-LU-2, EC-2). `password_last_set` is read-only and does not drive
  autonomous drift (ADR-LU-4). Import accepts SID (starts with `S-`) or SAM
  name; post-import `password` is null (EC-11). Structured error
  classification: `not_found`, `already_exists`, `builtin_account`,
  `rename_conflict`, `password_policy`, `permission_denied`, `invalid_name`,
  `unknown`. Adds `ResolveLocalUserSID` helper (symmetric to `ResolveGroup`
  in `local_group_helpers.go`) for resolving a SAM name or SID string to a
  canonical `*UserState` — available for future resources that need local
  user identity resolution without duplicating PowerShell logic.

- `windows_local_group_member` resource: non-authoritative single-membership
  management for Windows local groups (companion to `windows_local_group`).
  Each Terraform resource instance represents one `(group, member)` pair;
  out-of-band memberships are left undisturbed (EC-12). Composite resource ID
  is `"<group_sid>/<member_sid>"` — both SIDs are stable across renames.
  Supports all Windows identity formats for `member` (`DOMAIN\user`, UPN,
  local username, direct SID string). Implements three-tier orphaned-AD-SID
  fallback (`Get-LocalGroupMember` → `Win32_GroupUser` WMI → `net localgroup`)
  for groups containing stale AD SIDs (EC-6). BUILTIN groups (`Administrators`,
  `Remote Desktop Users`, etc.) are explicitly supported as primary targets
  (EC-9). Import accepts `"<group>/<member>"` with name or SID on either side.
  Structured error classification: `group_not_found`, `member_already_exists`,
  `member_unresolvable`, `member_not_found`, `permission_denied`, `unknown`.

- `windows_local_group` resource: manages a Windows local group (Local Users
  and Groups) on a remote host via WinRM and PowerShell
  (`Microsoft.PowerShell.LocalAccounts`, Windows Server 2016 / Windows 10+).
  The Terraform resource ID is the group **SID** (stable across renames);
  changing `name` issues `Rename-LocalGroup` in place — no resource
  replacement. Built-in groups (SID prefix `S-1-5-32-*`) are protected against
  deletion with a hard error. Membership management is out of scope (delegated
  to the future `windows_local_group_member` resource). Supports import by
  group name **or** SID (auto-detected by `S-` prefix). Structured error
  classification: `not_found`, `already_exists`, `builtin_group`,
  `permission_denied`, `name_conflict`, `invalid_name`, `unknown`.

- `windows_hostname` resource: manage the NetBIOS computer name of a remote
  Windows host over WinRM via `Rename-Computer`. Renames are asynchronous —
  the resource never reboots on its own and surfaces `current_name`,
  `pending_name` and `reboot_pending` to drive downstream reboot
  orchestration. The Terraform ID is anchored on `MachineGuid` so it
  survives renames and detects machine replacement out-of-band. Supports
  case-insensitive idempotency, NetBIOS validation (length, charset,
  leading/trailing hyphen, purely numeric), `force`, structured error
  classification (`invalid_name`, `permission_denied`, `domain_joined`,
  `unreachable`, `machine_mismatch`, `concurrent_modification`), and
  import by `MachineGuid`. Workgroup machines only in v1; domain-joined
  hosts are rejected. Destroy is a no-op (a Windows host cannot exist
  without a hostname).
- `windows_feature` resource: install/uninstall a Windows Server role or
  feature over WinRM via `Get-/Install-/Uninstall-WindowsFeature`
  (ServerManager). Supports `include_sub_features`,
  `include_management_tools`, offline `source` (SxS/WIM), `restart`,
  drift detection (`install_state`, `installed`), pending-reboot signalling
  (`restart_pending`), import by feature name, and structured error
  classification (not_found, source_missing, dependency_missing,
  unsupported_sku, permission_denied, timeout).
- `windows_service` resource: full lifecycle management of Windows services
  over WinRM (create, read, update, delete, import). Supports start type,
  runtime status control (Running/Stopped/Paused), custom service account
  with write-only password semantics, dependencies, and cross-field
  validation (EC-4, EC-11).
