# Pinned Ghidra functionality coverage

This ledger accounts for the pinned functionality and its current command/equivalence mapping.
The owner selected the complete catalog, with equivalent logical operations allowed.
`scripts/audit-coverage.mjs` checks that all 210 mappings resolve to the actual command tree and
that the eight bridge controls remain accounted for. This structural check is separate from
behavioral acceptance: exact-revision native/installed evidence is required before final delivery.
No generic raw-MCP passthrough satisfies this ledger.

See [native SDK → MCP → facade gaps](gaps_api_ghidra.md) for the per-operation native API mapping
and **G01–G07 P0/P1 closure**. The upstream `/find_dead_code` and `/detect_crypto_constants` stubs now
have bounded native facade replacements; nested placeholders fail. Audited memory/prototype input
variants and stronger semantic/result contracts are implemented. [Current closure evidence](verification/api-gaps.json)
identifies the newer implementation and affected native/installed regressions. The historical 210/8/215 count
does not imply complete SDK breadth or an exhaustive parameter matrix. The current 261-leaf tree
adds [selected native P2 workflows](verification/api-gaps-p2.json), including genuine VT/FID/BSim,
DB differences, byte/assembly/context editing, formats, GDT, namespaces, typed IR and live/trace
operations. Those extensions do not change the 210 pinned operation mappings or eight controls.

## Completed combined evidence

The [full acceptance report](verification/full-facade.json) binds 23 passing native groups,
installed CLI/IPC/crash verification and the tested artifact to implementation revision
`300884e3c9be0928a8e1659e088aa2144c2c70b4`.
[Machine-readable evidence joins](verification/coverage-evidence.json) map all 210 rows to their
actual command/equivalent, permission and verification group. This does not widen automatic merge
semantics or claim an exhaustive matrix of every input combination.

## Source baseline

- GhidraMCP source: `57e37a8bf388b1279cff46378f85be1554548f61`, version 7.0.0.
- [Endpoint catalog](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/tests/endpoints.json): 210 entries, 210 unique paths, SHA256 `ebdaa9195ec2ea55fb706107bba1ee3732abd2eda783ed67a6ccc7359fdc5c66`.
- Access metadata was checked against Java `McpTool` declarations and [manual descriptors](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/src/main/java/com/xebyte/core/ManualToolDescriptors.java): 103 READ_ONLY, 84 WRITE, 23 DESTRUCTIVE; no missing classification.
- Catalog runtime modes: 19 GUI-only, four headless-only, 187 available in both modes. Mode availability does not prove useful GUI behavior in headless mode.
- [Static bridge controls](https://github.com/bethington/ghidra-mcp/blob/57e37a8bf388b1279cff46378f85be1554548f61/python/bridge_mcp_ghidra/static_tools.py): eight separately accounted controls.

The 210 count is the pinned REST catalog, not a claim that every connected MCP installation has
the same tools. Static bridge import overlaps REST import; the bridge controls are not eight
additional independent program editing features. Runtime schema/binding checks must detect
incompatible installations rather than quietly accepting a different catalog.

## Scope and outcome classes

`C` means explicit session/target/tool context; `P` means selected profile and explicit
project/repository selectors as applicable; `X` means source and destination target selectors
for a cross-program operation; `U` is a stateless utility or command-discovery operation.
Administration is a separate functional surface and does not infer an EXE from global backend
state. Research calls always retain explicit session/target scope.

Access labels below are upstream annotations, not the final Factory permission map or evidence
of semantic merge safety. Factory gates and handler effects must be verified. Candidate effect
classes are planning classifications:

- `query`: return bounded data; no publication. Emulation uses isolated inputs/results.
- `scalar candidate`: ordinary persisted private edits; only verified effect scopes qualify for
  three-way merge. Side effects/dependencies must be checked, not guessed from the method name.
- `program state`: capture/verify the saved private DB result; unchanged-base publication is
  required. After divergence, unverified categories retain explicit conflicts.
- `lifecycle`: facade owns save/open/binding/release; no direct bypass of publication authority.
- `project/files`: effects outside a program transaction need explicit selectors, owned staging,
  persistence verification and retained outcomes. File exports/imports do not rewrite target identity.
- `server`: explicit profile/repository administration; cannot silently release another writer
  or bypass the service's unknown-publication gate. These effects are not DB merge proposals.
- `debugger/UI`: owned GUI context/live process state; request identity avoids blind duplicate
  actions. Saved traces/results survive where supported; lost execution state is disconnected.
- `script`: capture program changes plus operation-specific external effects; no arbitrary replay
  or claim that program rollback undoes filesystem/network/process effects.
- `archive`: explicit external exchange; configured-service contract and outcome reconciliation.

These classes do not implement a generic changeset framework. Every entry needs an actual scoped
handler or an equivalent facade action and an acceptance case. Destructive actions retain their
explicit intent/permissions; automatic cleanup is confined to verified owned resources.

## Category totals

| Source category | Operations |
| --- | --- |
| analysis | 20 |
| comment | 4 |
| datatype | 32 |
| debugger | 16 |
| documentation | 12 |
| emulation | 2 |
| function | 23 |
| getter | 1 |
| headless | 3 |
| listing | 12 |
| malware | 5 |
| program | 33 |
| project | 11 |
| server | 18 |
| symbol | 4 |
| system | 1 |
| utility | 5 |
| xref | 8 |

## Operation ledger

### analysis

| Source operation | Facade action | Mode | Access | Scope | Effect/outcome class |
| --- | --- | --- | --- | --- | --- |
| `/analyze_control_flow` | `ghidra analysis analyze-control-flow` | gui + headless | READ_ONLY | C | query |
| `/analyze_data_region` | `ghidra analysis analyze-data-region` | gui + headless | WRITE | C | program state |
| `/analyze_dataflow` | `ghidra analysis analyze-dataflow` | gui + headless | READ_ONLY | C | query |
| `/analyze_for_documentation` | `ghidra analysis analyze-for-documentation` | gui + headless | READ_ONLY | C | query |
| `/analyze_function_complete` | `ghidra analysis analyze-function-complete` | gui + headless | READ_ONLY | C | query |
| `/analyze_function_completeness` | `ghidra analysis analyze-function-completeness` | gui + headless | READ_ONLY | C | query |
| `/batch_apply_documentation` | `ghidra analysis batch-apply-documentation` | gui + headless | WRITE | C | program state |
| `/configure_analyzer` | `ghidra analysis configure-analyzer` | gui + headless | WRITE | C | program state |
| `/detect_array_bounds` | `ghidra analysis detect-array-bounds` | gui + headless | WRITE | C | program state |
| `/find_code_gaps` | `ghidra analysis find-code-gaps` | gui + headless | READ_ONLY | C | query |
| `/find_dead_code` | `ghidra analysis find-dead-code` | gui + headless | READ_ONLY | C | query |
| `/find_next_undefined_function` | `ghidra analysis find-next-undefined-function` | gui + headless | READ_ONLY | C | query |
| `/find_similar_functions` | `ghidra analysis find-similar-functions` | gui + headless | READ_ONLY | C | query |
| `/get_field_access_context` | `ghidra analysis get-field-access-context` | gui + headless | READ_ONLY | C | query |
| `/get_function_pcode` | `ghidra analysis get-function-pcode` | gui + headless | READ_ONLY | C | query |
| `/inspect_memory_content` | `ghidra analysis inspect-memory-content` | gui + headless | READ_ONLY | C | query |
| `/list_analyzers` | `ghidra analysis list-analyzers` | gui + headless | READ_ONLY | C | query |
| `/run_analysis` | `ghidra analysis run` | gui + headless | WRITE | C | program state |
| `/search_byte_patterns` | `ghidra analysis search-byte-patterns` | gui + headless | READ_ONLY | C | query |
| `/search_instructions` | `ghidra analysis search-instructions` | gui + headless | READ_ONLY | C | query |

### comment

| Source operation | Facade action | Mode | Access | Scope | Effect/outcome class |
| --- | --- | --- | --- | --- | --- |
| `/batch_set_comments` | `ghidra comments set-batch` | gui + headless | WRITE | C | scalar candidate |
| `/clear_function_comments` | `ghidra comments clear-function` | gui + headless | DESTRUCTIVE | C | scalar candidate |
| `/get_comment` | `ghidra comments inspect` | gui + headless | READ_ONLY | C | query |
| `/set_comment` | `ghidra comments set` | gui + headless | WRITE | C | scalar candidate |

### datatype

| Source operation | Facade action | Mode | Access | Scope | Effect/outcome class |
| --- | --- | --- | --- | --- | --- |
| `/add_struct_field` | `ghidra types add-struct-field` | gui + headless | WRITE | C | program state |
| `/analyze_global_completeness` | `ghidra types analyze-global-completeness` | gui + headless | READ_ONLY | C | query |
| `/analyze_struct_field_usage` | `ghidra types analyze-struct-field-usage` | gui + headless | READ_ONLY | C | query |
| `/apply_data_classification` | `ghidra types apply-data-classification` | gui + headless | WRITE | C | program state |
| `/apply_data_type` | `ghidra types apply-data-type` | gui + headless | WRITE | C | program state |
| `/audit_global` | `ghidra types audit-global` | gui + headless | READ_ONLY | C | query |
| `/audit_globals_in_function` | `ghidra types audit-globals-in-function` | gui + headless | READ_ONLY | C | query |
| `/clone_data_type` | `ghidra types clone-data-type` | gui + headless | WRITE | C | program state |
| `/create_data_type_category` | `ghidra types create-data-type-category` | gui + headless | WRITE | C | program state |
| `/create_derived_type` | `ghidra types create-derived-type` | gui + headless | WRITE | C | program state |
| `/create_enum` | `ghidra types create-enum` | gui + headless | WRITE | C | program state |
| `/create_function_signature` | `ghidra types create-function-signature` | gui + headless | WRITE | C | program state |
| `/create_struct` | `ghidra types create-struct` | gui + headless | WRITE | C | program state |
| `/create_union` | `ghidra types create-union` | gui + headless | WRITE | C | program state |
| `/delete_data_type` | `ghidra types delete-data-type` | gui + headless | DESTRUCTIVE | C | program state |
| `/find_data_types` | `ghidra types find-data-types` | gui + headless | READ_ONLY | C | query |
| `/get_enum_values` | `ghidra types get-enum-values` | gui + headless | READ_ONLY | C | query |
| `/get_struct_layout` | `ghidra types get-struct-layout` | gui + headless | READ_ONLY | C | query |
| `/get_type_size` | `ghidra types get-type-size` | gui + headless | READ_ONLY | C | query |
| `/get_valid_data_types` | `ghidra types get-valid-data-types` | gui + headless | READ_ONLY | C | query |
| `/import_data_types` | `ghidra types import-data-types` | gui + headless | WRITE | C | program state |
| `/modify_struct_field` | `ghidra types modify-struct-field` | gui + headless | WRITE | C | program state |
| `/move_data_type_to_category` | `ghidra types move-data-type-to-category` | gui + headless | WRITE | C | program state |
| `/recreate_struct` | `ghidra types recreate-struct` | gui + headless | WRITE | C | program state |
| `/remove_struct_field` | `ghidra types remove-struct-field` | gui + headless | DESTRUCTIVE | C | program state |
| `/rename_data_type` | `ghidra types rename-data-type` | gui + headless | WRITE | C | program state |
| `/resize_struct` | `ghidra types resize-struct` | gui + headless | WRITE | C | program state |
| `/resolve_duplicate_type` | `ghidra types resolve-duplicate-type` | gui + headless | WRITE | C | program state |
| `/set_global` | `ghidra types set-global` | gui + headless | WRITE | C | program state |
| `/suggest_field_names` | `ghidra types suggest-field-names` | gui + headless | READ_ONLY | C | query |
| `/validate_data_type` | `ghidra types validate-data-type` | gui + headless | READ_ONLY | C | query |
| `/validate_function_prototype` | `ghidra types validate-function-prototype` | gui + headless | READ_ONLY | C | query |

### debugger

| Source operation | Facade action | Mode | Access | Scope | Effect/outcome class |
| --- | --- | --- | --- | --- | --- |
| `/debugger/dynamic_to_static` | `ghidra debugger dynamic-to-static` | gui | READ_ONLY | C | debugger/UI |
| `/debugger/interrupt` | `ghidra debugger interrupt` | gui | WRITE | C | debugger/UI |
| `/debugger/launch` | `ghidra debugger launch` | gui | WRITE | C | debugger/UI |
| `/debugger/launch_offers` | `ghidra debugger launch-offers` | gui | READ_ONLY | C | debugger/UI |
| `/debugger/list_breakpoints` | `ghidra debugger list-breakpoints` | gui | READ_ONLY | C | debugger/UI |
| `/debugger/modules` | `ghidra debugger modules` | gui | READ_ONLY | C | debugger/UI |
| `/debugger/read_memory` | `ghidra debugger read-memory` | gui | READ_ONLY | C | debugger/UI |
| `/debugger/registers` | `ghidra debugger registers` | gui | READ_ONLY | C | debugger/UI |
| `/debugger/remove_breakpoint` | `ghidra debugger remove-breakpoint` | gui | DESTRUCTIVE | C | debugger/UI |
| `/debugger/resume` | `ghidra debugger resume` | gui | WRITE | C | debugger/UI |
| `/debugger/set_breakpoint` | `ghidra debugger set-breakpoint` | gui | WRITE | C | debugger/UI |
| `/debugger/stack_trace` | `ghidra debugger stack-trace` | gui | READ_ONLY | C | debugger/UI |
| `/debugger/static_to_dynamic` | `ghidra debugger static-to-dynamic` | gui | READ_ONLY | C | debugger/UI |
| `/debugger/status` | `ghidra debugger status` | gui | READ_ONLY | C | debugger/UI |
| `/debugger/step` | `ghidra debugger step` | gui | WRITE | C | debugger/UI |
| `/debugger/traces` | `ghidra debugger traces` | gui | READ_ONLY | C | debugger/UI |

### documentation

| Source operation | Facade action | Mode | Access | Scope | Effect/outcome class |
| --- | --- | --- | --- | --- | --- |
| `/apply_function_documentation` | `ghidra documentation apply` | gui + headless | WRITE | C | program state |
| `/archive_ingest_function` | `ghidra archive ingest-function` | gui + headless | WRITE | C | archive |
| `/archive_ingest_program` | `ghidra archive ingest-program` | gui + headless | WRITE | C | archive |
| `/batch_string_anchor_report` | `ghidra documentation batch-string-anchor-report` | gui + headless | READ_ONLY | C | query |
| `/bulk_fuzzy_match` | `ghidra documentation bulk-fuzzy-match` | gui + headless | READ_ONLY | X | query |
| `/compare_programs_documentation` | `ghidra documentation compare` | gui + headless | READ_ONLY | X | query |
| `/diff_functions` | `ghidra functions diff` | gui + headless | READ_ONLY | X | query |
| `/find_similar_functions_fuzzy` | `ghidra documentation find-similar-functions-fuzzy` | gui + headless | READ_ONLY | X | query |
| `/find_undocumented_by_string` | `ghidra documentation find-undocumented-by-string` | gui + headless | READ_ONLY | C | query |
| `/get_function_documentation` | `ghidra documentation get` | gui + headless | READ_ONLY | C | query |
| `/get_function_hash` | `ghidra documentation get-function-hash` | gui + headless | READ_ONLY | C | query |
| `/merge_program_documentation` | `ghidra documentation transfer` | gui + headless | WRITE | X | program state |

### emulation

| Source operation | Facade action | Mode | Access | Scope | Effect/outcome class |
| --- | --- | --- | --- | --- | --- |
| `/emulate_function` | `ghidra emulation emulate-function` | gui + headless | READ_ONLY | C | query |
| `/emulate_hash_batch` | `ghidra emulation emulate-hash-batch` | gui + headless | READ_ONLY | C | query |

### function

| Source operation | Facade action | Mode | Access | Scope | Effect/outcome class |
| --- | --- | --- | --- | --- | --- |
| `/add_function_tag` | `ghidra functions add-function-tag` | gui + headless | WRITE | C | program state |
| `/batch_rename_function_components` | `ghidra functions batch-rename-function-components` | gui + headless | WRITE | C | program state |
| `/clear_flow_and_repair` | `ghidra functions clear-flow-and-repair` | gui + headless | DESTRUCTIVE | C | program state |
| `/clear_instruction_flow_override` | `ghidra functions clear-instruction-flow-override` | gui + headless | DESTRUCTIVE | C | program state |
| `/create_function` | `ghidra functions create` | gui + headless | WRITE | C | program state |
| `/delete_function` | `ghidra functions delete` | gui + headless | DESTRUCTIVE | C | program state |
| `/delete_function_tag` | `ghidra functions delete-function-tag` | gui + headless | DESTRUCTIVE | C | program state |
| `/disassemble_bytes` | `ghidra functions disassemble-bytes` | gui + headless | WRITE | C | program state |
| `/disassemble_function` | `ghidra functions disassemble` | gui + headless | READ_ONLY | C | query |
| `/force_decompile` | `ghidra functions force-decompile` | gui + headless | READ_ONLY | C | query |
| `/get_functions` | `ghidra functions inspect` | gui + headless | READ_ONLY | C | query |
| `/list_class_members` | `ghidra functions list-class-members` | gui + headless | READ_ONLY | C | query |
| `/list_function_tags` | `ghidra functions list-function-tags` | gui + headless | READ_ONLY | C | query |
| `/remove_function_tag` | `ghidra functions remove-function-tag` | gui + headless | DESTRUCTIVE | C | program state |
| `/rename_function` | `ghidra functions rename` | gui + headless | WRITE | C | scalar candidate |
| `/rename_variables` | `ghidra functions rename-variables` | gui + headless | WRITE | C | program state |
| `/set_function_no_return` | `ghidra functions set-function-no-return` | gui + headless | WRITE | C | program state |
| `/set_function_prototype` | `ghidra functions set-function-prototype` | gui + headless | WRITE | C | program state |
| `/set_function_tag_comment` | `ghidra functions set-function-tag-comment` | gui + headless | WRITE | C | program state |
| `/set_function_this_type` | `ghidra functions set-function-this-type` | gui + headless | WRITE | C | program state |
| `/set_variable_storage` | `ghidra functions set-variable-storage` | gui + headless | WRITE | C | program state |
| `/set_variable_type` | `ghidra functions set-variable-type` | gui + headless | WRITE | C | program state |
| `/set_variables` | `ghidra functions set-variables` | gui + headless | WRITE | C | program state |

### getter

| Source operation | Facade action | Mode | Access | Scope | Effect/outcome class |
| --- | --- | --- | --- | --- | --- |
| `/get_ui_cursor` | `ghidra ui cursor` | gui + headless | READ_ONLY | C | debugger/UI |

### headless

| Source operation | Facade action | Mode | Access | Scope | Effect/outcome class |
| --- | --- | --- | --- | --- | --- |
| `/close_project` | `ghidra projects close` | headless | DESTRUCTIVE | P | lifecycle |
| `/create_project` | `ghidra projects create` | headless | WRITE | P | lifecycle |
| `/open_project` | `ghidra projects open` | gui + headless | WRITE | P | lifecycle |

### listing

| Source operation | Facade action | Mode | Access | Scope | Effect/outcome class |
| --- | --- | --- | --- | --- | --- |
| `/convert_number` | `ghidra utility convert-number` | gui + headless | READ_ONLY | U | query |
| `/find_functions` | `ghidra functions search` | gui + headless | READ_ONLY | C | query |
| `/get_entry_points` | `ghidra listing get-entry-points` | gui + headless | READ_ONLY | C | query |
| `/get_external_location` | `ghidra listing get-external-location` | gui + headless | READ_ONLY | C | query |
| `/get_function_count` | `ghidra listing get-function-count` | gui + headless | READ_ONLY | C | query |
| `/list_calling_conventions` | `ghidra listing list-calling-conventions` | gui + headless | READ_ONLY | C | query |
| `/list_data_items_by_xrefs` | `ghidra listing list-data-items-by-xrefs` | gui + headless | READ_ONLY | C | query |
| `/list_globals` | `ghidra listing list-globals` | gui + headless | READ_ONLY | C | query |
| `/list_program_items` | `ghidra listing list-program-items` | gui + headless | READ_ONLY | C | query |
| `/list_shadowed_globals` | `ghidra listing list-shadowed-globals` | gui + headless | READ_ONLY | C | query |
| `/list_strings` | `ghidra strings list` | gui + headless | READ_ONLY | C | query |
| `/search_strings` | `ghidra strings search-regex` | gui + headless | READ_ONLY | C | query |

### malware

| Source operation | Facade action | Mode | Access | Scope | Effect/outcome class |
| --- | --- | --- | --- | --- | --- |
| `/analyze_api_call_chains` | `ghidra analysis analyze-api-call-chains` | gui + headless | READ_ONLY | C | query |
| `/detect_crypto_constants` | `ghidra analysis detect-crypto-constants` | gui + headless | READ_ONLY | C | query |
| `/detect_malware_behaviors` | `ghidra analysis detect-malware-behaviors` | gui + headless | READ_ONLY | C | query |
| `/extract_iocs_with_context` | `ghidra analysis extract-iocs-with-context` | gui + headless | READ_ONLY | C | query |
| `/find_anti_analysis_techniques` | `ghidra analysis find-anti-analysis-techniques` | gui + headless | READ_ONLY | C | query |

### program

| Source operation | Facade action | Mode | Access | Scope | Effect/outcome class |
| --- | --- | --- | --- | --- | --- |
| `/analysis_status` | `ghidra analysis status` | gui + headless | READ_ONLY | C | query |
| `/close_program` | `ghidra close` | gui + headless | DESTRUCTIVE | C | lifecycle |
| `/create_memory_block` | `ghidra memory create-block` | gui + headless | WRITE | C | program state |
| `/create_property_map` | `ghidra program create-property-map` | gui + headless | WRITE | C | program state |
| `/delete_bookmark` | `ghidra program delete-bookmark` | gui + headless | DESTRUCTIVE | C | program state |
| `/delete_property_map` | `ghidra program delete-property-map` | gui + headless | DESTRUCTIVE | C | program state |
| `/exit_ghidra` | `ghidra close (owned contexts, save before release)` | gui + headless | DESTRUCTIVE | C | lifecycle |
| `/get_address_spaces` | `ghidra memory spaces` | gui + headless | READ_ONLY | C | query |
| `/get_language_metadata` | `ghidra program get-language-metadata` | gui + headless | READ_ONLY | C | query |
| `/get_metadata` | `ghidra program metadata` | gui + headless | READ_ONLY | C | query |
| `/get_program_options` | `ghidra program get-program-options` | gui + headless | READ_ONLY | C | query |
| `/get_property` | `ghidra program get-property` | gui + headless | READ_ONLY | C | query |
| `/import_file` | `ghidra open` | gui + headless | WRITE | C | lifecycle |
| `/list_bookmarks` | `ghidra program list-bookmarks` | gui + headless | READ_ONLY | C | query |
| `/list_open_programs` | `sessions status (explicit session; targets list inventories inputs)` | gui + headless | READ_ONLY | C | lifecycle |
| `/list_project_files` | `ghidra projects files` | gui + headless | READ_ONLY | P | query |
| `/list_properties` | `ghidra program list-properties` | gui + headless | READ_ONLY | C | query |
| `/list_scripts` | `ghidra scripts list` | gui + headless | READ_ONLY | C | query |
| `/open_program` | `ghidra open` | gui + headless | WRITE | C | lifecycle |
| `/read_memory` | `ghidra memory read` | gui + headless | READ_ONLY | C | query |
| `/reanalyze` | `ghidra analysis reanalyze` | gui + headless | WRITE | C | program state |
| `/remove_program_option` | `ghidra program remove-program-option` | gui + headless | DESTRUCTIVE | C | program state |
| `/remove_property` | `ghidra program remove-property` | gui + headless | DESTRUCTIVE | C | program state |
| `/run_ghidra_script` | `ghidra scripts run` | gui + headless | WRITE | C | script |
| `/run_script_inline` | `ghidra scripts run-inline` | gui + headless | WRITE | C | script |
| `/save_all_programs` | `ghidra save-all (explicit session-wide selection)` | gui + headless | WRITE | C | lifecycle |
| `/save_program` | `ghidra save` | gui + headless | WRITE | C | lifecycle |
| `/set_bookmark` | `ghidra program set-bookmark` | gui + headless | WRITE | C | program state |
| `/set_image_base` | `ghidra program set-image-base` | gui + headless | WRITE | C | program state |
| `/set_memory_block` | `ghidra memory set-block` | gui + headless | WRITE | C | program state |
| `/set_program_option` | `ghidra program set-program-option` | gui + headless | WRITE | C | program state |
| `/set_property` | `ghidra program set-property` | gui + headless | WRITE | C | program state |
| `/switch_program` | `ghidra open (continuation; every research call carries explicit selectors)` | gui + headless | WRITE | C | lifecycle |

### project

| Source operation | Facade action | Mode | Access | Scope | Effect/outcome class |
| --- | --- | --- | --- | --- | --- |
| `/archive_project` | `ghidra projects archive` | gui + headless | WRITE | P | project/files |
| `/create_folder` | `ghidra projects create-folder` | gui + headless | WRITE | P | project/files |
| `/delete_file` | `ghidra projects delete-file` | gui + headless | DESTRUCTIVE | P | project/files |
| `/delete_project` | `ghidra projects delete` | headless | DESTRUCTIVE | P | lifecycle |
| `/export_program` | `ghidra program export` | gui + headless | WRITE | C | project/files |
| `/get_project_info` | `ghidra projects info` | gui + headless | READ_ONLY | P | query |
| `/import_program` | `ghidra program import` | gui + headless | WRITE | P | project/files |
| `/list_projects` | `ghidra projects list` | headless | READ_ONLY | P | lifecycle |
| `/move_file` | `ghidra projects move-file` | gui + headless | WRITE | P | project/files |
| `/move_folder` | `ghidra projects move-folder` | gui + headless | WRITE | P | project/files |
| `/restore_project` | `ghidra projects restore` | gui + headless | WRITE | P | project/files |

### server

| Source operation | Facade action | Mode | Access | Scope | Effect/outcome class |
| --- | --- | --- | --- | --- | --- |
| `/checkin_program` | `ghidra merge` | gui + headless | WRITE | C | lifecycle |
| `/server/admin/set_permissions` | `ghidra server admin set-permissions` | gui + headless | WRITE | P | server |
| `/server/admin/terminate_all_checkouts` | `ghidra server admin terminate-all-checkouts` | gui + headless | DESTRUCTIVE | P | server |
| `/server/admin/terminate_checkout` | `ghidra server admin terminate-checkout` | gui + headless | DESTRUCTIVE | P | server |
| `/server/admin/users` | `ghidra server admin users` | gui + headless | READ_ONLY | P | query |
| `/server/authenticate` | `auth login (Factory profile secrets)` | gui + headless | WRITE | P | lifecycle |
| `/server/checkouts` | `ghidra server checkouts` | gui + headless | READ_ONLY | P | query |
| `/server/connect` | `ghidra server connect` | gui + headless | WRITE | P | server |
| `/server/disconnect` | `ghidra server disconnect` | gui + headless | WRITE | P | server |
| `/server/repositories` | `ghidra server repositories list` | gui + headless | READ_ONLY | P | query |
| `/server/repository/create` | `ghidra server repositories create` | gui + headless | WRITE | P | server |
| `/server/repository/file` | `ghidra server repositories file` | gui + headless | READ_ONLY | P | query |
| `/server/repository/files` | `ghidra server repositories files` | gui + headless | READ_ONLY | P | query |
| `/server/status` | `ghidra server status` | gui + headless | READ_ONLY | P | query |
| `/server/version_control/add` | `ghidra open (automatic canonical registration)` | gui + headless | WRITE | P | lifecycle |
| `/server/version_control/checkout` | `ghidra open (private context; shared writer is internal)` | gui + headless | WRITE | C | lifecycle |
| `/server/version_control/undo_checkout` | `ghidra changes discard (explicit local intent)` | gui + headless | DESTRUCTIVE | C | lifecycle |
| `/server/version_history` | `ghidra server history` | gui + headless | READ_ONLY | P | query |

### symbol

| Source operation | Facade action | Mode | Access | Scope | Effect/outcome class |
| --- | --- | --- | --- | --- | --- |
| `/can_rename_at_address` | `ghidra symbols can-rename-at-address` | gui + headless | READ_ONLY | C | query |
| `/create_label` | `ghidra symbols create-label` | gui + headless | WRITE | C | program state |
| `/delete_label` | `ghidra symbols delete-label` | gui + headless | DESTRUCTIVE | C | program state |
| `/rename_symbol` | `ghidra symbols rename-symbol` | gui + headless | WRITE | C | program state |

### system

| Source operation | Facade action | Mode | Access | Scope | Effect/outcome class |
| --- | --- | --- | --- | --- | --- |
| `/prompt_policy` | `ghidra ui prompt-policy` | gui | WRITE | C | debugger/UI |

### utility

| Source operation | Facade action | Mode | Access | Scope | Effect/outcome class |
| --- | --- | --- | --- | --- | --- |
| `/check_connection` | `ghidra status` | gui + headless | READ_ONLY | C | lifecycle |
| `/mcp/health` | `ghidra status (tool health)` | gui + headless | READ_ONLY | C | lifecycle |
| `/mcp/schema` | `--help (Factory command discovery)` | gui + headless | READ_ONLY | U | lifecycle |
| `/tool/goto_address` | `ghidra ui goto` | gui | WRITE | C | debugger/UI |
| `/tool/running_tools` | `ghidra ui tools` | gui | READ_ONLY | C | debugger/UI |

### xref

| Source operation | Facade action | Mode | Access | Scope | Effect/outcome class |
| --- | --- | --- | --- | --- | --- |
| `/add_memory_reference` | `ghidra xrefs add-memory-reference` | gui + headless | WRITE | C | program state |
| `/analyze_call_graph` | `ghidra xrefs analyze-call-graph` | gui + headless | READ_ONLY | C | query |
| `/get_assembly_context` | `ghidra xrefs get-assembly-context` | gui + headless | READ_ONLY | C | query |
| `/get_full_call_graph` | `ghidra xrefs get-full-call-graph` | gui + headless | READ_ONLY | C | query |
| `/get_function_call_graph` | `ghidra xrefs get-function-call-graph` | gui + headless | READ_ONLY | C | query |
| `/get_xrefs_from` | `ghidra xrefs from` | gui + headless | READ_ONLY | C | query |
| `/get_xrefs_to` | `ghidra xrefs inspect-to` | gui + headless | READ_ONLY | C | query |
| `/remove_reference` | `ghidra xrefs remove-reference` | gui + headless | DESTRUCTIVE | C | program state |

## Static bridge equivalences

| Bridge control | Equivalent |
| --- | --- |
| `list_instances` | Root sessions/targets/status report logical owned contexts; backend roster is internal. |
| `connect_instance` | Scoped open/continuation chooses and verifies the owned binding; no mutable caller routing. |
| `list_tool_groups` | Factory generated group help/discovery accounts for available facade functionality. |
| `load_tool_group` | Facade commands are discoverable through Factory; bridge lazy loading is managed internally. |
| `unload_tool_group` | Internal discovery/resource behavior; caller functionality remains available through Factory. |
| `check_tools` | Facade capability/status checks report availability and prerequisites without MCP group management. |
| `search_tools` | Factory command help/discovery searches the facade functionality. |
| `import_file` | `ghidra open` performs scoped input import/selection; does not discover arbitrary external instances. |

## Completion evidence

Every source path and bridge control must remain accounted for at delivery. A replacement must
show the preserved user capability, not merely claim that the backend operation is hidden. Each
operation needs typed argument/result validation, selector/permission checks and an actual effect
or read assertion on suitable owned fixtures. A guarded unavailable result alone is not success
evidence for a capability included in the full delivery.

External dependencies and runtime prerequisites remain explicit: GUI actions use owned GUI
instances; debugger acceptance uses a supported macOS native fixture; archive exchange needs a
configured matching external service. Unit/contract fixtures establish adapter behavior, not the
production behavior of an independently deployed archive service.

The final coverage report must reference exact source/artifact versions, tested modes and fixture
classes, and retain unimplemented entries as open. The [plan](PLAN.md) requires combined acceptance
after all categories are present. Counts/annotations by themselves do not establish correctness,
capacity, isolation or automatic merge semantics.
