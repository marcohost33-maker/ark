# REGISTRY_POLICY_v1
Version: 1.0.5
Status: DRAFT

Plugin/contract resolution policy:
- exact pinning in kernel.plan wins
- otherwise highest compatible version within same MAJOR may be selected
- deprecated plugins must emit NEG.CONTRACT.DEPRECATED_PLUGIN_USED
- multiple providers for same output_schema are a hard error unless exact pin resolves the conflict
