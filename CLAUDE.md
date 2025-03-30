# Guide for Claude Code in crx3-rs

## Build/Test Commands
- Build: `cargo build`
- Run: `cargo run`
- Test: `cargo test`
- Run specific test: `cargo test test_name`
- Check: `cargo check`
- Lint: `cargo clippy`
- Format: `cargo fmt`

## Code Style Guidelines
- **Edition**: Rust 2024
- **Formatting**: Follow rustfmt conventions
- **Error Handling**: Use proper Result types, avoid unwrap() in production code
- **Naming**: Use snake_case for variables/functions, CamelCase for types
- **Imports**: Group by standard lib, external crates, then internal modules
- **Documentation**: Document public API with /// comments
- **Types**: Use strong typing, avoid unnecessary type conversions
- **Protocol Buffers**: Use prost-generated types directly
- **Security**: Handle private keys securely, validate inputs
- **Testing**: Write unit tests for critical functionality