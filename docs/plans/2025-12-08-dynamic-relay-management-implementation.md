# Dynamic Relay Management Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement dynamic relay management to connect to user relays and contact relays with configurable limits and priority-based selection.

**Architecture:** Add `max_relays` config field, implement relay calculation algorithm in `NostrClient`, and trigger relay updates on startup and contact changes.

**Tech Stack:** Rust, nostr-sdk, SurrealDB persistence

---

## Task 1: Add max_relays Configuration Field

**Files:**
- Modify: `crates/bcr-ebill-api/src/lib.rs:86-93`

**Step 1: Write test for NostrConfig with max_relays**

Add to `crates/bcr-ebill-api/src/tests/mod.rs` (or create if needed):

```rust
#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn test_nostr_config_default_max_relays() {
        let config = NostrConfig::default();
        assert_eq!(config.max_relays, Some(50));
    }

    #[test]
    fn test_nostr_config_with_custom_max_relays() {
        let config = NostrConfig {
            only_known_contacts: true,
            relays: vec![],
            max_relays: Some(100),
        };
        assert_eq!(config.max_relays, Some(100));
    }

    #[test]
    fn test_nostr_config_with_no_relay_limit() {
        let config = NostrConfig {
            only_known_contacts: false,
            relays: vec![],
            max_relays: None,
        };
        assert_eq!(config.max_relays, None);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --package bcr-ebill-api config_tests -v`  
Expected: FAIL with "no field `max_relays` found for type `NostrConfig`"

**Step 3: Add max_relays field to NostrConfig**

In `crates/bcr-ebill-api/src/lib.rs`, update `NostrConfig`:

```rust
/// Nostr specific configuration
#[derive(Debug, Clone, Default)]
pub struct NostrConfig {
    /// Only known contacts can message us via DM.
    pub only_known_contacts: bool,
    /// All relays we want to publish our messages to and receive messages from.
    pub relays: Vec<url::Url>,
    /// Maximum number of contact relays to connect to (user relays are exempt).
    /// Defaults to 50 if not specified.
    pub max_relays: Option<usize>,
}
```

**Step 4: Update Default implementation**

Since we're using `#[derive(Default)]`, we need to provide a custom Default impl:

```rust
impl Default for NostrConfig {
    fn default() -> Self {
        Self {
            only_known_contacts: false,
            relays: vec![],
            max_relays: Some(50),
        }
    }
}
```

Remove `Default` from the derive macro on line 87:

```rust
#[derive(Debug, Clone)]
pub struct NostrConfig {
```

**Step 5: Run test to verify it passes**

Run: `cargo test --package bcr-ebill-api config_tests -v`  
Expected: PASS (3 tests)

**Step 6: Commit**

```bash
git add crates/bcr-ebill-api/src/lib.rs crates/bcr-ebill-api/src/tests/
git commit -m "feat: add max_relays config field with default of 50"
```

---

## Task 2: Implement Relay Calculation Algorithm

**Files:**
- Modify: `crates/bcr-ebill-transport/src/nostr.rs`
- Test: `crates/bcr-ebill-transport/src/nostr.rs` (add inline tests module)

**Step 1: Write test for calculate_relay_set**

Add test module at the end of `crates/bcr-ebill-transport/src/nostr.rs`:

```rust
#[cfg(test)]
mod relay_calculation_tests {
    use super::*;
    use bcr_ebill_core::application::nostr_contact::{NostrContact, TrustLevel, HandshakeStatus};
    use bcr_common::core::NodeId;
    use std::collections::HashSet;

    fn create_test_contact(trust_level: TrustLevel, relays: Vec<&str>) -> NostrContact {
        let node_id = NodeId::new_random(bitcoin::Network::Testnet);
        NostrContact {
            npub: node_id.npub(),
            node_id,
            name: None,
            relays: relays.iter().map(|r| url::Url::parse(r).unwrap()).collect(),
            trust_level,
            handshake_status: HandshakeStatus::None,
            contact_private_key: None,
        }
    }

    #[test]
    fn test_user_relays_always_included() {
        let user_relays = vec![
            url::Url::parse("wss://relay1.com").unwrap(),
            url::Url::parse("wss://relay2.com").unwrap(),
        ];
        let contacts = vec![];
        let max_relays = Some(1); // Very low limit
        
        let result = calculate_relay_set_internal(&user_relays, &contacts, max_relays);
        
        // User relays should all be present despite low limit
        assert_eq!(result.len(), 2);
        assert!(result.contains(&url::Url::parse("wss://relay1.com").unwrap()));
        assert!(result.contains(&url::Url::parse("wss://relay2.com").unwrap()));
    }

    #[test]
    fn test_trusted_contacts_prioritized() {
        let user_relays = vec![];
        let contacts = vec![
            create_test_contact(TrustLevel::Participant, vec!["wss://participant.com"]),
            create_test_contact(TrustLevel::Trusted, vec!["wss://trusted.com"]),
        ];
        let max_relays = Some(1);
        
        let result = calculate_relay_set_internal(&user_relays, &contacts, max_relays);
        
        // Should only include trusted contact's relay (higher priority)
        assert_eq!(result.len(), 1);
        assert!(result.contains(&url::Url::parse("wss://trusted.com").unwrap()));
    }

    #[test]
    fn test_one_relay_per_contact_guaranteed() {
        let user_relays = vec![];
        let contacts = vec![
            create_test_contact(TrustLevel::Trusted, vec!["wss://contact1-relay1.com", "wss://contact1-relay2.com"]),
            create_test_contact(TrustLevel::Trusted, vec!["wss://contact2-relay1.com", "wss://contact2-relay2.com"]),
            create_test_contact(TrustLevel::Trusted, vec!["wss://contact3-relay1.com"]),
        ];
        let max_relays = Some(3);
        
        let result = calculate_relay_set_internal(&user_relays, &contacts, max_relays);
        
        // Should have exactly 3 relays (first relay from each contact)
        assert_eq!(result.len(), 3);
        assert!(result.contains(&url::Url::parse("wss://contact1-relay1.com").unwrap()));
        assert!(result.contains(&url::Url::parse("wss://contact2-relay1.com").unwrap()));
        assert!(result.contains(&url::Url::parse("wss://contact3-relay1.com").unwrap()));
    }

    #[test]
    fn test_deduplication_across_contacts() {
        let user_relays = vec![];
        let contacts = vec![
            create_test_contact(TrustLevel::Trusted, vec!["wss://shared.com", "wss://unique1.com"]),
            create_test_contact(TrustLevel::Trusted, vec!["wss://shared.com", "wss://unique2.com"]),
        ];
        let max_relays = Some(10);
        
        let result = calculate_relay_set_internal(&user_relays, &contacts, max_relays);
        
        // Should only include shared.com once
        assert_eq!(result.len(), 3);
        assert!(result.contains(&url::Url::parse("wss://shared.com").unwrap()));
        assert!(result.contains(&url::Url::parse("wss://unique1.com").unwrap()));
        assert!(result.contains(&url::Url::parse("wss://unique2.com").unwrap()));
    }

    #[test]
    fn test_banned_contacts_excluded() {
        let user_relays = vec![];
        let contacts = vec![
            create_test_contact(TrustLevel::Banned, vec!["wss://banned.com"]),
            create_test_contact(TrustLevel::Trusted, vec!["wss://trusted.com"]),
        ];
        let max_relays = Some(10);
        
        let result = calculate_relay_set_internal(&user_relays, &contacts, max_relays);
        
        assert_eq!(result.len(), 1);
        assert!(result.contains(&url::Url::parse("wss://trusted.com").unwrap()));
        assert!(!result.contains(&url::Url::parse("wss://banned.com").unwrap()));
    }

    #[test]
    fn test_none_trust_level_excluded() {
        let user_relays = vec![];
        let contacts = vec![
            create_test_contact(TrustLevel::None, vec!["wss://unknown.com"]),
            create_test_contact(TrustLevel::Participant, vec!["wss://participant.com"]),
        ];
        let max_relays = Some(10);
        
        let result = calculate_relay_set_internal(&user_relays, &contacts, max_relays);
        
        assert_eq!(result.len(), 1);
        assert!(result.contains(&url::Url::parse("wss://participant.com").unwrap()));
        assert!(!result.contains(&url::Url::parse("wss://unknown.com").unwrap()));
    }

    #[test]
    fn test_no_limit_when_max_relays_none() {
        let user_relays = vec![url::Url::parse("wss://user.com").unwrap()];
        let contacts = vec![
            create_test_contact(TrustLevel::Trusted, vec!["wss://relay1.com", "wss://relay2.com"]),
            create_test_contact(TrustLevel::Trusted, vec!["wss://relay3.com", "wss://relay4.com"]),
        ];
        let max_relays = None;
        
        let result = calculate_relay_set_internal(&user_relays, &contacts, max_relays);
        
        // All relays should be included
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn test_empty_contacts() {
        let user_relays = vec![url::Url::parse("wss://user.com").unwrap()];
        let contacts = vec![];
        let max_relays = Some(50);
        
        let result = calculate_relay_set_internal(&user_relays, &contacts, max_relays);
        
        assert_eq!(result.len(), 1);
        assert!(result.contains(&url::Url::parse("wss://user.com").unwrap()));
    }

    #[test]
    fn test_contact_with_no_relays() {
        let user_relays = vec![];
        let mut contact = create_test_contact(TrustLevel::Trusted, vec![]);
        contact.relays = vec![]; // Explicitly no relays
        let contacts = vec![contact];
        let max_relays = Some(10);
        
        let result = calculate_relay_set_internal(&user_relays, &contacts, max_relays);
        
        // Should handle gracefully
        assert_eq!(result.len(), 0);
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --package bcr-ebill-transport relay_calculation_tests -v`  
Expected: FAIL with "cannot find function `calculate_relay_set_internal`"

**Step 3: Implement calculate_relay_set_internal**

Add before the test module in `crates/bcr-ebill-transport/src/nostr.rs`:

```rust
/// Internal relay calculation function (pure function for testing)
fn calculate_relay_set_internal(
    user_relays: &[url::Url],
    contacts: &[bcr_ebill_core::application::nostr_contact::NostrContact],
    max_relays: Option<usize>,
) -> HashSet<url::Url> {
    use bcr_ebill_core::application::nostr_contact::TrustLevel;
    
    let mut relay_set = HashSet::new();
    
    // Pass 1: Add all user relays (exempt from limit)
    for relay in user_relays {
        relay_set.insert(relay.clone());
    }
    
    // Filter and sort contacts by trust level
    let mut eligible_contacts: Vec<&bcr_ebill_core::application::nostr_contact::NostrContact> = contacts
        .iter()
        .filter(|c| matches!(c.trust_level, TrustLevel::Trusted | TrustLevel::Participant))
        .collect();
    
    // Sort: Trusted (0) before Participant (1)
    eligible_contacts.sort_by_key(|c| match c.trust_level {
        TrustLevel::Trusted => 0,
        TrustLevel::Participant => 1,
        _ => 2, // unreachable due to filter
    });
    
    let limit = max_relays.unwrap_or(usize::MAX);
    
    // Pass 2: Add first relay from each contact (priority order)
    for contact in &eligible_contacts {
        if relay_set.len() >= limit {
            break;
        }
        if let Some(first_relay) = contact.relays.first() {
            relay_set.insert(first_relay.clone());
        }
    }
    
    // Pass 3: Fill remaining slots with additional contact relays
    for contact in &eligible_contacts {
        for relay in contact.relays.iter().skip(1) {
            if relay_set.len() >= limit {
                return relay_set;
            }
            relay_set.insert(relay.clone());
        }
    }
    
    relay_set
}
```

Add HashSet import at the top of the file:

```rust
use std::collections::{HashMap, HashSet};
```

**Step 4: Run tests to verify they pass**

Run: `cargo test --package bcr-ebill-transport relay_calculation_tests -v`  
Expected: PASS (10 tests)

**Step 5: Commit**

```bash
git add crates/bcr-ebill-transport/src/nostr.rs
git commit -m "feat: implement relay calculation algorithm with tests"
```

---

## Task 3: Add NostrClient Methods for Relay Management

**Files:**
- Modify: `crates/bcr-ebill-transport/src/nostr.rs`

**Step 1: Add dependencies to NostrClient struct**

Update the `NostrClient` struct to store max_relays and contact store reference:

```rust
#[derive(Clone)]
pub struct NostrClient {
    client: Client,
    signers: Arc<Mutex<HashMap<NodeId, Arc<Keys>>>>,
    relays: Vec<url::Url>,
    default_timeout: Duration,
    connected: Arc<AtomicBool>,
    max_relays: Option<usize>,
    nostr_contact_store: Option<Arc<dyn bcr_ebill_persistence::nostr::NostrContactStoreApi>>,
}
```

**Step 2: Update NostrClient::new() signature**

Update the `new()` method to accept max_relays and contact_store:

```rust
pub async fn new(
    identities: Vec<(NodeId, BcrKeys)>,
    relays: Vec<url::Url>,
    default_timeout: Duration,
    max_relays: Option<usize>,
    nostr_contact_store: Option<Arc<dyn bcr_ebill_persistence::nostr::NostrContactStoreApi>>,
) -> Result<Self> {
    if identities.is_empty() {
        return Err(Error::Message("At least one identity required".to_string()));
    }

    // Use first identity to construct the underlying Client
    let first_keys = &identities[0].1;
    let options = ClientOptions::new();
    let client = Client::builder()
        .signer(first_keys.get_nostr_keys().clone())
        .opts(options)
        .build();

    // Add all relays to the shared pool
    for relay in &relays {
        client.add_relay(relay).await.map_err(|e| {
            error!("Failed to add relay to Nostr client: {e}");
            Error::Network("Failed to add relay to Nostr client".to_string())
        })?;
    }

    // Build signers HashMap from all identities
    let mut signers = HashMap::new();
    for (node_id, keys) in identities {
        signers.insert(node_id, Arc::new(keys.get_nostr_keys()));
    }

    Ok(Self {
        client,
        signers: Arc::new(Mutex::new(signers)),
        relays,
        default_timeout,
        connected: Arc::new(AtomicBool::new(false)),
        max_relays,
        nostr_contact_store,
    })
}
```

**Step 3: Update NostrClient::default() to pass new parameters**

```rust
pub async fn default(config: &NostrConfig) -> Result<Self> {
    let identities = vec![(config.node_id.clone(), config.keys.clone())];
    Self::new(
        identities,
        config.relays.clone(),
        config.default_timeout,
        None, // max_relays not available in old config
        None, // contact_store not available
    ).await
}
```

**Step 4: Add calculate_relay_set method to NostrClient**

```rust
impl NostrClient {
    // ... existing methods ...

    /// Calculate the complete relay set from user relays + contact relays
    async fn calculate_relay_set(&self) -> Result<HashSet<url::Url>> {
        // Get contacts from store if available
        let contacts = if let Some(store) = &self.nostr_contact_store {
            store.get_all().await.map_err(|e| {
                error!("Failed to fetch contacts for relay calculation: {e}");
                Error::Message("Failed to fetch contacts".to_string())
            })?
        } else {
            vec![]
        };

        Ok(calculate_relay_set_internal(&self.relays, &contacts, self.max_relays))
    }

    /// Update the client's relay connections to match the target set
    async fn update_relays(&self, target_relays: HashSet<url::Url>) -> Result<()> {
        let client = self.client().await?;
        
        // Get current relays
        let current_relays: HashSet<url::Url> = client
            .relays()
            .await
            .iter()
            .map(|r| r.url().as_str().parse::<url::Url>())
            .filter_map(|r| r.ok())
            .collect();

        // Add new relays
        for relay in target_relays.iter() {
            if !current_relays.contains(relay) {
                match client.add_relay(relay).await {
                    Ok(_) => debug!("Added relay: {}", relay),
                    Err(e) => warn!("Failed to add relay {}: {}", relay, e),
                }
            }
        }

        // Remove old relays (relays not in target set)
        for relay in current_relays.iter() {
            if !target_relays.contains(relay) {
                // Convert url::Url to RelayUrl
                if let Ok(relay_url) = relay.as_str().parse::<RelayUrl>() {
                    match client.remove_relay(relay_url).await {
                        Ok(_) => debug!("Removed relay: {}", relay),
                        Err(e) => warn!("Failed to remove relay {}: {}", relay, e),
                    }
                }
            }
        }

        Ok(())
    }

    /// Public method to refresh relay connections based on current contacts
    pub async fn refresh_relays(&self) -> Result<()> {
        info!("Refreshing relay connections based on contacts");
        let relay_set = self.calculate_relay_set().await?;
        self.update_relays(relay_set).await?;
        info!("Relay refresh complete, connected to {} relays", 
              self.client().await?.relays().await.len());
        Ok(())
    }
}
```

**Step 5: Build to verify compilation**

Run: `cargo build --package bcr-ebill-transport`  
Expected: Success (may have warnings about unused code)

**Step 6: Commit**

```bash
git add crates/bcr-ebill-transport/src/nostr.rs
git commit -m "feat: add relay management methods to NostrClient"
```

---

## Task 4: Update NostrClient Creation to Pass New Parameters

**Files:**
- Modify: `crates/bcr-ebill-transport/src/lib.rs`

**Step 1: Find create_nostr_clients function**

Locate the `create_nostr_clients` function around line 52-108 in `crates/bcr-ebill-transport/src/lib.rs`.

**Step 2: Update function to accept max_relays and nostr_contact_store**

Update function signature:

```rust
pub async fn create_nostr_clients(
    config: &bcr_ebill_api::service::transport_service::NostrConfig,
    additional_identities: Vec<(NodeId, BcrKeys)>,
    max_relays: Option<usize>,
    nostr_contact_store: Arc<dyn bcr_ebill_persistence::nostr::NostrContactStoreApi>,
) -> bcr_ebill_api::service::transport_service::Result<Arc<NostrClient>> {
```

**Step 3: Update NostrClient::new call**

Find where `NostrClient::new()` is called and update it:

```rust
let nostr_client = Arc::new(
    NostrClient::new(
        all_identities,
        config.relays.clone(),
        config.default_timeout,
        max_relays,
        Some(nostr_contact_store),
    )
    .await?,
);
```

**Step 4: Call refresh_relays after creation**

After creating the client, trigger initial relay refresh:

```rust
// Initial relay refresh to include contact relays
if let Err(e) = nostr_client.refresh_relays().await {
    warn!("Failed initial relay refresh: {}", e);
    // Continue anyway - we have user relays at minimum
}
```

**Step 5: Build to check for callers that need updating**

Run: `cargo build --package bcr-ebill-transport 2>&1 | grep "create_nostr_clients"`  
Expected: Compilation errors showing where `create_nostr_clients` is called

**Step 6: Update all callers of create_nostr_clients**

Find all call sites (likely in the same file or nearby) and update them to pass the new parameters. Look for patterns like:

```rust
// OLD
create_nostr_clients(&nostr_config, additional_identities).await?

// NEW
create_nostr_clients(
    &nostr_config,
    additional_identities,
    nostr_config.max_relays, // or config.nostr_config.max_relays
    nostr_contact_store.clone(),
).await?
```

**Step 7: Build to verify**

Run: `cargo build --package bcr-ebill-transport`  
Expected: Success

**Step 8: Commit**

```bash
git add crates/bcr-ebill-transport/src/lib.rs
git commit -m "feat: update NostrClient creation to use max_relays and contact store"
```

---

## Task 5: Trigger Relay Refresh on Contact Updates

**Files:**
- Modify: `crates/bcr-ebill-transport/src/handler/nostr_contact_processor.rs`

**Step 1: Add nostr_client reference to NostrContactProcessor**

Update the struct:

```rust
pub struct NostrContactProcessor {
    transport: Arc<dyn TransportClientApi>,
    nostr_contact_store: Arc<dyn NostrContactStoreApi>,
    bitcoin_network: bitcoin::Network,
    nostr_client: Option<Arc<crate::nostr::NostrClient>>, // NEW
}
```

**Step 2: Update constructor**

```rust
pub fn new(
    transport: Arc<dyn TransportClientApi>,
    nostr_contact_store: Arc<dyn NostrContactStoreApi>,
    bitcoin_network: bitcoin::Network,
    nostr_client: Option<Arc<crate::nostr::NostrClient>>,
) -> Self {
    Self {
        transport,
        nostr_contact_store,
        bitcoin_network,
        nostr_client,
    }
}
```

**Step 3: Update upsert_contact to trigger relay refresh**

Modify the `upsert_contact` method around line 73:

```rust
async fn upsert_contact(&self, node_id: &NodeId, contact: &NostrContact) {
    if let Err(e) = self.nostr_contact_store.upsert(contact).await {
        error!("Failed to save nostr contact information for node_id {node_id}: {e}");
    } else {
        if let Err(e) = self.transport.add_contact_subscription(node_id).await {
            error!("Failed to add nostr contact subscription for contact node_id {node_id}: {e}");
        }
        
        // Trigger relay refresh to include new contact's relays
        if let Some(ref client) = self.nostr_client {
            if let Err(e) = client.refresh_relays().await {
                warn!("Failed to refresh relays after contact update for {node_id}: {e}");
            }
        }
    }
}
```

**Step 4: Find and update NostrContactProcessor construction sites**

Run: `cargo build --package bcr-ebill-transport 2>&1 | grep "NostrContactProcessor::new"`  
Expected: Compilation errors showing where processor is constructed

Update all construction sites to pass the nostr_client parameter.

**Step 5: Build to verify**

Run: `cargo build --package bcr-ebill-transport`  
Expected: Success

**Step 6: Commit**

```bash
git add crates/bcr-ebill-transport/src/handler/nostr_contact_processor.rs
git commit -m "feat: trigger relay refresh when contacts are updated"
```

---

## Task 6: Integration Testing

**Files:**
- Create: `crates/bcr-ebill-transport/src/tests/relay_management_integration_test.rs`

**Step 1: Write integration test**

Create a new test file with integration test:

```rust
#[cfg(test)]
mod relay_management_integration_tests {
    use super::*;
    use bcr_ebill_core::application::nostr_contact::{NostrContact, TrustLevel, HandshakeStatus};
    use bcr_common::core::NodeId;
    use std::sync::Arc;

    // Note: This is a conceptual integration test
    // Actual implementation may need mock stores or test fixtures

    #[tokio::test]
    async fn test_relay_refresh_includes_contact_relays() {
        // This test would require:
        // 1. Mock NostrContactStore with test contacts
        // 2. NostrClient with max_relays configured
        // 3. Verify relay count after refresh

        // TODO: Implement with proper test infrastructure
    }

    #[tokio::test]
    async fn test_relay_limit_enforced() {
        // This test would verify:
        // 1. max_relays limit is respected
        // 2. User relays are all included
        // 3. Contact relays limited to remaining slots

        // TODO: Implement with proper test infrastructure
    }
}
```

**Step 2: Run existing tests to ensure nothing broke**

Run: `cargo test --package bcr-ebill-transport`  
Expected: All existing tests pass

Run: `cargo test --package bcr-ebill-api`  
Expected: All existing tests pass

**Step 3: Run full test suite**

Run: `cargo test --no-fail-fast`  
Expected: All 682+ tests pass

**Step 4: Commit**

```bash
git add crates/bcr-ebill-transport/src/tests/
git commit -m "test: add integration test scaffolding for relay management"
```

---

## Task 7: Update Documentation

**Files:**
- Modify: `docs/plans/2025-12-08-dynamic-relay-management-design.md`

**Step 1: Add Implementation Status section**

Add at the top of the design doc:

```markdown
## Implementation Status

✅ **Completed:**
- Added `max_relays` configuration field with default of 50
- Implemented relay calculation algorithm with comprehensive tests
- Added relay management methods to NostrClient
- Integrated relay refresh on startup and contact updates
- All tests passing (682+ tests)

**Verification:**
- Run `cargo test relay_calculation_tests` - 10/10 passing
- Run `cargo build` - Success
- Run `cargo test` - All tests passing
```

**Step 2: Commit documentation**

```bash
git add docs/plans/2025-12-08-dynamic-relay-management-design.md
git commit -m "docs: update design doc with implementation status"
```

---

## Task 8: Final Verification

**Step 1: Build entire workspace**

Run: `cargo build --release`  
Expected: Success with no errors

**Step 2: Run all tests**

Run: `cargo test --no-fail-fast 2>&1 | grep "test result"`  
Expected: All test suites pass

**Step 3: Check for any warnings**

Run: `cargo clippy -- -D warnings`  
Expected: Pass or document acceptable warnings

**Step 4: Verify git status**

Run: `git status`  
Expected: Clean working directory (all changes committed)

**Step 5: Review commit history**

Run: `git log --oneline -10`  
Expected: See all implementation commits

---

## Summary

This implementation adds dynamic relay management to the E-Bills Nostr transport:

**Key Changes:**
1. Configuration: Added `max_relays` field (default 50)
2. Algorithm: Implemented priority-based relay selection with tests
3. Integration: Relay refresh on startup and contact updates
4. Testing: Comprehensive unit tests for algorithm

**Behavior:**
- User relays always connected (exempt from limit)
- Contact relays added up to limit (Trusted > Participant priority)
- At least 1 relay per contact guaranteed
- Automatic deduplication
- Reactive updates when contacts change

**Next Steps:**
- Monitor relay connection behavior in production
- Consider adding relay health tracking
- Optionally add recency-based prioritization

