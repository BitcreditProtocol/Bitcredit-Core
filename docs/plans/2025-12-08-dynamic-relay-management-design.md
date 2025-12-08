# Dynamic Relay Management Design

**Date:** 2025-12-08  
**Status:** ✅ Implemented

## Implementation Status

✅ **Completed:**
- Added `max_relays` configuration field with default of 50
- Implemented relay calculation algorithm with comprehensive tests (10 unit tests)
- Added relay management methods to NostrClient (calculate_relay_set, update_relays, refresh_relays)
- Integrated relay refresh on startup and contact updates
- All tests passing (694 tests)

**Verification:**
- `cargo test relay_calculation_tests` - 10/10 passing
- `cargo test` - 694 tests passing
- `cargo build` - Success

**Commits:**
- 57d3539: feat: add get_all() method to NostrContactStoreApi
- 8e66d4c: feat: add max_relays config field with default of 50
- 4ac3a08: feat: implement relay calculation algorithm with tests
- 4715817: fix: add max_relays to wasm config and clean up warnings
- b4beef6: feat: add relay management methods and update NostrClient creation
- f9be33d: feat: trigger relay refresh on contact updates

## Overview

Support multiple relays dynamically by connecting to both user-configured relays and relays from nostr contacts. Implement configurable limits with priority-based selection to ensure connectivity while preventing connection sprawl.

## Current State

✅ **Already Working:**
- Single Nostr client with multi-identity support
- Private messages already go to contact-specific relays via `send_event_to()`
- Contact relay storage in `NostrContact.relays`
- Relay fetching via NIP-65 relay list events
- Subscription filters based on contacts

⚠️ **Missing:**
- No relay connection management for contact relays
- No relay limits or deduplication
- No dynamic relay updates when contacts change

## Goals

1. Connect to all user-configured relays (always)
2. Connect to relays from trusted nostr contacts
3. Deduplicate relays across contacts
4. Enforce configurable upper limit on total relays
5. Ensure at least one relay per contact when under limit
6. Update relay connections when contacts change

## Architecture

### Component Changes

**1. Configuration (`NostrConfig` in `bcr-ebill-api/src/lib.rs`)**
```rust
pub struct NostrConfig {
    pub only_known_contacts: bool,
    pub relays: Vec<url::Url>,
    pub max_relays: Option<usize>,  // NEW: defaults to Some(50)
}
```

**2. Relay Management (`NostrClient` in `bcr-ebill-transport/src/nostr.rs`)**

New methods:
- `calculate_relay_set()` - computes complete relay set from user + contacts
- `update_relays()` - syncs relay changes with nostr_sdk client
- `refresh_relays()` - public trigger for relay recalculation

**3. Integration Points**
- **Startup**: Calculate and apply relay set in `NostrClient::new()`
- **Contact updates**: Trigger recalculation in `NostrContactProcessor` after upsert
- **Subscription addition**: Trigger after `add_contact_subscription()`

### Data Flow

```
NostrConfig.max_relays (50) + NostrConfig.relays (user relays)
                    ↓
        NostrContactStore (all contacts with relays)
                    ↓
    calculate_relay_set() applies two-pass algorithm:
      Pass 1: Add all user relays (always included)
      Pass 2: Add 1 relay per contact (Trusted > Participant priority)
      Pass 3: Fill remaining slots with additional contact relays
                    ↓
        HashSet<Url> (deduplicated relay set)
                    ↓
    update_relays() syncs with nostr_sdk Client
```

## Relay Selection Algorithm

### Two-Pass Algorithm

```rust
fn calculate_relay_set(
    user_relays: Vec<Url>,
    contacts: Vec<NostrContact>,
    max_relays: Option<usize>
) -> HashSet<Url> {
    let mut relay_set = HashSet::new();
    
    // Pass 1: Add all user relays (exempt from limit)
    for relay in user_relays {
        relay_set.insert(relay);
    }
    
    // Filter and sort contacts by trust level
    let mut eligible_contacts: Vec<&NostrContact> = contacts.iter()
        .filter(|c| matches!(c.trust_level, TrustLevel::Trusted | TrustLevel::Participant))
        .collect();
    
    // Sort: Trusted before Participant
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

### Trust Level Priority

**Included:**
- `TrustLevel::Trusted` (priority 0) - Successful handshake contacts
- `TrustLevel::Participant` (priority 1) - Encountered in bills (transitively trusted)

**Excluded:**
- `TrustLevel::None` - Unknown contacts
- `TrustLevel::Banned` - Actively blocked contacts

### Edge Cases

1. **No max_relays set**: Use `usize::MAX` - effectively unlimited
2. **Contact with no relays**: Skipped gracefully
3. **Duplicate relays across contacts**: `HashSet` automatically deduplicates
4. **Max < user_relays.len()**: User relays still all added (exempt from limit)
5. **More contacts than slots**: Each gets 1 relay up to limit
6. **Banned/None trust contacts**: Filtered out before processing

### Guarantees

✓ All user relays always included (exempt from limit)  
✓ At least 1 relay per contact up to `limit - user_relays.len()`  
✓ Trusted contacts prioritized over Participants  
✓ No duplicate relays  
✓ Deterministic ordering (stable sort by trust level)

## Error Handling

### Failure Modes

**Relay calculation failures:**
- `NostrContactStore` query fails → Log error, fall back to user relays only
- Relay URL parsing fails → Skip invalid relay, continue with valid ones
- `client.add_relay()` fails → Log warning, continue (relay may be unreachable)

**Graceful degradation:**
- Empty contact list → Use only user relays
- All contacts have no relays → Use only user relays
- Network issues → Existing connections maintained

## Implementation Structure

### New Methods in `NostrClient`

```rust
impl NostrClient {
    /// Calculate complete relay set from user config + contact relays
    async fn calculate_relay_set(&self) -> Result<HashSet<Url>>;
    
    /// Sync relay set with nostr_sdk client (add new, remove old)
    async fn update_relays(&self, target_relays: HashSet<Url>) -> Result<()>;
    
    /// Public trigger for external callers to refresh relay connections
    pub async fn refresh_relays(&self) -> Result<()>;
}
```

### Dependencies

- `NostrClient` needs access to `NostrContactStore` (pass reference or store during construction)
- `NostrClient` needs `max_relays` config (store during construction)
- Store user relays (already have in `self.relays`)

### Integration Points

**1. Startup** (`NostrClient::new()`)
```rust
// After creating client and adding initial relays
let relay_set = self.calculate_relay_set().await?;
self.update_relays(relay_set).await?;
```

**2. Contact Updates** (`handler/nostr_contact_processor.rs`)
```rust
// After contact_store.upsert()
nostr_client.refresh_relays().await?;
```

**3. Contact Subscription** (`nostr.rs::add_contact_subscription()`)
```rust
// After adding subscription
self.refresh_relays().await?;
```

## Testing Considerations

### Unit Tests

- Relay calculation with various contact scenarios
- Priority ordering (Trusted before Participant)
- Limit enforcement and "1 per contact" guarantee
- Deduplication across contacts
- User relays exempt from limit
- Edge cases (empty contacts, no relays, etc.)

### Integration Tests

- Relay updates triggered by contact changes
- Subscription additions trigger relay refresh
- Startup relay calculation with existing contacts

## Future Enhancements

- **Recency tracking**: Add `last_message_at` to `NostrContact` for recency-based prioritization
- **Relay health monitoring**: Track relay connectivity and deprioritize failing relays
- **Relay ownership tracking**: Map relays to contacts for better removal handling
- **Dynamic limits**: Adjust limits based on bandwidth/connection constraints

## Configuration Example

```rust
NostrConfig {
    only_known_contacts: true,
    relays: vec![
        "wss://relay.damus.io".parse()?,
        "wss://relay.nostr.band".parse()?,
    ],
    max_relays: Some(50),  // Up to 50 contact relays + 2 user relays = 52 total
}
```

## Summary

This design provides dynamic relay management that:
- Ensures connectivity to user's own relays (always)
- Extends reach to trusted contact relays (priority-based)
- Prevents connection sprawl (configurable limits)
- Maintains fairness (at least 1 relay per contact)
- Updates reactively (on contact changes)
- Degrades gracefully (falls back to user relays on errors)
