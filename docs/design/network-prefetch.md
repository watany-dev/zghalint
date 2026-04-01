# Parallel Network Prefetch Design

## Overview

zghalint's 4 network-dependent rules (SC003-SC006) previously executed sequentially, each creating its own `std.http.Client` with no connection reuse or parallelism. The prefetch system collects all action references before rule execution and fetches API data in parallel using `std.Thread.Pool`, populating each rule module's cache so that rule execution hits only cached data.

## Architecture

```
[Parse All Files] -> [Collect ActionRefs] -> [Thread Pool Prefetch] -> [Populate Caches] -> [Run Rules (all cache hits)]
```

### Module: `src/rules/prefetch.zig`

Single public entry point:

```zig
pub fn prefetchAll(backing_allocator: Allocator, workflows: []const Workflow) void
```

### Processing Flow

1. **Early return**: Skip if `ZGHALINT_OFFLINE=1` or network deadline exceeded
2. **Arena allocation**: Temporary arena for collection phase data
3. **Collection**: Walk workflows -> jobs -> steps -> `ActionRef`, classifying into:
   - `has_actions: bool` (SC003: 1 bulk advisory fetch)
   - `unique_repos` (SC004: `owner/repo` for archived check)
   - `unique_sha_pins` (SC005: `owner/repo@sha` for stale ref check)
   - `unique_tag_refs` (SC006: `owner/repo@ref` for ref confusion check)
4. **Result slot allocation**: Pre-allocate per-task result structs indexed by task
5. **Thread pool execution**: `std.Thread.Pool` + `WaitGroup`, max 8 threads
6. **Cache population**: Main thread iterates results and calls each module's `setCachedResult` API
7. **Cleanup**: Arena freed, pool destroyed

## Result Types

```zig
const ArchivedResult = struct { owner: []const u8, repo: []const u8, value: ?bool };
const StaleRefResult = struct { owner: []const u8, repo: []const u8, sha: []const u8, value: TagResolution };
const RefResult = struct { owner: []const u8, repo: []const u8, ref: []const u8, value: RefStatus };
```

## Worker Functions

Each worker calls the existing module's pub fetch function directly (no logic duplication):

| Rule | Worker | Fetch Function | Allocator |
|------|--------|----------------|-----------|
| SC003 | `fetchAdvisoryTask` | `advisory.fetchAndParse` | `ThreadSafeAllocator` wrapping advisory arena |
| SC004 | `fetchArchivedTask` | `archived.fetchArchiveStatus` | `page_allocator` (worker-local) |
| SC005 | `fetchStaleRefTask` | `stale_refs.resolveTagForSha` | `page_allocator` (worker-local) |
| SC006 | `fetchRefTask` | `refconfusion.queryRefStatus` | `page_allocator` (worker-local) |

## Memory Lifetime

| Data | Lifetime | Allocator | Thread Safety |
|------|----------|-----------|---------------|
| Advisory array + strings | Program exit | advisory arena via `ThreadSafeAllocator` | Mutex-protected |
| Worker temp buffers (URL, HTTP response) | Worker function scope | `page_allocator` | Not needed (local) |
| Collection HashMaps | `prefetchAll` scope | prefetch arena | Not needed (main thread) |
| Result slot arrays | `prefetchAll` scope | prefetch arena | Index-separated (no contention) |
| Cache key strings | Program exit | Each module's arena | Not needed (main thread populates) |

## Thread Safety

- `std.http.Client` has internal mutex-protected connection pool (thread-safe)
- `refconfusion.rate_limited` uses `std.atomic.Value(bool)` with `.monotonic` ordering for lock-free sharing across workers
- Result slots are pre-allocated and indexed per-worker (no shared writes)
- Cache population happens after `WaitGroup.wait()` on the main thread only

## Error Handling (Fail-Open)

| Error | Result Value | Rule Behavior |
|-------|-------------|---------------|
| HTTP failure | `null` / `.unknown` / `.fetch_failed` | Existing lazy fetch retries as fallback |
| JSON parse failure | Same | Same |
| Network deadline exceeded | `error.FetchFailed` | Rule skips diagnostic |
| OOM (slot allocation) | `prefetchAll` returns | Existing lazy fetch as fallback |
| Rate limit (403/429) | `rate_limited.store(true, .monotonic)` | Subsequent SC006 workers return `.fetch_failed` |

## main.zig Integration

The `main` function uses a 3-phase approach:

1. **Parse**: Workflow files parsed into `ParsedWorkflow` structs (arena heap-allocated for ArrayList stability)
2. **Prefetch**: `prefetchAll` called with extracted `[]const Workflow` slice
3. **Lint**: Dependabot files linted directly; parsed workflows linted via `lintParsedWorkflow` (all network data cached)

## Technology Choices

- **`std.Thread.Pool`**: Zig standard library, integrates with `WaitGroup` for completion tracking
- **`std.heap.ThreadSafeAllocator`**: Wraps advisory arena with mutex for safe cross-thread allocation
- **`std.atomic.Value(bool)`**: Lock-free flag for `rate_limited` state sharing
- **Max 8 threads**: GitHub API rate limit consideration (60 unauthenticated / 5000 authenticated per hour)
