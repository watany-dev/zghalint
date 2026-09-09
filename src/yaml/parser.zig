const std = @import("std");
const Tokenizer = @import("tokenizer.zig").Tokenizer;
const TokenKind = @import("tokenizer.zig").TokenKind;
const Token = @import("tokenizer.zig").Token;
const types = @import("types.zig");
const Node = types.Node;
const Scalar = types.Scalar;
const Sequence = types.Sequence;
const Mapping = types.Mapping;
const MappingEntry = types.MappingEntry;
const Span = types.Span;
const ScalarStyle = types.ScalarStyle;

pub const ParseError = error{
    UnexpectedToken,
    OutOfMemory,
    MaxDepthExceeded,
    MultipleDocuments,
    UndefinedAlias,
    AliasExpansionTooLarge,
};

/// Hard cap on nested mappings/sequences/flow containers. A well-formed
/// Actions workflow nests ~6 levels deep; 256 leaves ample headroom while
/// preventing an attacker-controlled YAML from recursing the parser into
/// a stack overflow (SIGSEGV) during CI runs.
pub const max_parse_depth: u16 = 256;

/// Total nodes an `*alias` expansion may materialise across one document.
/// Each alias is copied rather than shared so its diagnostics point at the
/// alias site, which makes the classic "billion laughs" YAML (`&b [*a, *a]`
/// repeated) grow exponentially. A real workflow expands a few hundred nodes;
/// the cap stops a hostile file from exhausting CI memory.
pub const max_alias_expansion_nodes: usize = 100_000;

/// `<<: *anchor` folds the referenced mapping's entries into the surrounding
/// mapping.
const merge_key = "<<";

pub const Parser = struct {
    allocator: std.mem.Allocator,
    tokenizer: Tokenizer,
    current: Token,
    source: []const u8,
    depth: u16,
    /// `&name` definitions seen so far. Registered only *after* the anchored
    /// node finishes parsing, so `&a [*a]` resolves to an undefined alias
    /// instead of a cycle — the parser can never build a self-referential AST.
    anchors: std.StringHashMapUnmanaged(Node),
    alias_budget: usize,
    /// Where the parse gave up, when the failure has a source position worth
    /// showing. Zig errors carry no payload, so the CLI reads it from here to
    /// print `file:line:col` instead of a bare error name.
    failure: ?Failure,
    /// End byte of the last *content* token consumed; newlines and comments
    /// leave it alone. A collection parser returns with `current` already
    /// past the trivia that follows its node (and, for a nested mapping,
    /// past the next sibling's first token), so this is the only anchor that
    /// still marks where the node's own text stopped.
    last_end: usize,
    /// Line the last content token *started* on. A block scalar starts and ends
    /// on different lines, so this deliberately marks the start: trailing junk
    /// is only ever recognised on a single-line value.
    last_start_line: u32,
    /// How many anchor definitions the parse has consumed. A sequence whose
    /// items define anchors cannot be edited by byte range: an alias far away
    /// in the file still expands to the text being removed.
    anchors_seen: usize,
    /// How many comments the parse has consumed. Only flow sequences care —
    /// their item ranges span the commas, so a comment sitting between two
    /// items falls inside one of them.
    comments_seen: usize,

    pub const Failure = struct {
        span: Span,
        /// Anchor name the alias referred to, without the `*`.
        alias: []const u8,
    };

    pub fn init(allocator: std.mem.Allocator, source: []const u8) Parser {
        var tokenizer = Tokenizer.init(source);
        const first = tokenizer.next();
        _ = first;
        const current = tokenizer.next();
        return .{
            .allocator = allocator,
            .tokenizer = tokenizer,
            .current = current,
            .source = source,
            .depth = 0,
            .anchors = .{},
            .alias_budget = max_alias_expansion_nodes,
            .failure = null,
            .last_end = 0,
            .last_start_line = 0,
            .anchors_seen = 0,
            .comments_seen = 0,
        };
    }

    pub fn parse(self: *Parser) ParseError!Node {
        // Comments may precede the document marker (a license header, a
        // lint directive), so the marker is looked for past them rather
        // than only as the very first token.
        self.skipNewlinesAndComments();
        if (self.current.kind == .document_start) {
            self.advance();
            self.skipNewlines();
        }

        const node = try self.parseNode(0);
        try self.rejectTrailingDocument();
        return node;
    }

    /// A workflow file holds exactly one YAML document; GitHub never runs a
    /// second one. Silently parsing only the first would hide the rest of the
    /// file from every rule, so any content past the first document is
    /// rejected — whether it is introduced by a `---` or, after a `...` end
    /// marker, starts bare. Trailing markers on their own hide nothing and
    /// are consumed.
    fn rejectTrailingDocument(self: *Parser) ParseError!void {
        var marker_seen = false;
        while (self.current.kind != .eof) : (self.advance()) {
            switch (self.current.kind) {
                .document_start, .document_end => marker_seen = true,
                .newline, .comment => {},
                // Malformed input (an unclosed flow collection, say) also
                // leaves tokens behind, so only a marker turns the leftovers
                // into a second document.
                else => if (marker_seen) return error.MultipleDocuments,
            }
        }
    }

    fn parseNode(self: *Parser, min_indent: u32) ParseError!Node {
        if (self.depth >= max_parse_depth) return error.MaxDepthExceeded;
        self.depth += 1;
        defer self.depth -= 1;

        self.skipNewlinesAndComments();

        if (self.current.kind == .eof) {
            return Node{ .null_value = self.spanFromToken(self.current) };
        }

        if (self.current.kind == .anchor) {
            return self.parseAnchoredNode(min_indent);
        }

        if (self.current.kind == .alias) {
            return self.resolveAlias();
        }

        if (self.current.kind == .sequence_entry) {
            return self.parseBlockSequence();
        }

        if (self.current.kind == .flow_mapping_start) {
            return self.parseFlowMapping();
        }

        if (self.current.kind == .flow_sequence_start) {
            return self.parseFlowSequence();
        }

        if (self.current.kind == .scalar) {
            const scalar_token = self.current;
            self.advance();

            if (self.current.kind == .mapping_value) {
                return self.parseBlockMapping(scalar_token, min_indent);
            }

            return Node{ .scalar = self.scalarFromToken(scalar_token) };
        }

        if (self.current.kind == .mapping_value) {
            self.advance();
            return self.parseNode(min_indent);
        }

        return Node{ .null_value = self.spanFromToken(self.current) };
    }

    /// `&name` binds the node that follows it, which may sit on the same line
    /// (`key: &a value`) or on the indented lines below (`key: &a` + a block).
    fn parseAnchoredNode(self: *Parser, min_indent: u32) ParseError!Node {
        const name = self.current.slice(self.source)[1..];
        self.advance();

        const node = if (self.current.kind == .newline or self.current.kind == .eof or self.current.kind == .comment) blk: {
            self.skipNewlinesAndComments();
            if (self.current.kind == .eof or self.current.column < min_indent) {
                break :blk Node{ .null_value = self.spanFromToken(self.current) };
            }
            break :blk try self.parseNode(min_indent);
        } else try self.parseNode(min_indent);

        // Every `*name` expands to this text, so an item cannot be removed from
        // here by byte range without silently editing those expansions too.
        const bound = switch (node) {
            .sequence => |seq| Node{ .sequence = .{ .items = seq.items, .span = seq.span } },
            else => node,
        };

        // A repeated `&name` shadows the earlier definition, as in YAML.
        self.anchors.put(self.allocator, name, bound) catch return ParseError.OutOfMemory;
        return bound;
    }

    /// Resolves `*name` to a copy of the anchored node whose spans all point at
    /// the alias token. Diagnostics then land on the line the user actually
    /// wrote rather than on the far-away anchor definition.
    fn resolveAlias(self: *Parser) ParseError!Node {
        const token = self.current;
        self.advance();

        const name = token.slice(self.source)[1..];
        const span = self.spanFromToken(token);
        const target = self.anchors.get(name) orelse {
            self.failure = .{ .span = span, .alias = name };
            return ParseError.UndefinedAlias;
        };
        return self.cloneWithSpan(target, span);
    }

    /// Expanded nodes carry no `full_span`: their text lives at the anchor, so
    /// no autofix may rewrite the source range the alias occupies.
    fn cloneWithSpan(self: *Parser, node: Node, span: Span) ParseError!Node {
        if (self.alias_budget == 0) return ParseError.AliasExpansionTooLarge;
        self.alias_budget -= 1;

        return switch (node) {
            .scalar => |s| Node{ .scalar = .{ .value = s.value, .style = s.style, .span = span } },
            .null_value => Node{ .null_value = span },
            .sequence => |seq| blk: {
                const items = self.allocator.alloc(Node, seq.items.len) catch return ParseError.OutOfMemory;
                for (seq.items, items) |src, *dst| dst.* = try self.cloneWithSpan(src, span);
                break :blk Node{ .sequence = .{ .items = items, .span = span } };
            },
            .mapping => |m| blk: {
                const entries = self.allocator.alloc(MappingEntry, m.entries.len) catch return ParseError.OutOfMemory;
                for (m.entries, entries) |src, *dst| {
                    dst.* = .{
                        .key = .{ .value = src.key.value, .style = src.key.style, .span = span },
                        .value = try self.cloneWithSpan(src.value, span),
                        .span = span,
                        .full_span = null,
                    };
                }
                break :blk Node{ .mapping = .{ .entries = entries, .span = span } };
            },
        };
    }

    /// Folds `<<:` sources into `entries`. Explicit keys win over merged ones
    /// and, among several sources, the earlier one wins — the YAML 1.1 merge
    /// rule. Returns `entries` untouched when the mapping holds no merge key,
    /// which is every mapping in a workflow that uses no anchors.
    fn applyMergeKeys(self: *Parser, entries: []MappingEntry) ParseError![]MappingEntry {
        var has_merge = false;
        for (entries) |entry| {
            if (std.mem.eql(u8, entry.key.value, merge_key)) has_merge = true;
        }
        if (!has_merge) return entries;

        var merged = std.ArrayList(MappingEntry){};
        for (entries) |entry| {
            if (std.mem.eql(u8, entry.key.value, merge_key)) continue;
            merged.append(self.allocator, entry) catch return ParseError.OutOfMemory;
        }

        for (entries) |entry| {
            if (!std.mem.eql(u8, entry.key.value, merge_key)) continue;
            switch (entry.value) {
                .mapping => |m| try self.mergeMappingInto(&merged, m),
                // `<<: [*a, *b]` merges several mappings; non-mapping items
                // are not merge sources and are ignored rather than fatal.
                .sequence => |seq| for (seq.items) |item| {
                    if (item == .mapping) try self.mergeMappingInto(&merged, item.mapping);
                },
                else => {},
            }
        }

        return merged.toOwnedSlice(self.allocator) catch ParseError.OutOfMemory;
    }

    fn mergeMappingInto(self: *Parser, merged: *std.ArrayList(MappingEntry), source: Mapping) ParseError!void {
        outer: for (source.entries) |entry| {
            for (merged.items) |existing| {
                if (std.mem.eql(u8, existing.key.value, entry.key.value)) continue :outer;
            }
            var copy = entry;
            // The entry's text lives at the merge source, not here.
            copy.full_span = null;
            merged.append(self.allocator, copy) catch return ParseError.OutOfMemory;
        }
    }

    fn parseBlockMapping(self: *Parser, first_key_token: Token, min_indent: u32) ParseError!Node {
        var entries = std.ArrayList(MappingEntry){};

        const key_indent = first_key_token.column;
        var current_key = first_key_token;

        while (true) {
            if (self.current.kind != .mapping_value) break;
            self.advance();

            // A comment ends the value line just as a newline does:
            // `key: # note` has no value, so the comment must not let the
            // next line be read as this key's value.
            const value = if (self.current.kind == .newline or self.current.kind == .eof or self.current.kind == .comment) blk: {
                self.skipNewlinesAndComments();
                if (self.current.kind == .eof) {
                    break :blk Node{ .null_value = self.spanFromToken(self.current) };
                }
                if (self.current.column > key_indent) {
                    break :blk try self.parseNode(key_indent + 1);
                }
                // YAML lets a block sequence sit at its parent key's own
                // indentation (`on:\n  schedule:\n  - cron: ...`). No sibling
                // key can start with `-`, so an entry at exactly `key_indent`
                // is this key's value rather than the end of the mapping.
                if (self.current.kind == .sequence_entry and self.current.column == key_indent) {
                    break :blk try self.parseBlockSequence();
                }
                break :blk Node{ .null_value = self.spanFromToken(self.current) };
            } else try self.parseNode(key_indent + 1);

            const key_scalar = self.scalarFromToken(current_key);
            try entries.append(self.allocator, .{
                .key = key_scalar,
                .value = value,
                .span = key_scalar.span,
                .full_span = self.blockEntryFullSpan(key_scalar, value),
            });

            // Text left over on the line the entry ended on is junk: `on: []l`
            // leaves `l` behind. Ending the mapping there dropped every key
            // written below it, so the whole rest of the file went unlintable
            // and an inserted top-level key stayed invisible (fuzz).
            self.skipTrailingLineTokens();
            self.skipNewlinesAndComments();

            if (self.current.kind == .eof) break;
            if (self.current.column < key_indent) break;
            // A line indented past the key, reached only after the entry's own
            // value was fully parsed, belongs to no node: `on: []` followed by
            // ` l` is orphan text. Ending the mapping there dropped every key
            // written below it, so the file went unlintable from that line on
            // (fuzz). Skip the line and look for the next sibling instead.
            while (self.current.kind != .eof and self.current.column > key_indent) {
                self.skipLine();
            }
            if (self.current.kind == .eof) break;
            if (self.current.column < key_indent) break;
            if (self.current.column < min_indent) break;

            if (self.current.kind == .scalar) {
                current_key = self.current;
                self.advance();
                continue;
            }

            break;
        }

        const parsed_entries = entries.toOwnedSlice(self.allocator) catch return ParseError.OutOfMemory;
        // The span is taken before merging. `applyMergeKeys` appends entries
        // whose text lives at the merge source, which sits anywhere in the file
        // -- reading the range off the merged list made a mapping written after
        // its anchor end before it began (#367). The entries parsed here are in
        // source order, so the first and last of them bound the mapping.
        const span = if (parsed_entries.len > 0)
            Span{
                .start_line = parsed_entries[0].key.span.start_line,
                .start_col = parsed_entries[0].key.span.start_col,
                .end_line = parsed_entries[parsed_entries.len - 1].span.end_line,
                .end_col = parsed_entries[parsed_entries.len - 1].span.end_col,
                .start_byte = parsed_entries[0].key.span.start_byte,
                .end_byte = parsed_entries[parsed_entries.len - 1].span.end_byte,
            }
        else
            self.spanFromToken(first_key_token);
        const owned_entries = try self.applyMergeKeys(parsed_entries);

        return Node{ .mapping = .{ .entries = owned_entries, .span = span } };
    }

    fn parseBlockSequence(self: *Parser) ParseError!Node {
        var items = std.ArrayList(Node){};
        var deletes = std.ArrayList(types.ItemDelete){};
        const seq_indent = self.current.column;
        const anchors_before = self.anchors_seen;
        // Cleared once any item's range proves untrustworthy: the sequence then
        // offers no `item_deletes` at all rather than one that cuts in the
        // wrong place.
        var deletable = true;

        while (self.current.kind == .sequence_entry and self.current.column == seq_indent) {
            const dash = self.current;
            self.advance();

            if (self.current.kind == .newline or self.current.kind == .eof or self.current.kind == .comment) {
                self.skipNewlinesAndComments();
                if (self.current.kind != .eof and self.current.column > seq_indent) {
                    try items.append(self.allocator, try self.parseNode(seq_indent + 1));
                } else {
                    try items.append(self.allocator, Node{ .null_value = self.spanFromToken(self.current) });
                }
            } else {
                try items.append(self.allocator, try self.parseNode(seq_indent + 1));
            }

            // The `- ` bullet through the end of the item's last line. A
            // comment line *between* two items stays: it introduces the one
            // that follows, so the item above must not carry it away.
            const line_start = self.lineStartByte(dash.start);
            // A nested `- - a` puts the inner bullet mid-line: taking the line
            // from its start would carry the outer bullet away with it.
            for (self.source[line_start..dash.start]) |c| {
                if (c != ' ' and c != '\t') deletable = false;
            }
            try deletes.append(self.allocator, .{
                .span = self.lineRangeSpan(line_start, self.contentLineEnd(), dash.line),
                .prev_end = line_start,
            });

            self.skipNewlinesAndComments();
        }

        // A plain scalar continued on the next line (`- foo\n  bar`) ends the
        // loop on that continuation, and the recorded range stopped at the
        // first line: removing it would leave the orphan behind.
        if (self.current.kind != .eof and self.current.column > seq_indent) deletable = false;
        if (self.anchors_seen != anchors_before) deletable = false;
        if (!deletable) deletes.clearRetainingCapacity();

        const owned_items = items.toOwnedSlice(self.allocator) catch return ParseError.OutOfMemory;
        const owned_deletes = deletes.toOwnedSlice(self.allocator) catch return ParseError.OutOfMemory;
        const span = Span.point(
            if (owned_items.len > 0) owned_items[0].getSpan().start_line else self.current.line,
            seq_indent,
            if (owned_items.len > 0) owned_items[0].getSpan().start_byte else self.current.start,
        );

        return Node{ .sequence = .{ .items = owned_items, .span = span, .item_deletes = owned_deletes } };
    }

    /// End of the line the last content token sits on, newline included. A
    /// block scalar's token already ends past its final newline, so scanning
    /// on from there would swallow the line that follows it.
    fn contentLineEnd(self: *Parser) usize {
        if (self.last_end > 0 and self.last_end <= self.source.len and self.source[self.last_end - 1] == '\n') {
            return self.last_end;
        }
        return self.scanLineEndInclusive(self.last_end);
    }

    fn lineRangeSpan(self: *Parser, start_byte: usize, end_byte_in: usize, start_line: u32) Span {
        const end_byte = @max(start_byte, @min(end_byte_in, self.source.len));
        const newlines: u32 = @intCast(std.mem.count(u8, self.source[start_byte..end_byte], "\n"));
        return .{
            .start_line = start_line,
            .start_col = 1,
            .end_line = start_line + newlines,
            .end_col = 1,
            .start_byte = start_byte,
            .end_byte = end_byte,
        };
    }

    fn parseFlowMapping(self: *Parser) ParseError!Node {
        var entries = std.ArrayList(MappingEntry){};
        const start_span = self.spanFromToken(self.current);
        self.advance();

        while (self.current.kind != .flow_mapping_end and self.current.kind != .eof) {
            self.skipNewlinesAndComments();
            if (self.current.kind == .flow_mapping_end) break;

            if (self.current.kind != .scalar) break;
            const key_token = self.current;
            self.advance();

            if (self.current.kind != .mapping_value) break;
            self.advance();

            const value = try self.parseFlowValue();

            const key_scalar = self.scalarFromToken(key_token);
            try entries.append(self.allocator, .{
                .key = key_scalar,
                .value = value,
                .span = key_scalar.span,
            });

            if (self.current.kind == .flow_entry) {
                self.advance();
            }
        }

        var close_byte: ?usize = null;
        if (self.current.kind == .flow_mapping_end) {
            self.advance();
            close_byte = self.last_end;
        }

        const parsed_entries = entries.toOwnedSlice(self.allocator) catch return ParseError.OutOfMemory;
        const owned_entries = try self.applyMergeKeys(parsed_entries);
        return Node{ .mapping = .{ .entries = owned_entries, .span = start_span, .close_byte = close_byte } };
    }

    fn parseFlowSequence(self: *Parser) ParseError!Node {
        var items = std.ArrayList(Node){};
        var extents = std.ArrayList(ItemExtent){};
        const start_span = self.spanFromToken(self.current);
        const open_line = self.current.line;
        const anchors_before = self.anchors_seen;
        const comments_before = self.comments_seen;
        self.advance();

        while (self.current.kind != .flow_sequence_end and self.current.kind != .eof) {
            self.skipNewlinesAndComments();
            if (self.current.kind == .flow_sequence_end) break;

            const before = self.current.start;
            try items.append(self.allocator, try self.parseFlowValue());
            try extents.append(self.allocator, .{ .start = before, .end = self.last_end });

            if (self.current.kind == .flow_entry) {
                self.advance();
                continue;
            }
            // `parseFlowValue` returns a null node *without* consuming a token it
            // does not understand — `[` running into block content such as
            // `[\nname: CI` leaves the `:` in place. Stop instead of spinning on
            // it forever.
            if (self.current.start == before) break;
        }

        var close_byte: ?usize = null;
        if (self.current.kind == .flow_sequence_end) {
            self.advance();
            close_byte = self.last_end;
        }

        const owned_items = items.toOwnedSlice(self.allocator) catch return ParseError.OutOfMemory;
        const owned_deletes = if (self.anchors_seen != anchors_before or self.comments_seen != comments_before)
            &[_]types.ItemDelete{}
        else
            try self.flowItemDeletes(extents.items, open_line);
        return Node{ .sequence = .{
            .items = owned_items,
            .span = start_span,
            .item_deletes = owned_deletes,
            .close_byte = close_byte,
        } };
    }

    /// Where one flow item's text starts and stops, comma excluded.
    const ItemExtent = struct {
        start: usize,
        end: usize,
    };

    /// An item takes the comma that follows it, which keeps the sequence
    /// well-formed for every item but the last — it has none. `prev_end`
    /// carries the comma *before* an item, which is what a deletion running
    /// to the end of the sequence uses instead.
    fn flowItemDeletes(self: *Parser, extents: []const ItemExtent, line: u32) ParseError![]const types.ItemDelete {
        const deletes = self.allocator.alloc(types.ItemDelete, extents.len) catch return ParseError.OutOfMemory;
        for (extents, 0..) |extent, i| {
            const is_last = i + 1 == extents.len;
            deletes[i] = .{
                .span = self.lineRangeSpan(
                    extent.start,
                    if (is_last) extent.end else extents[i + 1].start,
                    line,
                ),
                .prev_end = if (i > 0) extents[i - 1].end else extent.start,
            };
        }
        return deletes;
    }

    /// Flow collections recurse through this without passing `parseNode`, so
    /// the depth guard is applied here as well.
    fn parseFlowValue(self: *Parser) ParseError!Node {
        if (self.depth >= max_parse_depth) return error.MaxDepthExceeded;
        self.depth += 1;
        defer self.depth -= 1;

        self.skipNewlinesAndComments();

        if (self.current.kind == .anchor) {
            const name = self.current.slice(self.source)[1..];
            self.advance();
            const node = try self.parseFlowValue();
            self.anchors.put(self.allocator, name, node) catch return ParseError.OutOfMemory;
            return node;
        }
        if (self.current.kind == .alias) {
            return self.resolveAlias();
        }
        if (self.current.kind == .flow_mapping_start) {
            return self.parseFlowMapping();
        }
        if (self.current.kind == .flow_sequence_start) {
            return self.parseFlowSequence();
        }
        if (self.current.kind == .scalar) {
            const token = self.current;
            self.advance();
            return Node{ .scalar = self.scalarFromToken(token) };
        }

        return Node{ .null_value = self.spanFromToken(self.current) };
    }

    fn advance(self: *Parser) void {
        switch (self.current.kind) {
            .newline => {},
            .comment => self.comments_seen += 1,
            .anchor => {
                self.anchors_seen += 1;
                self.last_end = self.current.end;
                self.last_start_line = self.current.line;
            },
            else => {
                self.last_end = self.current.end;
                self.last_start_line = self.current.line;
            },
        }
        self.current = self.tokenizer.next();
    }

    fn skipNewlines(self: *Parser) void {
        while (self.current.kind == .newline) {
            self.advance();
        }
    }

    /// Drop whatever still sits on the line `value` ended on, so the next
    /// sibling key is read from the line below instead of being taken for the
    /// end of the mapping.
    fn skipTrailingLineTokens(self: *Parser) void {
        while (self.current.kind != .newline and
            self.current.kind != .comment and
            self.current.kind != .eof)
        {
            if (self.current.line != self.last_start_line) break;
            self.advance();
        }
    }

    /// Consume the rest of the current line, then the trivia after it.
    fn skipLine(self: *Parser) void {
        while (self.current.kind != .newline and self.current.kind != .eof) {
            self.advance();
        }
        self.skipNewlinesAndComments();
    }

    fn skipNewlinesAndComments(self: *Parser) void {
        while (self.current.kind == .newline or self.current.kind == .comment) {
            self.advance();
        }
    }

    fn spanFromToken(self: *Parser, token: Token) Span {
        _ = self;
        return .{
            .start_line = token.line,
            .start_col = token.column,
            .end_line = token.line,
            .end_col = token.column + @as(u32, @intCast(token.end - token.start)),
            .start_byte = token.start,
            .end_byte = token.end,
        };
    }

    /// True when only blanks or a comment separate the token from the end of
    /// its line, so an autofix may append `# ...` after it.
    fn tokenEndsLine(self: *Parser, token: Token) bool {
        var i = token.end;
        while (i < self.source.len and (self.source[i] == ' ' or self.source[i] == '\t')) : (i += 1) {}
        if (i >= self.source.len) return true;
        return self.source[i] == '\n' or self.source[i] == '\r' or self.source[i] == '#';
    }

    /// The `#` comment trailing the token on its own line, `#` and surrounding
    /// blanks stripped. Only a comment separated from the token by a blank is
    /// one: `a#b` is a single plain scalar in YAML, not a value and a comment.
    fn tokenLineComment(self: *Parser, token: Token) ?[]const u8 {
        // A block scalar ends at the start of the line that closes it, so what
        // follows `end` is a separate line whose comment belongs to no scalar.
        if (std.mem.indexOfScalar(u8, token.slice(self.source), '\n') != null) return null;

        var i = token.end;
        if (i >= self.source.len) return null;
        if (self.source[i] != ' ' and self.source[i] != '\t') return null;
        while (i < self.source.len and (self.source[i] == ' ' or self.source[i] == '\t')) : (i += 1) {}
        if (i >= self.source.len or self.source[i] != '#') return null;

        const start = i + 1;
        var end = start;
        while (end < self.source.len and self.source[end] != '\n' and self.source[end] != '\r') : (end += 1) {}
        const text = std.mem.trim(u8, self.source[start..end], " \t");
        return if (text.len == 0) null else text;
    }

    /// True when a quoted token never met its closing quote and so ran to the
    /// end of the file. The last byte alone does not answer it: in `"a\"` the
    /// trailing quote is escaped, and the scalar is still open.
    fn quotedIsUnterminated(raw: []const u8) bool {
        if (raw.len < 2) return true;
        if (raw[raw.len - 1] != raw[0]) return true;
        if (raw[0] != '"') return false;
        var backslashes: usize = 0;
        var i = raw.len - 1;
        while (i > 1 and raw[i - 1] == '\\') : (i -= 1) backslashes += 1;
        return backslashes % 2 == 1;
    }

    fn scalarFromToken(self: *Parser, token: Token) Scalar {
        const raw = token.slice(self.source);
        const ends_line = self.tokenEndsLine(token);
        const line_comment = self.tokenLineComment(token);
        if (raw.len >= 1 and (raw[0] == '\'' or raw[0] == '"')) {
            return .{
                .value = if (raw.len >= 2) raw[1 .. raw.len - 1] else "",
                .style = if (raw[0] == '\'') .single_quoted else .double_quoted,
                .span = self.spanFromToken(token),
                .ends_line = ends_line,
                .line_comment = line_comment,
                .unterminated = quotedIsUnterminated(raw),
            };
        }
        if (raw.len >= 1 and (raw[0] == '|' or raw[0] == '>')) {
            const style: ScalarStyle = if (raw[0] == '|') .literal else .folded;
            const content_start = if (std.mem.indexOfScalar(u8, raw, '\n')) |nl| nl + 1 else 0;
            return .{
                .value = if (content_start < raw.len) raw[content_start..] else "",
                .style = style,
                .span = self.spanFromToken(token),
                .ends_line = ends_line,
                .line_comment = line_comment,
            };
        }
        return .{
            .value = raw,
            .style = .plain,
            .span = self.spanFromToken(token),
            .ends_line = ends_line,
            .line_comment = line_comment,
        };
    }

    fn blockEntryFullSpan(self: *Parser, key: Scalar, value: Node) ?Span {
        const line_start = self.lineStartByte(key.span.start_byte);

        // The span has to remove the entry and nothing else, so it starts at
        // the line start -- which is only the entry's own if nothing but
        // indentation and sequence indicators precedes the key.
        // `b: strategy: fail-fast: false` puts three keys on one line, and
        // removing the innermost as a line took the job with it (fuzz).
        if (std.mem.indexOfNone(u8, self.source[line_start..key.span.start_byte], " \t-") != null) {
            return null;
        }

        const end_byte = self.entryEndByteInclusive(key, value) orelse return null;

        // A scalar value sits on the key's own line, so its end line / column
        // follow the value itself. Every other shape keeps the key line as the
        // end anchor.
        if (value == .scalar) {
            const newlines: u32 = @intCast(std.mem.count(u8, self.source[line_start..end_byte], "\n"));
            return .{
                .start_line = key.span.start_line,
                .start_col = 1,
                .end_line = key.span.start_line + newlines,
                .end_col = @as(u32, @intCast(end_byte - self.lineStartByte(end_byte) + 1)),
                .start_byte = line_start,
                .end_byte = end_byte,
            };
        }
        return keyLineSpan(key, line_start, end_byte);
    }

    /// Where an entry's text stops, trailing newline included. This is the
    /// entry's extent alone: whether the entry starts its own line, and so
    /// whether it can be removed as one, is `blockEntryFullSpan`'s question.
    fn entryEndByteInclusive(self: *Parser, key: Scalar, value: Node) ?usize {
        if (value == .scalar) {
            const scalar = value.scalar;
            // A quoted scalar that never closes runs to the end of the file, so
            // there is no boundary after it: text appended there becomes more
            // quoted content, and `--fix` appended the same key every round
            // (fuzz).
            if (scalar.unterminated) return null;
            // A block scalar that took content ends at the start of the line
            // that closes it, trailing newline included. Scanning on to the
            // next '\n' from there would swallow the next sibling key line.
            // One that took none ends on its own indicator, mid-line, and does
            // need the scan: anchoring an insertion at the indicator wrote the
            // new key into the middle of the `on:` line (fuzz).
            const at_line_start = scalar.span.end_byte > 0 and
                scalar.span.end_byte <= self.source.len and
                self.source[scalar.span.end_byte - 1] == '\n';
            const is_block = (scalar.style == .literal or scalar.style == .folded) and at_line_start;
            var end_byte = scalar.span.end_byte;
            if (!is_block) {
                while (end_byte < self.source.len and self.source[end_byte] != '\n') {
                    end_byte += 1;
                }
                if (end_byte < self.source.len) end_byte += 1;
            }
            return end_byte;
        }

        // An empty or null value has no body: end at the key's own line. The
        // value's span may point at a far-away token (the next sibling), so we
        // anchor on `key.span.end_byte` instead.
        const key_line_end = self.scanLineEndInclusive(key.span.end_byte);
        const nested = switch (value) {
            .scalar => unreachable,
            .null_value => key_line_end,
            .mapping => |m| if (m.entries.len == 0) self.flowCloseLineEnd(m.close_byte, key_line_end) else (self.nodeEndByteInclusive(value) orelse return null),
            .sequence => |seq| if (seq.items.len == 0) self.flowCloseLineEnd(seq.close_byte, key_line_end) else (self.nodeEndByteInclusive(value) orelse return null),
        };

        // A merge key or an alias puts an entry's text elsewhere in the file,
        // so the nested end can land before the key. The entry still owns at
        // least its own line.
        const end = @max(key_line_end, nested);
        return self.extendOverIndentedTail(end, key.span.start_col, key.span.start_byte);
    }

    /// The end of the line holding a flow collection's closing bracket. A flow
    /// collection written across lines closes below its last item, so an
    /// insertion anchored on the item's line lands inside the brackets (fuzz).
    fn flowCloseLineEnd(self: *Parser, close_byte: ?usize, fallback: usize) usize {
        const close = close_byte orelse return fallback;
        if (close > self.source.len) return fallback;
        return @max(fallback, self.scanLineEndInclusive(close));
    }

    /// Lines the parser dropped still belong to the entry when they are
    /// indented past its key: a bare `7` under `on:` holds no node, but an
    /// insertion anchored before it lands inside the block all the same.
    fn extendOverIndentedTail(self: *Parser, end_byte: usize, key_col: u32, key_start: usize) ?usize {
        if (key_col == 0) return end_byte;
        // Column arithmetic only describes a line boundary; mid-line the
        // leading run of spaces is not the line's indent.
        if (end_byte != 0 and (end_byte > self.source.len or self.source[end_byte - 1] != '\n')) return end_byte;
        const key_indent = key_col - 1;

        var end = end_byte;
        // A quote opened inside the entry is still open at `end_byte`: the
        // parser drops a token the flow parser never claimed (`push: []'`), so
        // starting the scan closed read the next line's column 0 as a boundary
        // and `--fix` wrote the new key inside the quotes (fuzz).
        var quote = self.quoteStateAt(key_start, end_byte);
        while (end < self.source.len) {
            const line_end = self.scanLineEndInclusive(end);
            var text = end;
            while (text < line_end and (self.source[text] == ' ' or self.source[text] == '\t')) text += 1;
            // Indentation says nothing while a quoted scalar is still open:
            // its closing line may sit at column 0 and still belong to the
            // block. Stopping there put an insertion inside the quotes (fuzz).
            if (quote == null) {
                // A blank line is already a safe boundary, so stop rather than
                // guess whether the block resumes after it.
                if (text >= line_end or self.source[text] == '\n' or self.source[text] == '\r') return end;
                if (text - end <= key_indent) return end;
            }
            quote = scanQuoteState(self.source[end..line_end], quote);
            end = line_end;
        }
        // A quote that never closes leaves no boundary to trust.
        return if (quote == null) end else null;
    }

    /// The quote state at `to`, starting closed at the beginning of the line
    /// holding `from`.
    fn quoteStateAt(self: *Parser, from: usize, to: usize) ?u8 {
        if (to > self.source.len) return null;
        var at = self.lineStartByte(from);
        var quote: ?u8 = null;
        while (at < to) {
            const line_end = @min(self.scanLineEndInclusive(at), to);
            quote = scanQuoteState(self.source[at..line_end], quote);
            at = line_end;
        }
        return quote;
    }

    /// Whether a quoted scalar is still open at the end of `line`, given the
    /// state at its start. A quote opens a scalar only at a token start, so an
    /// apostrophe inside a plain scalar (`don't`) is just a character.
    fn scanQuoteState(line: []const u8, state: ?u8) ?u8 {
        var open = state;
        // A line begins a token; after that only a structural character does.
        var at_token_start = true;
        var i: usize = 0;
        while (i < line.len) : (i += 1) {
            const c = line[i];
            if (open) |q| {
                if (c != q) continue;
                // `''` is one escaped quote inside a single-quoted scalar; a
                // double-quoted one uses a backslash instead.
                if (q == '\'' and i + 1 < line.len and line[i + 1] == '\'') {
                    i += 1;
                    continue;
                }
                if (q == '"') {
                    var backslashes: usize = 0;
                    while (backslashes < i and line[i - 1 - backslashes] == '\\') backslashes += 1;
                    if (backslashes % 2 == 1) continue;
                }
                open = null;
                at_token_start = false;
                continue;
            }
            const prev: u8 = if (i == 0) ' ' else line[i - 1];
            // A comment holds no scalar, so nothing in it opens one.
            if (c == '#' and (i == 0 or prev == ' ' or prev == '\t')) break;
            if (c == ' ' or c == '\t') continue;
            if ((c == '\'' or c == '"') and at_token_start) {
                open = c;
                continue;
            }
            // Whitespace alone does not start a token: in `) "x` the quote sits
            // inside the plain scalar that `)` began, and the tokenizer reads
            // the whole line as one scalar. Treating it as an opening quote
            // stretched the entry over the rest of the file, and `--fix`
            // deleted every key in between (fuzz).
            const next: u8 = if (i + 1 < line.len) line[i + 1] else ' ';
            const separates = next == ' ' or next == '\t' or next == '\n' or next == '\r';
            at_token_start = switch (c) {
                ',', '[', '{', ']', '}' => true,
                ':', '-', '?' => separates,
                else => false,
            };
        }
        return open;
    }

    /// The last byte the node's text occupies, trailing newline included.
    /// Nested values are followed to the end: a sequence whose last item is a
    /// multi-line mapping ends where that mapping's last value ends, not where
    /// its last key sits (#368).
    fn nodeEndByteInclusive(self: *Parser, node: Node) ?usize {
        return switch (node) {
            .mapping => |m| if (m.entries.len == 0)
                self.flowCloseLineEnd(m.close_byte, self.scanLineEndInclusive(m.span.end_byte))
            else blk: {
                const last = m.entries[m.entries.len - 1];
                // The entry's extent, not its removability: an inner key that
                // shares a line still ends where its value ends, and the outer
                // entry that owns the line is removable all the same (fuzz).
                const last_end = self.entryEndByteInclusive(last.key, last.value) orelse return null;
                break :blk self.flowCloseLineEnd(m.close_byte, last_end);
            },
            .sequence => |seq| if (seq.items.len == 0)
                self.flowCloseLineEnd(seq.close_byte, self.scanLineEndInclusive(seq.span.end_byte))
            else blk: {
                const last_end = self.nodeEndByteInclusive(seq.items[seq.items.len - 1]) orelse return null;
                break :blk self.flowCloseLineEnd(seq.close_byte, last_end);
            },
            // A block scalar's span already ends at the start of the line that
            // closes it; scanning on would swallow the next sibling.
            .scalar => |sc| if (sc.style == .literal or sc.style == .folded)
                sc.span.end_byte
            else
                self.scanLineEndInclusive(sc.span.end_byte),
            else => self.scanLineEndInclusive(node.getSpan().end_byte),
        };
    }

    /// The line / column pair describes the key line only; the byte range is
    /// what callers rewrite.
    fn keyLineSpan(key: Scalar, line_start: usize, end_byte: usize) Span {
        return .{
            .start_line = key.span.start_line,
            .start_col = 1,
            .end_line = key.span.start_line,
            .end_col = key.span.start_col,
            .start_byte = line_start,
            .end_byte = end_byte,
        };
    }

    fn scanLineEndInclusive(self: *Parser, start: usize) usize {
        var end = start;
        while (end < self.source.len and self.source[end] != '\n') end += 1;
        if (end < self.source.len and self.source[end] == '\n') end += 1;
        return end;
    }

    fn lineStartByte(self: *Parser, byte_offset: usize) usize {
        var start = byte_offset;
        while (start > 0 and self.source[start - 1] != '\n') {
            start -= 1;
        }
        return start;
    }
};

test "parse simple mapping" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "name: CI");
    const node = try parser.parse();
    switch (node) {
        .mapping => |m| {
            try std.testing.expectEqual(@as(usize, 1), m.entries.len);
            try std.testing.expectEqualStrings("name", m.entries[0].key.value);
            switch (m.entries[0].value) {
                .scalar => |s| try std.testing.expectEqualStrings("CI", s.value),
                else => return error.UnexpectedToken,
            }
        },
        else => return error.UnexpectedToken,
    }
}

test "parse mapping with a UTF-8 BOM prefix" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "\xEF\xBB\xBFname: CI\non: push\n");
    const node = try parser.parse();
    switch (node) {
        .mapping => |m| {
            try std.testing.expectEqual(@as(usize, 2), m.entries.len);
            try std.testing.expectEqualStrings("name", m.entries[0].key.value);
            try std.testing.expectEqual(@as(u32, 1), m.entries[0].key.span.start_line);
            try std.testing.expectEqual(@as(u32, 1), m.entries[0].key.span.start_col);
            try std.testing.expectEqualStrings("on", m.entries[1].key.value);
            try std.testing.expectEqual(@as(u32, 2), m.entries[1].key.span.start_line);
        },
        else => return error.UnexpectedToken,
    }
}

test "parse document wrapped in explicit markers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "---\nname: CI\non: push\n...\n");
    const node = try parser.parse();
    switch (node) {
        .mapping => |m| {
            try std.testing.expectEqual(@as(usize, 2), m.entries.len);
            try std.testing.expectEqualStrings("name", m.entries[0].key.value);
            // Line 1 is the marker, so the first key sits on line 2.
            try std.testing.expectEqual(@as(u32, 2), m.entries[0].key.span.start_line);
            try std.testing.expectEqualStrings("on", m.entries[1].key.value);
            try std.testing.expectEqual(@as(u32, 3), m.entries[1].key.span.start_line);
        },
        else => return error.UnexpectedToken,
    }
}

test "parse document marker preceded by comments" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "# header\n\n---\nname: CI\n");
    const node = try parser.parse();
    switch (node) {
        .mapping => |m| {
            try std.testing.expectEqual(@as(usize, 1), m.entries.len);
            try std.testing.expectEqualStrings("name", m.entries[0].key.value);
            try std.testing.expectEqual(@as(u32, 4), m.entries[0].key.span.start_line);
        },
        else => return error.UnexpectedToken,
    }
}

test "parse rejects a second document" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "name: first\n---\nname: second\n");
    try std.testing.expectError(error.MultipleDocuments, parser.parse());
}

test "parse rejects a second document after an end marker" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "---\nname: first\n...\n---\nname: second\n...\n");
    try std.testing.expectError(error.MultipleDocuments, parser.parse());
}

test "parse rejects a bare second document after an end marker" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "---\nname: first\n...\nname: second\n");
    try std.testing.expectError(error.MultipleDocuments, parser.parse());
}

test "parse accepts trailing markers with no second document" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "name: CI\n...\n---\n# trailing\n");
    const node = try parser.parse();
    switch (node) {
        .mapping => |m| try std.testing.expectEqual(@as(usize, 1), m.entries.len),
        else => return error.UnexpectedToken,
    }
}

test "parse multi-key mapping" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "name: CI\non: push");
    const node = try parser.parse();
    switch (node) {
        .mapping => |m| {
            try std.testing.expectEqual(@as(usize, 2), m.entries.len);
            try std.testing.expectEqualStrings("name", m.entries[0].key.value);
            try std.testing.expectEqualStrings("on", m.entries[1].key.value);
        },
        else => return error.UnexpectedToken,
    }
}

test "parse sequence" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "- item1\n- item2\n- item3");
    const node = try parser.parse();
    switch (node) {
        .sequence => |s| {
            try std.testing.expectEqual(@as(usize, 3), s.items.len);
        },
        else => return error.UnexpectedToken,
    }
}

test "parse nested mapping" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(),
        \\name: CI
        \\on:
        \\  push:
        \\    branches:
        \\      - main
    );
    const node = try parser.parse();
    switch (node) {
        .mapping => |m| {
            try std.testing.expectEqual(@as(usize, 2), m.entries.len);
            try std.testing.expectEqualStrings("name", m.entries[0].key.value);
            try std.testing.expectEqualStrings("on", m.entries[1].key.value);
        },
        else => return error.UnexpectedToken,
    }
}

test "parse flow mapping" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "{name: CI, on: push}");
    const node = try parser.parse();
    switch (node) {
        .mapping => |m| {
            try std.testing.expectEqual(@as(usize, 2), m.entries.len);
            try std.testing.expectEqualStrings("name", m.entries[0].key.value);
            try std.testing.expectEqualStrings("on", m.entries[1].key.value);
        },
        else => return error.UnexpectedToken,
    }
}

test "parse flow sequence" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "[main, dev, release]");
    const node = try parser.parse();
    switch (node) {
        .sequence => |s| {
            try std.testing.expectEqual(@as(usize, 3), s.items.len);
        },
        else => return error.UnexpectedToken,
    }
}

test "parse document start marker" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "---\nname: CI");
    const node = try parser.parse();
    switch (node) {
        .mapping => |m| {
            try std.testing.expectEqual(@as(usize, 1), m.entries.len);
        },
        else => return error.UnexpectedToken,
    }
}

test "parse empty input" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "");
    const node = try parser.parse();
    switch (node) {
        .null_value => {},
        else => return error.UnexpectedToken,
    }
}

test "parse quoted strings" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "name: 'hello world'");
    const node = try parser.parse();
    switch (node) {
        .mapping => |m| {
            try std.testing.expectEqual(@as(usize, 1), m.entries.len);
            switch (m.entries[0].value) {
                .scalar => |s| {
                    try std.testing.expectEqualStrings("hello world", s.value);
                    try std.testing.expectEqual(ScalarStyle.single_quoted, s.style);
                },
                else => return error.UnexpectedToken,
            }
        },
        else => return error.UnexpectedToken,
    }
}

test "parse mapping with get helper" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = Parser.init(arena.allocator(), "name: CI\non: push");
    const node = try parser.parse();
    switch (node) {
        .mapping => |m| {
            const name = m.getScalar("name");
            try std.testing.expect(name != null);
            try std.testing.expectEqualStrings("CI", name.?);
            try std.testing.expect(m.get("nonexistent") == null);
        },
        else => return error.UnexpectedToken,
    }
}

test "parse rejects input nested past max_parse_depth" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const levels = @as(usize, max_parse_depth) + 16;
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);
    for (0..levels) |i| {
        try buf.appendNTimes(std.testing.allocator, ' ', i);
        try buf.appendSlice(std.testing.allocator, "k:\n");
    }

    var parser = Parser.init(arena.allocator(), buf.items);
    try std.testing.expectError(error.MaxDepthExceeded, parser.parse());
}

test "parse rejects flow collections nested past max_parse_depth" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const levels = @as(usize, max_parse_depth) + 16;
    var buf = std.ArrayList(u8){};
    defer buf.deinit(std.testing.allocator);
    try buf.appendSlice(std.testing.allocator, "a: ");
    try buf.appendNTimes(std.testing.allocator, '[', levels);
    try buf.appendNTimes(std.testing.allocator, ']', levels);

    var parser = Parser.init(arena.allocator(), buf.items);
    try std.testing.expectError(error.MaxDepthExceeded, parser.parse());

    buf.clearRetainingCapacity();
    try buf.appendSlice(std.testing.allocator, "a: ");
    for (0..levels) |_| try buf.appendSlice(std.testing.allocator, "{k: ");
    try buf.appendNTimes(std.testing.allocator, '}', levels);

    var parser2 = Parser.init(arena.allocator(), buf.items);
    try std.testing.expectError(error.MaxDepthExceeded, parser2.parse());
}

test "parse accepts moderately nested flow collections" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var parser = Parser.init(arena.allocator(), "a: [[1, 2], {b: [3, {c: 4}]}]");
    _ = try parser.parse();
}

test "parse terminates on an unclosed flow sequence running into block content" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // The `:` after `name` starts no flow value, so the flow-sequence loop used
    // to append null nodes forever without consuming it.
    var parser = Parser.init(arena.allocator(), "[\nname: CI");
    _ = try parser.parse();
}

fn entryFullSpanText(source: []const u8, mapping: Mapping, key: []const u8) ?[]const u8 {
    for (mapping.entries) |entry| {
        if (!std.mem.eql(u8, entry.key.value, key)) continue;
        const fs = entry.full_span orelse return null;
        return source[fs.start_byte..fs.end_byte];
    }
    return null;
}

test "full_span of a block scalar entry stops before the next sibling key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source =
        \\job:
        \\  runs-on: |
        \\    ubuntu-latest
        \\  steps: []
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();
    const job = root.mapping.entries[0].value.mapping;

    try std.testing.expectEqualStrings(
        "  runs-on: |\n    ubuntu-latest\n",
        entryFullSpanText(source, job, "runs-on").?,
    );
}

test "full_span of a block scalar entry at EOF without a trailing newline" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source = "job:\n  runs-on: |\n    ubuntu-latest";
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();
    const job = root.mapping.entries[0].value.mapping;

    try std.testing.expectEqualStrings(
        "  runs-on: |\n    ubuntu-latest",
        entryFullSpanText(source, job, "runs-on").?,
    );
}

test "full_span covers a trailing line the parser held no node for (fuzz)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // The bare `7` ends the block mapping without becoming an entry. It still
    // sits under `on:`, so an insertion at the entry's end must follow it.
    const source = "on:\n    s:\n    7\njobs:\n";
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();

    try std.testing.expectEqualStrings(
        "on:\n    s:\n    7\n",
        entryFullSpanText(source, root.mapping, "on").?,
    );
}

test "full_span stops at a blank line rather than reaching past it (fuzz)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source = "on:\n  push:\n\njobs:\n  b:\n    steps: []\n";
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();

    try std.testing.expectEqualStrings(
        "on:\n  push:\n",
        entryFullSpanText(source, root.mapping, "on").?,
    );
}

test "full_span of a plain scalar entry still covers its whole line" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source = "job:\n  runs-on: ubuntu-latest\n  steps: []\n";
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();
    const job = root.mapping.entries[0].value.mapping;

    try std.testing.expectEqualStrings(
        "  runs-on: ubuntu-latest\n",
        entryFullSpanText(source, job, "runs-on").?,
    );
}

test "full_span end_line follows a multi-line quoted scalar" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source = "job:\n  name: \"a\n    b\"\n  steps: []\n";
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();
    const job = root.mapping.entries[0].value.mapping;

    // end_line points just past the consumed trailing newline, as it does for
    // a single-line entry; the value itself ends on line 3.
    const fs = job.entries[0].full_span.?;
    try std.testing.expectEqual(@as(u32, 2), fs.start_line);
    try std.testing.expectEqual(@as(u32, 4), fs.end_line);
    try std.testing.expectEqualStrings("  name: \"a\n    b\"\n", source[fs.start_byte..fs.end_byte]);
}

test "a run of comments between sequence items does not end the sequence" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source =
        \\include:
        \\  - target: a
        \\  # one
        \\  # two
        \\  # three
        \\  - target: b
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();
    const items = root.mapping.entries[0].value.sequence.items;

    try std.testing.expectEqual(@as(usize, 2), items.len);
}

test "a run of comments between mapping entries does not end the mapping" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source =
        \\job:
        \\  a: 1
        \\  # one
        \\  # two
        \\  # three
        \\  b: 2
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();
    const job = root.mapping.entries[0].value.mapping;

    try std.testing.expectEqual(@as(usize, 2), job.entries.len);
}

test "a trailing comment on an empty value does not swallow the next key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // `workflow_dispatch: # comment` has no value; without the comment the
    // key ends at the newline, and the comment must not make the following
    // top-level key look like the value instead.
    const source =
        \\on:
        \\  workflow_dispatch: # allow manual runs
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();

    try std.testing.expectEqual(@as(usize, 2), root.mapping.entries.len);
    try std.testing.expectEqualStrings("jobs", root.mapping.entries[1].key.value);
    try std.testing.expect(root.mapping.get("jobs").?.mapping.entries.len == 1);
}

test "an entry sharing its line with an outer key has no removable span (fuzz)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source = "jobs:\n b: strategy: fail-fast: false\n";
    var parser = Parser.init(arena.allocator(), source);
    const doc = try parser.parse();
    const job = doc.mapping.entries[0].value.mapping.entries[0];
    const strategy = job.value.mapping.entries[0];
    // Removing `fail-fast` as a line would take `b:` and `strategy:` with it.
    try std.testing.expect(strategy.value.mapping.entries[0].full_span == null);
    // A key that does start its own line keeps its span.
    try std.testing.expect(doc.mapping.entries[0].full_span != null);
}

test "a quoted scalar closing on an escaped quote is still open (fuzz)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // The final `"` is escaped, so the scalar runs to the end of the file and
    // the entry has no boundary after it.
    var parser = Parser.init(alloc, "on: \"push\\\"");
    const doc = try parser.parse();
    try std.testing.expect(doc.mapping.entries[0].full_span == null);

    // A backslash of its own is escaped in turn, so this one does close.
    var closed = Parser.init(alloc, "on: \"push\\\\\"\n");
    const closed_doc = try closed.parse();
    try std.testing.expect(closed_doc.mapping.entries[0].full_span != null);
}

test "a quote inside a plain scalar does not stretch the entry (fuzz)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // `) "` is one plain scalar, so the `"` opens nothing. Reading it as an
    // open quote ran the `on:` entry to the closing `"` seven lines down, and
    // removing the entry as an empty section took `jobs:` with it.
    const source = "on:\n workflow_call:\n  ) \":\njobs:\n j:\n    steps:\n    - run: \"x\"\n";
    var parser = Parser.init(alloc, source);
    const doc = try parser.parse();
    const on_span = doc.mapping.entries[0].full_span.?;
    try std.testing.expect(on_span.end_byte <= std.mem.indexOf(u8, source, "jobs:").?);
}

test "an entry ends past a quote opened after a closing bracket (fuzz)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // The `'` after `[]` opens a scalar the flow parser never claimed, and it
    // runs to the `'` on the next line. Ending the `on:` entry on its own line
    // put an insertion inside those quotes.
    const source = "on:\n push: []'\n]'\njobs:\n";
    var parser = Parser.init(alloc, source);
    const doc = try parser.parse();
    try std.testing.expectEqual(@as(usize, 18), doc.mapping.entries[0].full_span.?.end_byte);

    // A quote that never closes leaves no boundary at all.
    var open = Parser.init(alloc, "on:\n push: []'\njobs:\n");
    const open_doc = try open.parse();
    try std.testing.expect(open_doc.mapping.entries[0].full_span == null);
}

test "an entry whose quoted scalar never closes has no span (fuzz)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // The scalar runs to the end of the file, so an insertion anchored after it
    // lands inside the quotes and never parses as a key.
    const source = "jobs:\non:\n \"\n";
    var parser = Parser.init(alloc, source);
    const doc = try parser.parse();
    try std.testing.expect(doc.mapping.entries[1].full_span == null);

    // The same scalar, closed, keeps its span.
    const closed = "jobs:\non: \"x\"\n";
    var closed_parser = Parser.init(alloc, closed);
    const closed_doc = try closed_parser.parse();
    try std.testing.expectEqual(@as(usize, 14), closed_doc.mapping.entries[1].full_span.?.end_byte);
}

test "an entry's tail runs to the line closing a quoted scalar (fuzz)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // The closing `'` sits at column 0 and still belongs to `on:`; an
    // insertion stopping before it lands inside the quotes.
    const source = "on:\n e: o\n  '\n'\njobs:\n";
    var parser = Parser.init(alloc, source);
    const doc = try parser.parse();
    try std.testing.expectEqual(@as(usize, 16), doc.mapping.entries[0].full_span.?.end_byte);

    // An apostrophe inside a plain scalar opens nothing, so the tail still
    // stops at the sibling key.
    const plain = "on:\n e: don't\njobs:\n";
    var plain_parser = Parser.init(alloc, plain);
    const plain_doc = try plain_parser.parse();
    try std.testing.expectEqual(@as(usize, 14), plain_doc.mapping.entries[0].full_span.?.end_byte);
}

test "a flow collection entry ends past its closing bracket (fuzz)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // An insertion anchored on the `on:` line would land between the brackets.
    const empty_source = "on: [\n]\njobs:\n";
    var empty = Parser.init(alloc, empty_source);
    const empty_doc = try empty.parse();
    try std.testing.expectEqual(@as(usize, 8), empty_doc.mapping.entries[0].full_span.?.end_byte);

    const filled_source = "on: [\n  push\n]\njobs:\n";
    var filled = Parser.init(alloc, filled_source);
    const filled_doc = try filled.parse();
    try std.testing.expectEqual(@as(usize, 15), filled_doc.mapping.entries[0].full_span.?.end_byte);
}

test "an empty block scalar entry ends at its own line (fuzz)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source = "on: |\njobs:\n";
    var parser = Parser.init(arena.allocator(), source);
    const doc = try parser.parse();
    const entry = doc.mapping.entries[0];
    try std.testing.expectEqualStrings("on", entry.key.value);
    // The entry must not stop on the `|` itself: an insertion anchored there
    // writes the next key into the middle of the `on:` line.
    try std.testing.expectEqual(@as(usize, 6), entry.full_span.?.end_byte);
}

test "junk after a flow collection does not end the mapping (fuzz)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source =
        \\on: []l
        \\permissions: {contents: read}
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();

    try std.testing.expectEqual(@as(usize, 2), root.mapping.entries.len);
    try std.testing.expect(root.mapping.get("permissions") != null);
}

test "an orphan indented line does not end the mapping (fuzz)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source =
        \\on: []
        \\ l
        \\permissions: {contents: read}
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();

    try std.testing.expectEqual(@as(usize, 2), root.mapping.entries.len);
    try std.testing.expect(root.mapping.get("permissions") != null);
}

test "a trailing comment on an empty sequence item does not swallow the next key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source =
        \\steps:
        \\  - # nothing here
        \\name: after
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();

    try std.testing.expectEqual(@as(usize, 2), root.mapping.entries.len);
    try std.testing.expectEqualStrings("after", root.mapping.getScalar("name").?);
}

test "parse resolves an alias to the anchored scalar" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var parser = Parser.init(arena.allocator(), "a: &runner ubuntu-latest\nb: *runner\n");
    const root = try parser.parse();

    try std.testing.expectEqualStrings("ubuntu-latest", root.mapping.getScalar("a").?);
    try std.testing.expectEqualStrings("ubuntu-latest", root.mapping.getScalar("b").?);
}

test "parse points an expanded alias at the alias site, not the anchor" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var parser = Parser.init(arena.allocator(), "a: &runner ubuntu-latest\nb: *runner\n");
    const root = try parser.parse();

    // Diagnostics on `b` must name line 2, where the user wrote the alias.
    try std.testing.expectEqual(@as(u32, 2), root.mapping.get("b").?.getSpan().start_line);
    try std.testing.expectEqual(@as(u32, 1), root.mapping.get("a").?.getSpan().start_line);
}

test "parse resolves an alias to an anchored block mapping" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source =
        \\x-common: &common
        \\  runs-on: ubuntu-latest
        \\  timeout-minutes: 10
        \\copy: *common
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();
    const copy = root.mapping.get("copy").?.mapping;

    try std.testing.expectEqual(@as(usize, 2), copy.entries.len);
    try std.testing.expectEqualStrings("ubuntu-latest", copy.getScalar("runs-on").?);
    try std.testing.expectEqualStrings("10", copy.getScalar("timeout-minutes").?);
}

test "parse merges an anchored mapping through a merge key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source =
        \\x-common: &common
        \\  runs-on: ubuntu-latest
        \\  timeout-minutes: 10
        \\jobs:
        \\  build:
        \\    <<: *common
        \\    steps: []
        \\  test:
        \\    <<: *common
        \\    steps: []
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();
    const jobs = root.mapping.get("jobs").?.mapping;

    for ([_][]const u8{ "build", "test" }) |job_id| {
        const job = jobs.get(job_id).?.mapping;
        try std.testing.expect(job.get(merge_key) == null);
        try std.testing.expectEqualStrings("ubuntu-latest", job.getScalar("runs-on").?);
        try std.testing.expectEqualStrings("10", job.getScalar("timeout-minutes").?);
        try std.testing.expect(job.get("steps") != null);
    }
}

test "parse lets an explicit key override a merged one" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source =
        \\x: &common
        \\  runs-on: ubuntu-latest
        \\job:
        \\  <<: *common
        \\  runs-on: macos-latest
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();
    const job = root.mapping.get("job").?.mapping;

    try std.testing.expectEqual(@as(usize, 1), job.entries.len);
    try std.testing.expectEqualStrings("macos-latest", job.getScalar("runs-on").?);
}

test "parse merges a sequence of aliases, earliest source winning" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source =
        \\a: &a
        \\  runs-on: ubuntu-latest
        \\b: &b
        \\  runs-on: macos-latest
        \\  timeout-minutes: 5
        \\job:
        \\  <<: [*a, *b]
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();
    const job = root.mapping.get("job").?.mapping;

    try std.testing.expectEqualStrings("ubuntu-latest", job.getScalar("runs-on").?);
    try std.testing.expectEqualStrings("5", job.getScalar("timeout-minutes").?);
}

test "parse applies several merge keys in order" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source =
        \\a: &a
        \\  x: 1
        \\b: &b
        \\  x: 2
        \\  y: 3
        \\job:
        \\  <<: *a
        \\  <<: *b
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();
    const job = root.mapping.get("job").?.mapping;

    try std.testing.expectEqualStrings("1", job.getScalar("x").?);
    try std.testing.expectEqualStrings("3", job.getScalar("y").?);
}

test "parse merges an inline mapping given directly to a merge key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var parser = Parser.init(arena.allocator(), "job:\n  <<: {a: 1}\n  b: 2\n");
    const root = try parser.parse();
    const job = root.mapping.get("job").?.mapping;

    try std.testing.expectEqualStrings("1", job.getScalar("a").?);
    try std.testing.expectEqualStrings("2", job.getScalar("b").?);
}

test "parse resolves anchors and aliases inside flow collections" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var parser = Parser.init(arena.allocator(), "a: [&r ubuntu-latest, *r]\n");
    const root = try parser.parse();
    const items = root.mapping.get("a").?.sequence.items;

    try std.testing.expectEqual(@as(usize, 2), items.len);
    try std.testing.expectEqualStrings("ubuntu-latest", items[0].scalar.value);
    try std.testing.expectEqualStrings("ubuntu-latest", items[1].scalar.value);
}

test "parse resolves an alias inside a block sequence item" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source =
        \\a: &step
        \\  uses: actions/checkout@v4
        \\steps:
        \\  - *step
        \\  - run: echo hi
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();
    const steps = root.mapping.get("steps").?.sequence.items;

    try std.testing.expectEqual(@as(usize, 2), steps.len);
    try std.testing.expectEqualStrings("actions/checkout@v4", steps[0].mapping.getScalar("uses").?);
}

test "parse takes the last definition of a repeated anchor name" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var parser = Parser.init(arena.allocator(), "a: &r one\nb: &r two\nc: *r\n");
    const root = try parser.parse();

    try std.testing.expectEqualStrings("two", root.mapping.getScalar("c").?);
}

test "parse rejects an alias with no matching anchor" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var parser = Parser.init(arena.allocator(), "job:\n  <<: *missing\n");
    try std.testing.expectError(error.UndefinedAlias, parser.parse());
}

// An anchor is registered only once its node is complete, so a reference to
// itself has nothing to resolve against. That is what keeps the AST acyclic
// and the parser out of an infinite loop.
test "parse rejects a self-referential anchor instead of looping" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var parser = Parser.init(arena.allocator(), "a: &a\n  b: *a\n");
    try std.testing.expectError(error.UndefinedAlias, parser.parse());
}

test "parse rejects mutually recursive anchors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var parser = Parser.init(arena.allocator(), "a: &a\n  x: *b\nb: &b\n  y: *a\n");
    try std.testing.expectError(error.UndefinedAlias, parser.parse());
}

test "parse caps an exponentially expanding alias chain" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // The classic "billion laughs": every level doubles the previous one, so
    // 32 levels would materialise 2^32 nodes without the expansion budget.
    var source = std.ArrayList(u8){};
    defer source.deinit(std.testing.allocator);
    try source.appendSlice(std.testing.allocator, "a0: &a0 [x, x]\n");
    for (1..32) |i| {
        try source.print(std.testing.allocator, "a{d}: &a{d} [*a{d}, *a{d}]\n", .{ i, i, i - 1, i - 1 });
    }

    var parser = Parser.init(arena.allocator(), source.items);
    try std.testing.expectError(error.AliasExpansionTooLarge, parser.parse());
}

test "parse leaves a merged entry without a rewritable full_span" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // The text of `timeout-minutes` lives at the anchor, so no autofix may
    // treat the alias line as its removable range.
    var parser = Parser.init(arena.allocator(), "x: &c\n  timeout-minutes: 10\njob:\n  <<: *c\n");
    const root = try parser.parse();
    const job = root.mapping.get("job").?.mapping;

    try std.testing.expectEqual(@as(usize, 1), job.entries.len);
    try std.testing.expect(job.entries[0].full_span == null);
}

test "a comment run longer than the depth limit does not abort the parse" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // Comments used to be skipped by recursing into `parseNode`, so a run
    // longer than `max_parse_depth` exhausted the budget and the whole
    // document failed to parse.
    var source = std.ArrayList(u8){};
    defer source.deinit(std.testing.allocator);
    for (0..max_parse_depth * 2) |_| try source.appendSlice(std.testing.allocator, "# skip me\n");
    try source.appendSlice(std.testing.allocator, "name: ci\n");

    var parser = Parser.init(arena.allocator(), source.items);
    const root = try parser.parse();

    try std.testing.expectEqualStrings("ci", root.mapping.entries[0].value.scalar.value);
}

// #293: docker/* workflows write every step this way. A bare `-` used to
// tokenize as a plain scalar, so the sequence never formed.
test "parse a block sequence whose entry mapping starts on the next line" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source =
        \\steps:
        \\  -
        \\    name: Checkout
        \\    uses: actions/checkout@v4
        \\  -
        \\    run: echo build
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();
    const items = root.mapping.get("steps").?.sequence.items;

    try std.testing.expectEqual(@as(usize, 2), items.len);
    try std.testing.expectEqualStrings("Checkout", items[0].mapping.getScalar("name").?);
    try std.testing.expectEqualStrings("actions/checkout@v4", items[0].mapping.getScalar("uses").?);
    try std.testing.expectEqualStrings("echo build", items[1].mapping.getScalar("run").?);
}

test "parse a bare `-` entry with no value as null" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var parser = Parser.init(arena.allocator(), "a:\n  -\n  - x\n");
    const root = try parser.parse();
    const items = root.mapping.get("a").?.sequence.items;

    try std.testing.expectEqual(@as(usize, 2), items.len);
    try std.testing.expect(items[0] == .null_value);
    try std.testing.expectEqualStrings("x", items[1].scalar.value);
}

// #293: `- main` at column 3 belongs to `branches:`, not to the mapping that
// holds it. The value used to come back null and every later key was dropped.
test "parse a block sequence at its parent key's indentation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const source =
        \\on:
        \\  schedule:
        \\  - cron: "0 0 * * *"
        \\  push:
        \\    branches:
        \\    - main
        \\    - dev
        \\jobs: {}
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const root = try parser.parse();

    try std.testing.expect(root.mapping.get("jobs") != null);

    const on = root.mapping.get("on").?.mapping;
    const schedule = on.get("schedule").?.sequence.items;
    try std.testing.expectEqual(@as(usize, 1), schedule.len);
    try std.testing.expectEqualStrings("0 0 * * *", schedule[0].mapping.getScalar("cron").?);

    const branches = on.get("push").?.mapping.get("branches").?.sequence.items;
    try std.testing.expectEqual(@as(usize, 2), branches.len);
    try std.testing.expectEqualStrings("main", branches[0].scalar.value);
    try std.testing.expectEqualStrings("dev", branches[1].scalar.value);
}

test "parse a top-level block sequence at its key's indentation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var parser = Parser.init(arena.allocator(), "on:\n- push\n- pull_request\njobs: {}\n");
    const root = try parser.parse();

    try std.testing.expectEqual(@as(usize, 2), root.mapping.get("on").?.sequence.items.len);
    try std.testing.expect(root.mapping.get("jobs") != null);
}

test "a plain scalar starting with `-` is not a sequence entry" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var parser = Parser.init(arena.allocator(), "a: -1\nb: --verbose\nc: [-1, -2]\n");
    const root = try parser.parse();

    try std.testing.expectEqualStrings("-1", root.mapping.getScalar("a").?);
    try std.testing.expectEqualStrings("--verbose", root.mapping.getScalar("b").?);
    try std.testing.expectEqual(@as(usize, 2), root.mapping.get("c").?.sequence.items.len);
}

test "block sequence item_deletes cover each item's own lines" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\needs:
        \\  - build
        \\  - test
        \\  - build
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const node = try parser.parse();
    const seq = node.mapping.entries[0].value.sequence;

    try std.testing.expectEqual(@as(usize, 3), seq.item_deletes.len);
    try std.testing.expectEqualStrings("  - build\n", source[seq.item_deletes[0].span.start_byte..seq.item_deletes[0].span.end_byte]);
    try std.testing.expectEqualStrings("  - test\n", source[seq.item_deletes[1].span.start_byte..seq.item_deletes[1].span.end_byte]);
    try std.testing.expectEqualStrings("  - build\n", source[seq.item_deletes[2].span.start_byte..seq.item_deletes[2].span.end_byte]);
}

test "block sequence delete_span of a multi-line mapping item stops at its last line" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\steps:
        \\  - uses: actions/checkout@v4
        \\    with:
        \\      fetch-depth: 0
        \\  - run: make
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const node = try parser.parse();
    const seq = node.mapping.entries[0].value.sequence;

    try std.testing.expectEqualStrings(
        "  - uses: actions/checkout@v4\n    with:\n      fetch-depth: 0\n",
        source[seq.item_deletes[0].span.start_byte..seq.item_deletes[0].span.end_byte],
    );
    try std.testing.expectEqualStrings("  - run: make\n", source[seq.item_deletes[1].span.start_byte..seq.item_deletes[1].span.end_byte]);
}

test "block sequence delete_span keeps a comment line that introduces the next item" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\needs:
        \\  - build
        \\  # why this one matters
        \\  - test
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const node = try parser.parse();
    const seq = node.mapping.entries[0].value.sequence;

    try std.testing.expectEqualStrings("  - build\n", source[seq.item_deletes[0].span.start_byte..seq.item_deletes[0].span.end_byte]);
}

test "block sequence delete_span of an item ending in a block scalar" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\steps:
        \\  - run: |
        \\      echo hi
        \\  - run: make
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const node = try parser.parse();
    const seq = node.mapping.entries[0].value.sequence;

    try std.testing.expectEqualStrings(
        "  - run: |\n      echo hi\n",
        source[seq.item_deletes[0].span.start_byte..seq.item_deletes[0].span.end_byte],
    );
}

test "flow sequence items carry the comma after them, and the one before as prev_end" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source = "needs: [build, test, build]\n";
    var parser = Parser.init(arena.allocator(), source);
    const node = try parser.parse();
    const seq = node.mapping.entries[0].value.sequence;

    try std.testing.expectEqual(@as(usize, 3), seq.item_deletes.len);
    try std.testing.expectEqualStrings("build, ", source[seq.item_deletes[0].span.start_byte..seq.item_deletes[0].span.end_byte]);
    try std.testing.expectEqualStrings("test, ", source[seq.item_deletes[1].span.start_byte..seq.item_deletes[1].span.end_byte]);
    // The last item has no comma after it to take; `prev_end` is where the
    // comma in front of it starts, which a deletion running to the end uses.
    try std.testing.expectEqualStrings("build", source[seq.item_deletes[2].span.start_byte..seq.item_deletes[2].span.end_byte]);
    try std.testing.expectEqualStrings(", build", source[seq.item_deletes[2].prev_end..seq.item_deletes[2].span.end_byte]);
}

test "flow sequence with a single item deletes just the item" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source = "needs: [build]\n";
    var parser = Parser.init(arena.allocator(), source);
    const node = try parser.parse();
    const seq = node.mapping.entries[0].value.sequence;

    try std.testing.expectEqual(@as(usize, 1), seq.item_deletes.len);
    try std.testing.expectEqualStrings("build", source[seq.item_deletes[0].span.start_byte..seq.item_deletes[0].span.end_byte]);
}

test "alias-expanded sequence carries no item_deletes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\a: &base
        \\  - one
        \\b: *base
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const node = try parser.parse();
    const anchored = node.mapping.entries[0].value.sequence;
    const aliased = node.mapping.entries[1].value.sequence;

    try std.testing.expectEqual(@as(usize, 0), anchored.item_deletes.len);
    try std.testing.expectEqual(@as(usize, 0), aliased.item_deletes.len);
}

test "block sequence continued by a plain scalar carries no item_deletes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\needs:
        \\  - build
        \\  - a long value
        \\    continued here
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const node = try parser.parse();
    const seq = node.mapping.entries[0].value.sequence;

    try std.testing.expectEqual(@as(usize, 0), seq.item_deletes.len);
}

test "block sequence defining an anchor carries no item_deletes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\needs:
        \\  - &first build
        \\  - test
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const node = try parser.parse();
    const seq = node.mapping.entries[0].value.sequence;

    try std.testing.expectEqual(@as(usize, 0), seq.item_deletes.len);
}

test "nested block sequence sharing a line carries no item_deletes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\matrix:
        \\  - - one
        \\    - two
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const node = try parser.parse();
    const inner = node.mapping.entries[0].value.sequence.items[0].sequence;

    try std.testing.expectEqual(@as(usize, 0), inner.item_deletes.len);
}

test "flow sequence with a comment between items carries no item_deletes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\needs: [
        \\  build, # first
        \\  test,
        \\]
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const node = try parser.parse();
    const seq = node.mapping.entries[0].value.sequence;

    try std.testing.expectEqual(@as(usize, 0), seq.item_deletes.len);
}

test "flow sequence defining an anchor carries no item_deletes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source = "needs: [&first build, test]\n";
    var parser = Parser.init(arena.allocator(), source);
    const node = try parser.parse();
    const seq = node.mapping.entries[0].value.sequence;

    try std.testing.expectEqual(@as(usize, 0), seq.item_deletes.len);
}

test "merge key leaves the mapping span covering its own text" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\anchor: &common
        \\  runs-on: ubuntu-latest
        \\job:
        \\  <<: *common
        \\  steps: []
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const node = try parser.parse();
    const job = node.mapping.entries[1].value.mapping;

    try std.testing.expect(job.span.start_byte <= job.span.end_byte);
    try std.testing.expectEqual(@as(u32, 4), job.span.start_line);
    try std.testing.expectEqual(@as(u32, 5), job.span.end_line);
}

test "full_span of a sequence covers the nested value of its last item" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\on:
        \\  schedule:
        \\    - cron: "0 0 * * *"
        \\      extra:
        \\        - a
        \\        - b
        \\jobs: {}
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const node = try parser.parse();
    const on_entry = node.mapping.entries[0];
    const full = on_entry.full_span orelse return error.TestExpectedNonNull;

    try std.testing.expectEqualStrings(
        \\on:
        \\  schedule:
        \\    - cron: "0 0 * * *"
        \\      extra:
        \\        - a
        \\        - b
        \\
    , source[full.start_byte..full.end_byte]);
}

test "trailing comment on a scalar is captured without the '#'" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\uses: owner/action@abc  #  v1.2.3
        \\name: plain
        \\quoted: "value" # note
        \\hash: a#b
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const node = try parser.parse();

    try std.testing.expectEqualStrings("v1.2.3", node.mapping.get("uses").?.scalar.line_comment.?);
    try std.testing.expect(node.mapping.get("name").?.scalar.line_comment == null);
    try std.testing.expectEqualStrings("note", node.mapping.get("quoted").?.scalar.line_comment.?);
    // A `#` not preceded by a blank starts no comment in YAML, so nothing is
    // reported for it even though the tokenizer ends the scalar there.
    try std.testing.expect(node.mapping.get("hash").?.scalar.line_comment == null);
}

test "a block scalar takes no comment from the line that closes it" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const source =
        \\folded: >-
        \\    owner/action@abc1234
        \\# v1.0.0
        \\empty: value #
        \\
    ;
    var parser = Parser.init(arena.allocator(), source);
    const node = try parser.parse();

    try std.testing.expect(node.mapping.get("folded").?.scalar.line_comment == null);
    // A `#` with nothing after it is no more a comment than a missing one.
    try std.testing.expect(node.mapping.get("empty").?.scalar.line_comment == null);
}
