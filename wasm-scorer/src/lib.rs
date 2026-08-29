#![cfg_attr(target_arch = "wasm32", no_std)]

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

const HEAP_SIZE: usize = 2 * 1024 * 1024;
const MAX_TOKENS: usize = 384;
const MAX_SCAN_BYTES: usize = 131_072;
const MAX_IDENTIFIERS: usize = 16;

static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
static mut HEAP_OFFSET: usize = 0;

#[cold]
fn allocation_failure() -> ! {
    #[cfg(target_arch = "wasm32")]
    core::arch::wasm32::unreachable();

    #[cfg(not(target_arch = "wasm32"))]
    panic!("WASM input arena exhausted");
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn alloc(size: i32) -> i32 {
    let size = size.max(0) as usize;
    unsafe {
        let aligned = (HEAP_OFFSET + 7) & !7;
        let end = aligned
            .checked_add(size)
            .unwrap_or_else(|| allocation_failure());
        if end > HEAP_SIZE {
            allocation_failure();
        }
        HEAP_OFFSET = end;
        core::ptr::addr_of_mut!(HEAP).cast::<u8>().add(aligned) as i32
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dealloc(_ptr: i32, _size: i32) {}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Verdict {
    None,
    Safe,
    Unsafe,
    Uncertain,
}

#[derive(Clone, Copy)]
struct Token {
    hash: u64,
    weight: u8,
    kind: u8,
    confirmation: i8,
    agreement: i8,
    boundary_before: bool,
    proper: bool,
}

const EMPTY_TOKEN: Token = Token {
    hash: 0,
    weight: 0,
    kind: 0,
    confirmation: 0,
    agreement: 0,
    boundary_before: false,
    proper: false,
};

const KIND_NEGATION: u8 = 1;
const KIND_TRUE: u8 = 2;
const KIND_FALSE: u8 = 3;
const KIND_SAFE: u8 = 4;
const KIND_UNSAFE: u8 = 5;
const KIND_UNCERTAIN: u8 = 6;
const KIND_LOW: u8 = 7;
const KIND_HIGH: u8 = 8;
const KIND_ZERO: u8 = 9;
const KIND_ONE: u8 = 10;
const KIND_COUNT: u8 = 11;

struct Tokens {
    values: [Token; MAX_TOKENS],
    len: usize,
    truncated: bool,
}

impl Tokens {
    fn new() -> Self {
        Self {
            values: [EMPTY_TOKEN; MAX_TOKENS],
            len: 0,
            truncated: false,
        }
    }

    fn contains(&self, hash: u64) -> bool {
        self.values[..self.len]
            .iter()
            .any(|token| token.hash == hash)
    }
}

fn is_ascii_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

fn is_numeric_separator(input: &[u8], index: usize, limit: usize) -> bool {
    index > 0
        && index + 1 < limit
        && (input[index] == b'.' || input[index] == b',')
        && input[index - 1].is_ascii_digit()
        && input[index + 1].is_ascii_digit()
}

fn ascii_lower(byte: u8) -> u8 {
    if byte.is_ascii_uppercase() {
        byte + 32
    } else {
        byte
    }
}

fn token_eq(token: &[u8], expected: &[u8]) -> bool {
    token.len() == expected.len()
        && token
            .iter()
            .zip(expected)
            .all(|(left, right)| ascii_lower(*left) == *right)
}

fn token_hash(token: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in token {
        hash ^= ascii_lower(*byte) as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn is_stop_word(token: &[u8]) -> bool {
    const WORDS: [&[u8]; 32] = [
        b"a",
        b"an",
        b"and",
        b"are",
        b"as",
        b"at",
        b"be",
        b"by",
        b"for",
        b"from",
        b"has",
        b"have",
        b"in",
        b"is",
        b"it",
        b"its",
        b"of",
        b"on",
        b"or",
        b"that",
        b"the",
        b"this",
        b"to",
        b"was",
        b"were",
        b"will",
        b"with",
        b"url",
        b"website",
        b"result",
        b"reason",
        b"confidence",
    ];
    WORDS.iter().any(|word| token_eq(token, word))
}

fn token_kind(token: &[u8]) -> u8 {
    if [
        b"not".as_slice(),
        b"no",
        b"non",
        b"never",
        b"none",
        b"nothing",
        b"rather",
        b"without",
    ]
    .iter()
    .any(|word| token_eq(token, word))
    {
        return KIND_NEGATION;
    }
    if token_eq(token, b"true") || token_eq(token, b"yes") {
        return KIND_TRUE;
    }
    if token_eq(token, b"false") {
        return KIND_FALSE;
    }
    if token_eq(token, b"0") {
        return KIND_ZERO;
    }
    if token_eq(token, b"1") {
        return KIND_ONE;
    }
    if token
        .iter()
        .all(|byte| byte.is_ascii_digit() || *byte == b'.' || *byte == b',')
    {
        return KIND_COUNT;
    }
    if [
        b"safe".as_slice(),
        b"clean",
        b"benign",
        b"harmless",
        b"legitimate",
        b"trusted",
        b"secure",
        b"valid",
        b"legit",
        b"good",
        b"normal",
        b"public",
        b"routable",
        b"external",
        b"okay",
        b"ok",
        b"negative",
        b"negative-detection",
        b"passed",
        b"clear",
        b"allow",
        b"allowed",
    ]
    .iter()
    .any(|word| token_eq(token, word))
    {
        return KIND_SAFE;
    }
    if [
        b"malicious".as_slice(),
        b"malware",
        b"phishing",
        b"unsafe",
        b"harmful",
        b"fraudulent",
        b"fraud",
        b"phish",
        b"blacklist",
        b"blacklisted",
        b"infected",
        b"compromised",
        b"dangerous",
        b"risky",
        b"bad",
        b"private",
        b"internal",
        b"localhost",
        b"loopback",
        b"reserved",
        b"positive",
        b"invalid",
        b"risk",
        b"block",
        b"blocked",
        b"threat",
        b"threats",
    ]
    .iter()
    .any(|word| token_eq(token, word))
    {
        return KIND_UNSAFE;
    }
    if [
        b"suspicious".as_slice(),
        b"unknown",
        b"pending",
        b"warn",
        b"uncertain",
        b"unverified",
        b"inconclusive",
        b"indeterminate",
        b"unavailable",
        b"unresolved",
        b"undetermined",
        b"processing",
        b"inaccessible",
        b"unreachable",
        b"failed",
        b"fails",
        b"timed",
        b"timeout",
        b"error",
    ]
    .iter()
    .any(|word| token_eq(token, word))
    {
        return KIND_UNCERTAIN;
    }
    if [b"low".as_slice(), b"minimal", b"negligible", b"none"]
        .iter()
        .any(|word| token_eq(token, word))
    {
        return KIND_LOW;
    }
    if [b"high".as_slice(), b"severe", b"critical", b"elevated"]
        .iter()
        .any(|word| token_eq(token, word))
    {
        return KIND_HIGH;
    }
    0
}

fn confirmation_kind(token: &[u8]) -> i8 {
    if [
        b"verified".as_slice(),
        b"confirmed",
        b"listed",
        b"present",
        b"found",
        b"matched",
        b"matches",
        b"detected",
        b"resolved",
        b"complete",
        b"completed",
        b"active",
        b"online",
        b"exists",
        b"record",
        b"records",
    ]
    .iter()
    .any(|word| token_eq(token, word))
    {
        return 1;
    }
    if [
        b"unverified".as_slice(),
        b"unconfirmed",
        b"unlisted",
        b"absent",
        b"missing",
        b"offline",
        b"dropped",
        b"removed",
        b"nothing",
        b"pending",
    ]
    .iter()
    .any(|word| token_eq(token, word))
    {
        return -1;
    }
    0
}

fn agreement_kind(token: &[u8]) -> i8 {
    if [b"agree".as_slice(), b"agrees", b"agreement", b"unanimous"]
        .iter()
        .any(|word| token_eq(token, word))
    {
        return 1;
    }
    if [
        b"disagree".as_slice(),
        b"disagrees",
        b"disagreement",
        b"conflict",
        b"conflicting",
        b"mixed",
    ]
    .iter()
    .any(|word| token_eq(token, word))
    {
        return -1;
    }
    0
}

fn token_weight(token: &[u8], kind: u8) -> u8 {
    if kind == KIND_SAFE || kind == KIND_UNSAFE || kind == KIND_UNCERTAIN {
        return 12;
    }
    if token.iter().any(u8::is_ascii_digit) {
        return 9;
    }
    if is_stop_word(token) {
        return 0;
    }
    match token.len() {
        0..=2 => 1,
        3..=4 => 2,
        5..=7 => 3,
        _ => 4,
    }
}

fn is_identifier_delimiter(byte: u8) -> bool {
    byte.is_ascii_whitespace()
        || matches!(
            byte,
            b'"' | b'\'' | b'(' | b')' | b'[' | b']' | b'{' | b'}' | b'<' | b'>' | b',' | b';'
        )
}

fn token_in_identifier(input: &[u8], token_start: usize, limit: usize) -> bool {
    let mut start = token_start;
    while start > 0 && !is_identifier_delimiter(input[start - 1]) {
        start -= 1;
    }
    let mut end = token_start;
    while end < limit && !is_identifier_delimiter(input[end]) {
        end += 1;
    }
    let span = &input[start..end];
    if starts_with_ascii(span, 0, b"http://") || starts_with_ascii(span, 0, b"https://") {
        return true;
    }

    let host_end = span
        .iter()
        .position(|byte| matches!(byte, b'/' | b'?' | b'#' | b':'))
        .unwrap_or(span.len());
    let mut trimmed_end = host_end;
    while trimmed_end > 0 && matches!(span[trimmed_end - 1], b'.' | b'!' | b'-' | b'_') {
        trimmed_end -= 1;
    }
    let host = &span[..trimmed_end];
    let dots = host.iter().filter(|byte| **byte == b'.').count();
    let suffix_is_domain = host
        .iter()
        .rposition(|byte| *byte == b'.')
        .is_some_and(|dot| {
            host.len().saturating_sub(dot + 1) >= 2
                && host[dot + 1..].iter().all(u8::is_ascii_alphabetic)
        });
    let ipv4_like = dots == 3
        && host
            .iter()
            .all(|byte| byte.is_ascii_digit() || *byte == b'.');
    suffix_is_domain || ipv4_like
}

fn tokenize(input: &[u8]) -> Tokens {
    let mut tokens = Tokens::new();
    let limit = input.len().min(MAX_SCAN_BYTES);
    let mut cursor = 0;
    while cursor < limit {
        let mut boundary_before = false;
        while cursor < limit && !is_ascii_word(input[cursor]) {
            if matches!(input[cursor], b'.' | b',' | b';' | b'!' | b'?')
                && !is_numeric_separator(input, cursor, limit)
            {
                boundary_before = true;
            }
            cursor += 1;
        }
        let start = cursor;
        while cursor < limit
            && (is_ascii_word(input[cursor]) || is_numeric_separator(input, cursor, limit))
        {
            cursor += 1;
        }
        if start == cursor {
            continue;
        }
        if tokens.len == MAX_TOKENS {
            tokens.truncated = true;
            break;
        }
        let raw = &input[start..cursor];
        let kind = if token_in_identifier(input, start, limit) {
            0
        } else {
            token_kind(raw)
        };
        tokens.values[tokens.len] = Token {
            hash: token_hash(raw),
            weight: token_weight(raw, kind),
            kind,
            confirmation: confirmation_kind(raw),
            agreement: agreement_kind(raw),
            boundary_before,
            proper: tokens.len > 0 && !boundary_before && raw[0].is_ascii_uppercase(),
        };
        tokens.len += 1;
    }
    tokens.truncated |= input.len() > limit;
    tokens
}

fn token_is(tokens: &Tokens, index: usize, expected: &[u8]) -> bool {
    tokens
        .values
        .get(index)
        .is_some_and(|token| token.hash == token_hash(expected))
}

fn negated_at(tokens: &Tokens, index: usize) -> bool {
    let mut cursor = index;
    let mut distance = 0;
    while cursor > 0 && distance < 4 {
        if tokens.values[cursor].boundary_before {
            break;
        }
        cursor -= 1;
        distance += 1;
        if matches!(
            tokens.values[cursor].kind,
            KIND_NEGATION | KIND_FALSE | KIND_ZERO
        ) {
            return true;
        }
    }
    false
}

fn denied_after(tokens: &Tokens, index: usize) -> bool {
    let Some(next_token) = tokens.values.get(index + 1) else {
        return false;
    };
    if next_token.boundary_before {
        return false;
    }
    let next = next_token.kind;
    if matches!(next, KIND_FALSE | KIND_ZERO) {
        return true;
    }
    let Some(next_two_token) = tokens.values.get(index + 2) else {
        return false;
    };
    if next_two_token.boundary_before {
        return false;
    }
    let next_two = next_two_token.kind;
    matches!(next_two, KIND_FALSE | KIND_ZERO)
        && (token_is(tokens, index + 1, b"is") || token_is(tokens, index + 1, b"equals"))
}

fn signed_axis(tokens: &Tokens, select: fn(&Token) -> i8) -> i8 {
    let mut positive = 0u16;
    let mut negative = 0u16;
    for index in 0..tokens.len {
        let value = select(&tokens.values[index]);
        if value == 0 {
            continue;
        }
        let value = if negated_at(tokens, index) || denied_after(tokens, index) {
            -value
        } else {
            value
        };
        if value > 0 {
            positive += 1;
        } else {
            negative += 1;
        }
    }
    positive.cmp(&negative) as i8
}

fn is_numeric(token: &Token) -> bool {
    matches!(token.kind, KIND_ZERO | KIND_ONE | KIND_COUNT)
}

fn numeric_label(tokens: &Tokens, index: usize) -> u8 {
    for distance in 1..=4 {
        if let Some(token) = tokens.values.get(index + distance)
            && matches!(token.kind, KIND_SAFE | KIND_UNSAFE | KIND_UNCERTAIN)
        {
            return token.kind;
        }
    }
    for distance in 1..=4 {
        if let Some(previous) = index.checked_sub(distance) {
            let token = tokens.values[previous];
            if matches!(token.kind, KIND_SAFE | KIND_UNSAFE | KIND_UNCERTAIN) {
                return token.kind;
            }
        }
    }
    0
}

fn is_metadata_number(tokens: &Tokens, index: usize) -> bool {
    index > 0
        && [b"sha".as_slice(), b"md", b"http", b"tls", b"version"]
            .iter()
            .any(|word| token_is(tokens, index - 1, word))
}

fn numeric_conflict(question: &Tokens, ground_truth: &Tokens, answer: &Tokens) -> bool {
    for answer_index in 0..answer.len {
        let answer_token = answer.values[answer_index];
        if !is_numeric(&answer_token)
            || question.contains(answer_token.hash)
            || is_metadata_number(answer, answer_index)
        {
            continue;
        }
        if answer_index > 0
            && matches!(
                answer.values[answer_index - 1].kind,
                KIND_SAFE | KIND_UNSAFE | KIND_UNCERTAIN
            )
        {
            continue;
        }
        let mut matched_value = false;
        let mut matched_slot = false;
        for truth_index in 0..ground_truth.len {
            let truth_token = ground_truth.values[truth_index];
            if !is_numeric(&truth_token) || truth_token.hash != answer_token.hash {
                continue;
            }
            matched_value = true;
            let truth_label = numeric_label(ground_truth, truth_index);
            let answer_label = numeric_label(answer, answer_index);
            if truth_label == 0 || answer_label == 0 || truth_label == answer_label {
                matched_slot = true;
            }
        }
        if !matched_value || !matched_slot {
            return true;
        }
    }
    false
}

struct Identifiers {
    values: [u64; MAX_IDENTIFIERS],
    len: usize,
}

impl Identifiers {
    fn new() -> Self {
        Self {
            values: [0; MAX_IDENTIFIERS],
            len: 0,
        }
    }

    fn push(&mut self, value: u64) {
        if value != 0 && self.len < MAX_IDENTIFIERS && !self.contains(value) {
            self.values[self.len] = value;
            self.len += 1;
        }
    }

    fn contains(&self, value: u64) -> bool {
        self.values[..self.len].contains(&value)
    }
}

fn starts_with_ascii(input: &[u8], start: usize, expected: &[u8]) -> bool {
    start + expected.len() <= input.len()
        && input[start..start + expected.len()]
            .iter()
            .zip(expected)
            .all(|(left, right)| ascii_lower(*left) == *right)
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'.' | b'-' | b'_' | b'/' | b':' | b'?' | b'=' | b'&' | b'%' | b'#'
        )
}

fn push_url_identifiers(input: &[u8], start: usize, end: usize, output: &mut Identifiers) {
    let mut trimmed_end = end;
    while trimmed_end > start
        && matches!(
            input[trimmed_end - 1],
            b'.' | b',' | b';' | b':' | b'!' | b'?'
        )
    {
        trimmed_end -= 1;
    }
    if trimmed_end <= start {
        return;
    }
    output.push(token_hash(&input[start..trimmed_end]));
    let host_end = input[start..trimmed_end]
        .iter()
        .position(|byte| matches!(byte, b'/' | b'?' | b'#'))
        .map(|offset| start + offset)
        .unwrap_or(trimmed_end);
    if host_end > start {
        output.push(token_hash(&input[start..host_end]));
    }
}

fn extract_identifiers(input: &[u8]) -> Identifiers {
    let mut output = Identifiers::new();
    let limit = input.len().min(MAX_SCAN_BYTES);
    let mut cursor = 0;
    while cursor < limit {
        let scheme = if starts_with_ascii(input, cursor, b"https://") {
            8
        } else if starts_with_ascii(input, cursor, b"http://") {
            7
        } else {
            0
        };
        if scheme > 0 {
            let start = cursor + scheme;
            let mut end = start;
            while end < limit && is_identifier_byte(input[end]) {
                end += 1;
            }
            push_url_identifiers(input, start, end, &mut output);
            cursor = end;
            continue;
        }

        if input[cursor].is_ascii_alphanumeric() {
            let start = cursor;
            while cursor < limit
                && (input[cursor].is_ascii_alphanumeric()
                    || matches!(input[cursor], b'.' | b'-' | b'_'))
            {
                cursor += 1;
            }
            let mut end = cursor;
            while end > start && matches!(input[end - 1], b'.' | b'-' | b'_') {
                end -= 1;
            }
            let span = &input[start..end];
            let dots = span.iter().filter(|byte| **byte == b'.').count();
            let all_hex = span.iter().all(u8::is_ascii_hexdigit);
            let suffix_is_domain = span
                .iter()
                .rposition(|byte| *byte == b'.')
                .is_some_and(|dot| {
                    span.len().saturating_sub(dot + 1) >= 2
                        && span[dot + 1..].iter().all(u8::is_ascii_alphabetic)
                });
            let ipv4_like = dots == 3
                && span
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || *byte == b'.');
            let domain_like = suffix_is_domain || ipv4_like;
            let hash_like = all_hex && span.len() >= 16;
            if domain_like || hash_like {
                output.push(token_hash(span));
            }
            continue;
        }
        cursor += 1;
    }
    output
}

fn identifier_conflict(question: &[u8], ground_truth: &[u8], answer: &[u8]) -> bool {
    let question_ids = extract_identifiers(question);
    let truth_ids = extract_identifiers(ground_truth);
    let answer_ids = extract_identifiers(answer);
    answer_ids.values[..answer_ids.len]
        .iter()
        .any(|value| !question_ids.contains(*value) && !truth_ids.contains(*value))
}

fn entity_conflict(question: &Tokens, ground_truth: &Tokens, answer: &Tokens) -> bool {
    fn metadata_entity(hash: u64) -> bool {
        [
            b"sha".as_slice(),
            b"http",
            b"https",
            b"tls",
            b"url",
            b"json",
        ]
        .iter()
        .any(|word| hash == token_hash(word))
    }

    let truth_has_entity = ground_truth.values[..ground_truth.len].iter().any(|token| {
        token.proper
            && token.weight > 1
            && !metadata_entity(token.hash)
            && !question.contains(token.hash)
    });
    truth_has_entity
        && answer.values[..answer.len].iter().any(|token| {
            token.proper
                && token.weight > 1
                && !metadata_entity(token.hash)
                && !question.contains(token.hash)
                && !ground_truth.contains(token.hash)
        })
}

fn mixed_verdict(tokens: &Tokens) -> bool {
    let mut safe = false;
    let mut unsafe_value = false;
    for index in 0..tokens.len {
        let token = tokens.values[index];
        if !matches!(token.kind, KIND_SAFE | KIND_UNSAFE) {
            continue;
        }
        let numeric_slot = index > 0 && is_numeric(&tokens.values[index - 1]);
        if numeric_slot {
            continue;
        }
        let negated = negated_at(tokens, index) || denied_after(tokens, index);
        match (token.kind, negated) {
            (KIND_SAFE, false) | (KIND_UNSAFE, true) => safe = true,
            (KIND_UNSAFE, false) | (KIND_SAFE, true) => unsafe_value = true,
            _ => {}
        }
    }
    safe && unsafe_value
}

fn significant_tokens_equal(left: &Tokens, right: &Tokens) -> bool {
    let mut left_index = 0;
    let mut right_index = 0;
    loop {
        while left_index < left.len && left.values[left_index].weight == 0 {
            left_index += 1;
        }
        while right_index < right.len && right.values[right_index].weight == 0 {
            right_index += 1;
        }
        if left_index == left.len || right_index == right.len {
            return left_index == left.len && right_index == right.len;
        }
        if left.values[left_index].hash != right.values[right_index].hash {
            return false;
        }
        left_index += 1;
        right_index += 1;
    }
}

fn verdict(question: &Tokens, tokens: &Tokens) -> Verdict {
    let mut safe = 0u16;
    let mut unsafe_score = 0u16;
    let mut uncertain = 0u16;
    let mut has_yes = false;
    let mut has_no = false;
    for index in 0..tokens.len {
        let current = tokens.values[index].kind;
        let previous = index
            .checked_sub(1)
            .map(|value| tokens.values[value].kind)
            .unwrap_or(0);
        let next = tokens
            .values
            .get(index + 1)
            .map(|token| token.kind)
            .unwrap_or(0);
        let next_two = tokens
            .values
            .get(index + 2)
            .map(|token| token.kind)
            .unwrap_or(0);
        let negated = negated_at(tokens, index)
            || denied_after(tokens, index)
            || (current == KIND_UNSAFE
                && (previous == KIND_LOW || next == KIND_LOW || next_two == KIND_LOW));
        match current {
            KIND_SAFE if negated => unsafe_score += 2,
            KIND_SAFE if next == KIND_COUNT || next_two == KIND_COUNT => safe += 1,
            KIND_SAFE => safe += 2,
            KIND_UNSAFE if negated => safe += 2,
            KIND_UNSAFE if next == KIND_COUNT || next_two == KIND_COUNT => unsafe_score += 4,
            KIND_UNSAFE => unsafe_score += 2,
            KIND_UNCERTAIN if negated => safe += 2,
            KIND_UNCERTAIN => uncertain += 2,
            KIND_TRUE | KIND_ONE => has_yes = true,
            KIND_FALSE | KIND_ZERO | KIND_NEGATION => has_no = true,
            _ => {}
        }
    }
    if uncertain > 0 && uncertain >= safe && uncertain >= unsafe_score {
        Verdict::Uncertain
    } else if safe > unsafe_score && safe > uncertain {
        Verdict::Safe
    } else if unsafe_score > safe && unsafe_score > uncertain {
        Verdict::Unsafe
    } else if safe > 0 || unsafe_score > 0 || uncertain > 0 {
        Verdict::Uncertain
    } else {
        let mut question_safe = 0u16;
        let mut question_unsafe = 0u16;
        for token in &question.values[..question.len] {
            match token.kind {
                KIND_SAFE => question_safe += 1,
                KIND_UNSAFE => question_unsafe += 1,
                _ => {}
            }
        }
        let asked = if question_unsafe > question_safe {
            Verdict::Unsafe
        } else if question_safe > question_unsafe {
            Verdict::Safe
        } else {
            Verdict::None
        };
        if asked == Verdict::None || has_yes == has_no {
            Verdict::None
        } else if has_yes {
            asked
        } else if asked == Verdict::Safe {
            Verdict::Unsafe
        } else {
            Verdict::Safe
        }
    }
}

fn overlap(question: &Tokens, ground_truth: &Tokens, answer: &Tokens) -> f32 {
    let mut recall_total = 0u32;
    let mut recall_match = 0u32;
    for token in &ground_truth.values[..ground_truth.len] {
        if token.weight == 0 {
            continue;
        }
        let weight = if question.contains(token.hash) {
            1
        } else {
            token.weight as u32
        };
        recall_total += weight;
        if answer.contains(token.hash) {
            recall_match += weight;
        }
    }

    let mut precision_total = 0u32;
    let mut precision_match = 0u32;
    for token in &answer.values[..answer.len] {
        if token.weight == 0 || question.contains(token.hash) {
            continue;
        }
        precision_total += token.weight as u32;
        if ground_truth.contains(token.hash) {
            precision_match += token.weight as u32;
        }
    }

    let recall = if recall_total == 0 {
        0.0
    } else {
        recall_match as f32 / recall_total as f32
    };
    let precision = if precision_total == 0 {
        0.0
    } else {
        precision_match as f32 / precision_total as f32
    };
    0.68 * recall + 0.32 * precision
}

fn smoothstep(value: f32) -> f32 {
    let bounded = value.clamp(0.0, 1.0);
    bounded * bounded * (3.0 - 2.0 * bounded)
}

fn score_bytes(question: &[u8], ground_truth: &[u8], answer: &[u8]) -> f32 {
    if answer.iter().all(|byte| byte.is_ascii_whitespace()) {
        return 0.0;
    }

    let question_tokens = tokenize(question);
    let ground_truth_tokens = tokenize(ground_truth);
    let answer_tokens = tokenize(answer);
    if answer_tokens.len == 0 {
        return 0.0;
    }
    if significant_tokens_equal(&ground_truth_tokens, &answer_tokens) {
        return 1.0;
    }

    let expected_verdict = verdict(&question_tokens, &ground_truth_tokens);
    let answer_verdict = verdict(&question_tokens, &answer_tokens);
    let expected_confirmation = signed_axis(&ground_truth_tokens, |token| token.confirmation);
    let answer_confirmation = signed_axis(&answer_tokens, |token| token.confirmation);
    let expected_agreement = signed_axis(&ground_truth_tokens, |token| token.agreement);
    let answer_agreement = signed_axis(&answer_tokens, |token| token.agreement);
    let mut score = overlap(&question_tokens, &ground_truth_tokens, &answer_tokens);

    if numeric_conflict(&question_tokens, &ground_truth_tokens, &answer_tokens)
        || identifier_conflict(question, ground_truth, answer)
        || entity_conflict(&question_tokens, &ground_truth_tokens, &answer_tokens)
        || (expected_confirmation != 0
            && answer_confirmation != 0
            && expected_confirmation != answer_confirmation)
        || (expected_agreement != 0
            && answer_agreement != 0
            && expected_agreement != answer_agreement)
    {
        return 0.0;
    }
    if mixed_verdict(&answer_tokens) && !mixed_verdict(&ground_truth_tokens) {
        return 0.05 * smoothstep(score);
    }

    if expected_verdict != Verdict::None && answer_verdict != Verdict::None {
        if expected_verdict == answer_verdict {
            score = 1.0;
        } else {
            score = 0.0;
        }
        return score;
    }
    if (expected_confirmation != 0 && expected_confirmation == answer_confirmation)
        || (expected_agreement != 0 && expected_agreement == answer_agreement)
    {
        return 1.0;
    }

    if answer_tokens.truncated {
        score *= 0.92;
    }
    smoothstep(score).clamp(0.0, 1.0)
}

unsafe fn read_bytes<'a>(ptr: i32, len: i32) -> &'a [u8] {
    if len <= 0 {
        return &[];
    }
    unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rank_answer(
    question_ptr: i32,
    question_len: i32,
    ground_truth_ptr: i32,
    ground_truth_len: i32,
    answer_ptr: i32,
    answer_len: i32,
) -> f32 {
    unsafe {
        let result = score_bytes(
            read_bytes(question_ptr, question_len),
            read_bytes(ground_truth_ptr, ground_truth_len),
            read_bytes(answer_ptr, answer_len),
        );
        HEAP_OFFSET = 0;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(question: &str, truth: &str, answer: &str) -> f32 {
        score_bytes(question.as_bytes(), truth.as_bytes(), answer.as_bytes())
    }

    #[test]
    fn exact_and_blank_satisfy_structural_contract() {
        assert_eq!(score("Scan example.com", "safe", "safe"), 1.0);
        assert_eq!(score("Scan example.com", "safe", "   \n"), 0.0);
    }

    #[test]
    fn equivalent_verdicts_score_above_opposites() {
        let safe = score(
            "Is https://example.com safe?",
            "The URL is safe and no malicious activity was detected.",
            "Verdict: benign. The site is not malicious.",
        );
        let unsafe_answer = score(
            "Is https://example.com safe?",
            "The URL is safe and no malicious activity was detected.",
            "Verdict: malicious phishing threat.",
        );
        assert!(safe > 0.8, "safe={safe}");
        assert!(unsafe_answer < 0.1, "unsafe={unsafe_answer}");
    }

    #[test]
    fn understands_json_boolean_verdicts() {
        let correct = score(
            "Scan https://bad.example",
            r#"{"verdict":"malicious","malicious":true}"#,
            r#"{"malicious":true,"reason":"phishing detected"}"#,
        );
        let wrong = score(
            "Scan https://bad.example",
            r#"{"verdict":"malicious","malicious":true}"#,
            r#"{"verdict":"safe","malicious":false}"#,
        );
        assert!(correct > 0.8, "correct={correct}");
        assert!(wrong < 0.1, "wrong={wrong}");
    }

    #[test]
    fn interprets_question_relative_yes_and_no() {
        assert!(score("Is this URL malicious?", "No.", "This URL is safe.") > 0.99);
        assert!(score("Is this URL malicious?", "No.", "Yes, malicious.") < 0.01);
        assert!(score("Is this URL safe?", "No.", "Unsafe.") > 0.99);
        assert!(score("Is this URL safe?", "Yes.", "No, it is dangerous.") < 0.01);
    }

    #[test]
    fn handles_common_machine_readable_safety_shapes() {
        let cases = [
            (r#"{"malicious":false}"#, r#"{"malicious":0}"#, "malicious"),
            (r#"{"safe":true}"#, "clean and secure", "unsafe"),
            ("No threats found", "not blacklisted", "threat detected"),
            ("Risk level: high", "critical phishing risk", "low risk"),
            ("verdict: suspicious", "warning: unverified", "safe"),
            (
                r#"{"stats":{"harmless":70,"malicious":0,"suspicious":0}}"#,
                "No malicious engines detected",
                r#"{"malicious":5,"harmless":65}"#,
            ),
            (
                r#"{"stats":{"harmless":65,"malicious":5}}"#,
                "Positive malware detections: 5",
                r#"{"malicious":0,"harmless":70}"#,
            ),
            ("malicious is false", "non-malicious", "malicious is true"),
            ("safe is false", "dangerous", "safe is true"),
        ];
        for (truth, good, bad) in cases {
            let good_score = score("Scan this URL for threats", truth, good);
            let bad_score = score("Scan this URL for threats", truth, bad);
            assert!(good_score > 0.99, "truth={truth} good={good_score}");
            assert!(bad_score < 0.01, "truth={truth} bad={bad_score}");
        }
    }

    #[test]
    fn decimal_confidence_does_not_invert_a_verdict() {
        let question = "Is http://paypal-secure-login.test safe to open?";
        let truth = "malicious phishing page; confidence 0.95. Do not open.";
        let good = "Verdict malicious, confidence 0.95; phishing. Do not open.";
        let bad = "Verdict safe, confidence 0.95; legitimate.";
        assert_eq!(score(question, truth, good), 1.0);
        assert_eq!(score(question, truth, bad), 0.0);
    }

    #[test]
    fn preserves_url_scan_counts_hash_metadata_and_graded_verdicts() {
        let cases = [
            (
                "Check github.com on VirusTotal.",
                "github.com has 0 malicious, 0 suspicious, 72 harmless, reputation 421.",
                "No engine flags github.com: 0 malicious, 0 suspicious, 72 harmless, reputation 421.",
                "github.com has 12 malicious, 4 suspicious, 56 harmless, reputation 421.",
            ),
            (
                "Is hash 44d88612fea8a8f36de82e1278abb02f malicious?",
                "The EICAR file has 63 malicious and 0 harmless detections.",
                "That SHA-256 is EICAR: 63 engines flag it malicious and 0 harmless.",
                "The file has 63 harmless and 0 malicious detections.",
            ),
            (
                "Is https://new-shop.test dangerous?",
                "It is suspicious, not confirmed malicious; the domain is 9 days old.",
                "Suspicious rather than confirmed malicious; it is 9 days old.",
                "It is confirmed malicious with 9 engine detections.",
            ),
            (
                "Is https://university.test safe?",
                "It is safe; the only note is a mixed-content warning.",
                "Safe. The only note is one mixed-content image.",
                "It is unsafe; the warning indicates an active attack.",
            ),
        ];
        for (question, truth, good, bad) in cases {
            let good_score = score(question, truth, good);
            let bad_score = score(question, truth, bad);
            assert!(
                good_score > bad_score,
                "question={question} good={good_score} bad={bad_score}"
            );
        }
    }

    #[test]
    fn binds_scores_to_the_requested_target_and_subject() {
        let question = "Is http://paypal-secure-login.tk/verify malicious?";
        let truth = "http://paypal-secure-login.tk/verify is malicious phishing.";
        assert_eq!(
            score(question, truth, "The requested URL is malicious."),
            1.0
        );
        assert_eq!(
            score(
                question,
                truth,
                "http://paypal-secure-login.ml/verify is malicious phishing.",
            ),
            0.0,
        );

        let hash_question =
            "Is 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f malicious?";
        let hash_truth = "That SHA-256 is EICAR and 61 engines flag it malicious.";
        assert_eq!(score(hash_question, hash_truth, hash_truth), 1.0);
        assert_eq!(
            score(
                hash_question,
                hash_truth,
                "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267 is EICAR and malicious.",
            ),
            0.0,
        );

        assert!(
            score(
                "What is the reputation of 185.220.101.34?",
                "It is a Tor exit node with 8 malicious hits.",
                "That address is a Tor exit relay with 8 malicious hits.",
            ) > score(
                "What is the reputation of 185.220.101.34?",
                "It is a Tor exit node with 8 malicious hits.",
                "That address is a Cloudflare edge with 8 malicious hits.",
            )
        );
    }

    #[test]
    fn rejects_mixed_verdict_keyword_stuffing() {
        let question = "Is https://example.test safe?";
        let truth = "The URL is malicious phishing and must be blocked.";
        let honest = score(question, truth, "Malicious phishing. Block it.");
        let stuffed = score(
            question,
            truth,
            "safe unsafe benign malicious phishing clean threat allow block",
        );
        assert!(honest > stuffed, "honest={honest} stuffed={stuffed}");

        let public_question = "Is http://paypal-secure-login.tk/verify safe to open?";
        let public_truth = "malicious. http://paypal-secure-login.tk/verify is listed on URLhaus as an active phishing page; confidence 0.95. Do not open it.";
        let public_honest = "Verdict malicious at confidence 0.95: URLhaus lists http://paypal-secure-login.tk/verify as a live phishing page, so it should not be opened.";
        let public_dump = "url scan phishing malware virus threat block allow safe unsafe verdict confidence urlhaus virustotal phishtank domain ip redirect certificate malicious http://paypal-secure-login.tk/verify page active listed open";
        let honest_score = score(public_question, public_truth, public_honest);
        let dump_score = score(public_question, public_truth, public_dump);
        assert!(
            mixed_verdict(&tokenize(public_dump.as_bytes())),
            "public keyword dump was not recognized as mixed"
        );
        assert!(
            !mixed_verdict(&tokenize(public_truth.as_bytes())),
            "public ground truth was incorrectly recognized as mixed"
        );
        assert!(
            !significant_tokens_equal(
                &tokenize(public_truth.as_bytes()),
                &tokenize(public_dump.as_bytes())
            ),
            "public keyword dump matched the significant-token shortcut"
        );
        assert!(
            honest_score > dump_score,
            "public honest={honest_score} dump={dump_score}"
        );
    }

    #[test]
    fn accepts_virustotal_hash_paraphrase() {
        let question =
            "Is the file hash 44d88612fea8a8f36de82e1278abb02f malicious according to VirusTotal?";
        let truth = "44d88612fea8a8f36de82e1278abb02f is the EICAR test file; 63 engines flag it as malicious, 0 harmless.";
        let good = "That hash is the EICAR test string. VirusTotal shows 63 engines flagging it malicious and 0 calling it harmless.";
        let question_tokens = tokenize(question.as_bytes());
        let truth_tokens = tokenize(truth.as_bytes());
        let good_tokens = tokenize(good.as_bytes());
        assert!(
            !numeric_conflict(&question_tokens, &truth_tokens, &good_tokens),
            "numeric conflict"
        );
        assert!(
            !identifier_conflict(question.as_bytes(), truth.as_bytes(), good.as_bytes()),
            "identifier conflict"
        );
        assert!(
            !entity_conflict(&question_tokens, &truth_tokens, &good_tokens),
            "entity conflict"
        );
        assert!(
            verdict(&question_tokens, &truth_tokens) == verdict(&question_tokens, &good_tokens),
            "verdict conflict"
        );
        assert_eq!(
            signed_axis(&truth_tokens, |token| token.confirmation),
            signed_axis(&good_tokens, |token| token.confirmation),
            "confirmation conflict"
        );
        assert_eq!(
            signed_axis(&truth_tokens, |token| token.agreement),
            signed_axis(&good_tokens, |token| token.agreement),
            "agreement conflict"
        );
        assert!(!mixed_verdict(&good_tokens), "mixed verdict");
        assert_eq!(score(question, truth, good), 1.0);
    }

    #[test]
    fn awkward_and_large_inputs_remain_bounded() {
        let score = score(
            "🔒 هل هذا الرابط آمن؟",
            "safe benign clean",
            "安全 ✅ benign",
        );
        assert!((0.0..=1.0).contains(&score));

        let large = [b'a'; 200_000];
        let score = score_bytes(b"scan", b"safe", &large);
        assert!((0.0..=1.0).contains(&score));
    }

    #[test]
    fn arbitrary_bytes_are_finite_bounded_and_repeatable() {
        let mut state = 0x9e37_79b9u32;
        let mut question = [0u8; 257];
        let mut truth = [0u8; 263];
        let mut answer = [0u8; 269];
        for iteration in 0..512 {
            for byte in question
                .iter_mut()
                .chain(truth.iter_mut())
                .chain(answer.iter_mut())
            {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = (state >> 24) as u8;
            }
            question[iteration % question.len()] = 0;
            truth[iteration % truth.len()] = 0;
            answer[iteration % answer.len()] = 0;
            let question_len = iteration % (question.len() + 1);
            let truth_len = (iteration * 3) % (truth.len() + 1);
            let answer_len = (iteration * 7) % (answer.len() + 1);
            let inputs = (
                &question[..question_len],
                &truth[..truth_len],
                &answer[..answer_len],
            );
            let first = score_bytes(inputs.0, inputs.1, inputs.2);
            let second = score_bytes(inputs.0, inputs.1, inputs.2);
            assert!(first.is_finite() && (0.0..=1.0).contains(&first));
            assert_eq!(first, second);
        }
    }
}
