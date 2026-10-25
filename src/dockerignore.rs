//! Bounded Linux Moby ignorefile rules. Matching is an iterative NFA, never
//! recursive backtracking. Paths are relative to the original context root.
use crate::context::Error;

pub(crate) const MAX_BYTES: usize = 1024 * 1024;
const MAX_RULES: usize = 4096;
const MAX_PATTERN: usize = 4096;
const MAX_STATES: usize = 65536;
pub(crate) const WORK: u64 = 256 * 1024 * 1024;

#[derive(Debug)]
enum Token {
    Literal(char),
    Start,
    Any,
    Star,
    Glob,
    // Zero characters, or any string ending in '/'.
    Dirs,
    Class(bool, Vec<(char, char)>),
}
#[derive(Debug)]
struct Rule {
    include: bool,
    pattern: String,
    tokens: Vec<Token>,
    suffix: Option<String>,
    prefix: Option<String>,
}
#[derive(Debug, Default)]
pub(crate) struct Policy {
    rules: Vec<Rule>,
    pub(crate) negations: bool,
}

fn clean(s: &str) -> String {
    let absolute = s.starts_with('/');
    let mut parts = Vec::new();
    for p in s.split('/') {
        match p {
            "" | "." => (),
            ".." if parts.last().is_some_and(|p| *p != "..") => {
                parts.pop();
            }
            ".." if absolute => (),
            _ => parts.push(p),
        }
    }
    let p = parts.join("/");
    if absolute {
        format!("/{p}")
    } else if p.is_empty() {
        ".".into()
    } else {
        p
    }
}

impl Policy {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::Limit("dockerignore bytes"));
        }
        let text = std::str::from_utf8(bytes).map_err(|_| Error::Invalid("dockerignore UTF-8"))?;
        let mut policy = Self::default();
        let mut states = 0usize;
        for (i, line) in text.split('\n').enumerate() {
            let line = if i == 0 {
                line.strip_prefix('\u{feff}').unwrap_or(line)
            } else {
                line
            };
            if line.starts_with('#') {
                continue;
            }
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line.len() > MAX_PATTERN {
                return Err(Error::Limit("dockerignore pattern bytes"));
            }
            let include = line.starts_with('!');
            let raw = if include { line[1..].trim() } else { line };
            if raw.is_empty() {
                return Err(Error::Invalid("bare dockerignore !"));
            }
            let pattern = clean(raw);
            let pattern = if pattern.len() > 1 {
                pattern.strip_prefix('/').unwrap_or(&pattern)
            } else {
                &pattern
            };
            if pattern == "." {
                continue;
            }
            // Moby optimizes a leading ** followed only by literals as a suffix
            // match (including the unusual **foo spelling).
            let suffix = pattern
                .strip_prefix("**")
                .filter(|s| !s.contains(['*', '?', '[', ']', '\\']))
                .map(str::to_owned);
            let prefix = pattern
                .strip_suffix("**")
                .filter(|s| !s.contains(['*', '?', '[', ']', '\\']))
                .map(str::to_owned);
            let regexp = suffix.is_none()
                && prefix.is_none()
                && pattern.contains(['*', '?', '[', ']', '\\']);
            let tokens = compile(pattern, regexp)?;
            states = states
                .checked_add(tokens.len() + 1)
                .ok_or(Error::Limit("dockerignore states"))?;
            if states > MAX_STATES || policy.rules.len() == MAX_RULES {
                return Err(Error::Limit("dockerignore rules/states"));
            }
            policy.negations |= include;
            policy.rules.push(Rule {
                include,
                pattern: pattern.into(),
                tokens,
                suffix,
                prefix,
            });
        }
        Ok(policy)
    }

    pub(crate) fn identity(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for r in &self.rules {
            out.push(u8::from(r.include));
            out.extend_from_slice(&(r.pattern.len() as u64).to_le_bytes());
            out.extend_from_slice(r.pattern.as_bytes());
        }
        out
    }

    #[cfg(test)]
    fn excluded(&self, path: &[u8], work: &mut u64) -> Result<bool, Error> {
        self.excluded_cancellable(path, work, &|| false)
    }

    pub(crate) fn excluded_cancellable(
        &self,
        path: &[u8],
        work: &mut u64,
        cancelled: &impl Fn() -> bool,
    ) -> Result<bool, Error> {
        if path.is_empty() {
            return Ok(false);
        }
        let mut excluded = false;
        for rule in &self.rules {
            if cancelled() {
                return Err(Error::Cancelled);
            }
            charge(work, 1)?;
            if rule.include != excluded {
                continue;
            }
            let mut end = path.len();
            loop {
                if rule.matches(&path[..end], work, cancelled)? {
                    excluded = !rule.include;
                    break;
                }
                match path[..end].iter().rposition(|b| *b == b'/') {
                    Some(n) => end = n,
                    None => break,
                }
            }
        }
        Ok(excluded)
    }
}

fn charge(work: &mut u64, amount: u64) -> Result<(), Error> {
    *work = work
        .checked_sub(amount)
        .ok_or(Error::Limit("dockerignore matching work"))?;
    Ok(())
}

impl Rule {
    fn matches(
        &self,
        s: &[u8],
        work: &mut u64,
        cancelled: &impl Fn() -> bool,
    ) -> Result<bool, Error> {
        charge(
            work,
            (s.len() as u64 + 1)
                .checked_mul(self.pattern.len() as u64 + 1)
                .ok_or(Error::Limit("dockerignore matching work"))?,
        )?;
        if let Some(suffix) = &self.suffix {
            return Ok(s.ends_with(suffix.as_bytes())
                || suffix.strip_prefix('/').map(str::as_bytes) == Some(s));
        }
        if let Some(prefix) = &self.prefix {
            return Ok(s.starts_with(prefix.as_bytes()));
        }
        // Moby's exact mode compares bytes; only regexp mode decodes runes.
        if !self.pattern.contains(['*', '?', '[', ']', '\\']) {
            return Ok(s == self.pattern.as_bytes());
        }
        let mut active = vec![false; self.tokens.len() + 1];
        active[0] = true;
        // Dirs needs a separate consuming state: epsilon is allowed only before
        // consuming, and after a slash, not after each arbitrary character.
        let mut dirs = vec![false; self.tokens.len()];
        // Go regexp consumes each invalid UTF-8 byte as one replacement rune
        // (unlike from_utf8_lossy, which can combine truncated sequences).
        let mut remaining = s;
        let chars = std::iter::from_fn(move || {
            let first = *remaining.first()?;
            let width = match first {
                0..=127 => 1,
                194..=223 => 2,
                224..=239 => 3,
                240..=244 => 4,
                _ => 1,
            };
            let decoded = remaining
                .get(..width)
                .and_then(|b| std::str::from_utf8(b).ok())
                .and_then(|s| s.chars().next());
            remaining = &remaining[if decoded.is_some() { width } else { 1 }..];
            Some(u32::from(decoded.unwrap_or('\u{fffd}')))
        });
        for (position, ch) in chars.map(Some).chain(std::iter::once(None)).enumerate() {
            if cancelled() {
                return Err(Error::Cancelled);
            }
            for (i, t) in self.tokens.iter().enumerate() {
                if active[i]
                    && (matches!(t, Token::Star | Token::Glob | Token::Dirs)
                        || (matches!(t, Token::Start) && position == 0))
                {
                    active[i + 1] = true;
                }
            }
            let Some(ch) = ch else {
                return Ok(active[self.tokens.len()]);
            };
            let mut next = vec![false; active.len()];
            for (i, t) in self.tokens.iter().enumerate() {
                if matches!(t, Token::Dirs) {
                    let consuming = active[i] || dirs[i];
                    dirs[i] = consuming && ch != u32::from('\n');
                    if consuming && ch == u32::from('/') {
                        next[i + 1] = true;
                    }
                    continue;
                }
                if !active[i] {
                    continue;
                }
                match t {
                    Token::Star if ch != u32::from('/') => next[i] = true,
                    Token::Glob if ch != u32::from('\n') => next[i] = true,
                    Token::Any if ch != u32::from('/') => next[i + 1] = true,
                    Token::Literal(c) if u32::from(*c) == ch => next[i + 1] = true,
                    Token::Class(neg, ranges)
                        if ranges
                            .iter()
                            .any(|(a, b)| u32::from(*a) <= ch && ch <= u32::from(*b))
                            != *neg =>
                    {
                        next[i + 1] = true
                    }
                    _ => (),
                }
            }
            active = next;
        }
        unreachable!()
    }
}

fn compile(pattern: &str, regexp: bool) -> Result<Vec<Token>, Error> {
    let chars: Vec<_> = pattern.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        out.push(match c {
            '*' if chars.get(i) == Some(&'*') => {
                i += 1;
                if chars.get(i) == Some(&'/') {
                    i += 1;
                }
                if i == chars.len() {
                    Token::Glob
                } else {
                    Token::Dirs
                }
            }
            '*' => Token::Star,
            '?' => Token::Any,
            '\\' => escape(&chars, &mut i)?,
            // Moby passes ^ through only when it ultimately uses regexp mode.
            '^' => Token::Start,
            // shortcut: Moby v0.6.0's byte bitmap fails to quote |{}; reject
            // their regexp operators until bounded semantics are implemented.
            '|' | '{' | '}' if regexp => {
                return Err(Error::Invalid("unsupported dockerignore regexp operator"));
            }
            '[' => {
                let neg = chars.get(i) == Some(&'^');
                if neg {
                    i += 1;
                }
                let mut ranges = Vec::new();
                while chars.get(i) != Some(&']') {
                    if chars.get(i) == Some(&'\\') {
                        let mut end = i + 1;
                        if let Token::Class(neg, escaped) = escape(&chars, &mut end)? {
                            if chars.get(end) == Some(&'-') {
                                return Err(Error::Invalid("dockerignore class range"));
                            }
                            if neg {
                                let mut start = '\0';
                                for (a, b) in escaped {
                                    if start < a {
                                        ranges.push((start, char::from_u32(a as u32 - 1).unwrap()));
                                    }
                                    start = char::from_u32(b as u32 + 1).unwrap();
                                }
                                ranges.push((start, char::MAX));
                            } else {
                                ranges.extend(escaped);
                            }
                            i = end;
                            continue;
                        }
                    }
                    let a = class_char(&chars, &mut i)?;
                    let b = if chars.get(i) == Some(&'-') {
                        i += 1;
                        class_char(&chars, &mut i)?
                    } else {
                        a
                    };
                    if a > b {
                        return Err(Error::Invalid("dockerignore class range"));
                    }
                    ranges.push((a, b));
                }
                if ranges.is_empty() {
                    return Err(Error::Invalid("empty dockerignore class"));
                }
                i += 1;
                Token::Class(neg, ranges)
            }
            _ => Token::Literal(c),
        });
    }
    Ok(out)
}
fn class_char(chars: &[char], i: &mut usize) -> Result<char, Error> {
    let mut c = *chars
        .get(*i)
        .ok_or(Error::Invalid("unterminated dockerignore class"))?;
    *i += 1;
    if c == '\\' {
        c = match escape(chars, i)? {
            Token::Literal(c) => c,
            _ => return Err(Error::Invalid("dockerignore class range")),
        };
    } else if matches!(c, ']' | '-' | '[' | '*' | '?') {
        return Err(Error::Invalid("dockerignore class character"));
    }
    Ok(c)
}

// Moby v0.6.0 passes escapes to Go regexp, rather than filepath.Match.
// shortcut: reject assertions, quoting, Unicode classes and braced hex until
// their interaction with Moby's regexp rewriting is implemented and verified.
fn escape(chars: &[char], i: &mut usize) -> Result<Token, Error> {
    let c = *chars
        .get(*i)
        .ok_or(Error::Invalid("dockerignore trailing escape"))?;
    *i += 1;
    let literal = match c {
        'a' => '\u{7}',
        'f' => '\u{c}',
        't' => '\t',
        'n' => '\n',
        'r' => '\r',
        'v' => '\u{b}',
        'd' | 'D' | 's' | 'S' | 'w' | 'W' => {
            let ranges = match c.to_ascii_lowercase() {
                'd' => vec![('0', '9')],
                's' => vec![('\t', '\n'), ('\u{c}', '\r'), (' ', ' ')],
                _ => vec![('0', '9'), ('A', 'Z'), ('_', '_'), ('a', 'z')],
            };
            return Ok(Token::Class(c.is_ascii_uppercase(), ranges));
        }
        'x' => {
            let mut value = 0;
            for _ in 0..2 {
                value = value * 16
                    + chars
                        .get(*i)
                        .and_then(|c| c.to_digit(16))
                        .ok_or(Error::Invalid("unsupported dockerignore hex escape"))?;
                *i += 1;
            }
            char::from_u32(value).unwrap()
        }
        '0'..='7' => {
            let mut value = c.to_digit(8).unwrap();
            let mut digits = 1;
            while digits < 3 {
                let Some(n) = chars.get(*i).and_then(|c| c.to_digit(8)) else {
                    break;
                };
                value = value * 8 + n;
                digits += 1;
                *i += 1;
            }
            if digits == 1 && c != '0' {
                return Err(Error::Invalid("dockerignore backreference escape"));
            }
            char::from_u32(value).unwrap()
        }
        c if c.is_ascii() && !c.is_ascii_alphanumeric() => c,
        _ => return Err(Error::Invalid("unsupported dockerignore regexp escape")),
    };
    Ok(Token::Literal(literal))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn caret_assertions_depend_on_moby_match_mode() {
        for (pattern, path, expected) in [
            ("^secret*", "secret.txt", true),
            ("^secret*", "^secret.txt", false),
            ("^^secret*", "secret.txt", true),
            ("sec^ret*", "secret.txt", false),
            ("*^secret", "secret", true),
            ("*^secret", "xsecret", false),
            ("secret*^", "secret", false),
            ("^secret.txt", "^secret.txt", true),
            ("^secret.txt", "secret.txt", false),
            ("**^secret", "dir/^secret", true),
            ("**^secret", "dir/secret", false),
            ("^secret**", "^secret.txt", true),
            ("^secret**", "secret.txt", false),
            ("**/^secret?", "secret1", true),
            ("**/^secret?", "dir/secret1", false),
            (r"\^secret*", "^secret.txt", true),
            (r"\^secret*", "secret.txt", false),
            ("[^a]secret*", "bsecret.txt", true),
            ("[^a]secret*", "asecret.txt", false),
            ("[a^]secret*", "^secret.txt", true),
        ] {
            let p = Policy::parse(pattern.as_bytes()).unwrap();
            assert_eq!(
                p.excluded(path.as_bytes(), &mut WORK.clone()).unwrap(),
                expected,
                "{pattern}"
            );
        }
    }

    #[test]
    fn other_regexp_punctuation_stays_literal() {
        // Moby treats these as literals in regexp mode, including $ and lone ].
        for c in ".+()$]".chars() {
            let pattern = format!("secret{c}*");
            let p = Policy::parse(pattern.as_bytes()).unwrap();
            assert!(
                p.excluded(format!("secret{c}.txt").as_bytes(), &mut WORK.clone())
                    .unwrap(),
                "{pattern}"
            );
            assert!(
                !p.excluded(b"secretXtxt", &mut WORK.clone()).unwrap(),
                "{pattern}"
            );
        }
    }

    #[test]
    fn regexp_alternation_and_repetition_fail_closed() {
        for pattern in [
            "secret|*",
            "secret{2}*",
            "secret}*",
            "**/secret|x?",
            "!secret{2}*",
        ] {
            assert!(Policy::parse(pattern.as_bytes()).is_err(), "{pattern}");
        }
        for c in "|{}".chars() {
            for pattern in [
                format!("secret{c}"),
                format!("secret{c}**"),
                format!("**secret{c}"),
                format!(r"secret\{c}*"),
                format!("secret[{c}]*"),
            ] {
                let p = Policy::parse(pattern.as_bytes()).unwrap();
                assert!(
                    p.excluded(format!("secret{c}").as_bytes(), &mut WORK.clone())
                        .unwrap(),
                    "{pattern}"
                );
                assert!(
                    !p.excluded(b"secretX", &mut WORK.clone()).unwrap(),
                    "{pattern}"
                );
            }
        }
    }

    #[test]
    fn invalid_utf8_uses_go_runes_only_in_regexp_mode() {
        // Expectations checked against Linux Moby patternmatcher v0.6.0.
        for (pattern, path, expected) in [
            ("secret*\u{fffd}", &b"secret\xff"[..], true),
            ("secret*\u{fffd}", &b"secret\xff/child"[..], true),
            ("secret[\u{fffd}]", &b"secret\xff"[..], true),
            ("secret[^\u{fffd}]", &b"secret\xff"[..], false),
            ("secret?\u{fffd}", &b"secret\xe2\x82"[..], true),
            ("secret?", &b"secret\xe2\x82"[..], false),
            ("secret\u{fffd}", &b"secret\xff"[..], false),
            ("secret\u{fffd}**", &b"secret\xfftail"[..], false),
            ("**secret\u{fffd}", &b"dir/secret\xff"[..], false),
            ("**/secret\u{fffd}", &b"secret\xff"[..], false),
            ("secret**", &b"secret\xff"[..], true),
            ("**secret", &b"\xffsecret"[..], true),
            ("**/secret?\u{fffd}", &b"dir/secret\xe2\x82"[..], true),
            ("secret*\n!secret*\u{fffd}", &b"secret\xff"[..], false),
            ("secret*\n!secret\u{fffd}", &b"secret\xff"[..], true),
        ] {
            let p = Policy::parse(pattern.as_bytes()).unwrap();
            assert_eq!(
                p.excluded(path, &mut WORK.clone()).unwrap(),
                expected,
                "{pattern}: {path:?}"
            );
        }
        for pattern in [
            "secret\u{fffd}",
            "secret\u{fffd}**",
            "**secret\u{fffd}",
            "**/secret\u{fffd}",
        ] {
            let p = Policy::parse(pattern.as_bytes()).unwrap();
            assert!(
                p.excluded("secret\u{fffd}".as_bytes(), &mut WORK.clone())
                    .unwrap(),
                "{pattern}"
            );
        }
    }

    #[test]
    fn regexp_escapes_do_not_literalize_secrets() {
        let p = Policy::parse(br"secret\tkey").unwrap();
        assert!(p.excluded(b"secret\tkey", &mut WORK.clone()).unwrap());
        assert!(!p.excluded(b"secrettkey", &mut WORK.clone()).unwrap());
    }
    #[test]
    fn common_go_regexp_escapes_and_classes() {
        for (pattern, yes, no) in [
            (r"a\ab", "a\u{7}b", "aab"),
            (r"a\fb", "a\u{c}b", "afb"),
            (r"a\nb", "a\nb", "anb"),
            (r"a\rb", "a\rb", "arb"),
            (r"a\vb", "a\u{b}b", "avb"),
            (r"a\x09b", "a\tb", "ax09b"),
            (r"a\011b", "a\tb", "a011b"),
            (r"a\*b", "a*b", "axxb"),
            (r"a\?b", "a?b", "axb"),
            (r"a\.b", "a.b", "axb"),
            (r"a\!b", "a!b", "ab"),
            (r"a\\b", r"a\b", "ab"),
            (r"a\db", "a5b", "aDb"),
            (r"a\Db", "aDb", "a5b"),
            (r"a\sb", "a\tb", "a\u{b}b"),
            (r"a\Sb", "a\u{b}b", "a\tb"),
            (r"a\wb", "a_b", "aéb"),
            (r"a\Wb", "aéb", "a_b"),
            (r"a[\t]b", "a\tb", "atb"),
            (r"a[\d_]b", "a5b", "adb"),
            (r"a[^\d]b", "adb", "a5b"),
            (r"a[\D]b", "adb", "a5b"),
            (r"a[^\D]b", "a5b", "adb"),
            (r"a[\w]b", "a_b", "aéb"),
            (r"a[\W]b", "aéb", "a_b"),
            (r"a[\s]b", "a\tb", "a\u{b}b"),
            (r"a[\S]b", "a\u{b}b", "a\tb"),
            (r"a[\x30-\x39]b", "a5b", "axb"),
            (r"a[\*\?\]]b", "a]b", "axb"),
        ] {
            let p = Policy::parse(pattern.as_bytes()).unwrap();
            assert!(
                p.excluded(yes.as_bytes(), &mut WORK.clone()).unwrap(),
                "{pattern}"
            );
            assert!(
                !p.excluded(no.as_bytes(), &mut WORK.clone()).unwrap(),
                "{pattern}"
            );
        }
        for pattern in [
            r"\q",
            r"\c",
            r"\u1234",
            r"\8",
            r"\1",
            r"\x",
            r"\x0g",
            r"[\q]",
            r"[a-\d]",
            r"\pL",
            r"\P{Greek}",
            r"\b",
            r"\B",
            r"\A",
            r"\z",
            r"\Qfoo\E",
            r"\x{09}",
        ] {
            assert!(Policy::parse(pattern.as_bytes()).is_err(), "{pattern}");
        }
    }
    #[test]
    fn unicode_bytes_prefix_and_bounded_work() {
        let p = Policy::parse("?\n!é\n�\nfoo**\n".as_bytes()).unwrap();
        assert!(!p.excluded("é".as_bytes(), &mut WORK.clone()).unwrap());
        assert!(p.excluded(b"\xff", &mut WORK.clone()).unwrap());
        let literal = Policy::parse("�".as_bytes()).unwrap();
        assert!(!literal.excluded(b"\xff", &mut WORK.clone()).unwrap());
        assert!(p.excluded(b"foo\nbar", &mut WORK.clone()).unwrap());
        let expensive = Policy::parse("*a".repeat(100).as_bytes()).unwrap();
        assert!(matches!(
            expensive.excluded(&[b'a'; 200], &mut 100),
            Err(Error::Limit(_))
        ));
        assert!(matches!(
            p.excluded_cancellable(b"foo", &mut WORK.clone(), &|| true),
            Err(Error::Cancelled)
        ));
        assert_eq!(
            Policy::parse(b"# comment\r\n /a/../b/\n")
                .unwrap()
                .identity(),
            Policy::parse(b"b\n").unwrap().identity()
        );
    }
    #[test]
    fn ordered_ancestors_and_globs() {
        let p = Policy::parse(b"cache\n!cache/**/keep?.[ch]\ncache/private\n").unwrap();
        for (s, excluded) in [
            ("cache/a", true),
            ("cache/keep1.c", false),
            ("cache/a/b/keep2.h", false),
            ("cache/private/keep1.c", true),
            ("nested/cache/a", false),
        ] {
            assert_eq!(
                p.excluded(s.as_bytes(), &mut WORK.clone()).unwrap(),
                excluded,
                "{s}"
            );
        }
    }
    #[test]
    fn ignorefile_cleaning_and_limits() {
        let p = Policy::parse(
            "\u{feff}#comment\r\n #literal\r\n /a/../b/ \n.\n\\!literal\n".as_bytes(),
        )
        .unwrap();
        for s in ["#literal", "b/file", "!literal"] {
            assert!(p.excluded(s.as_bytes(), &mut WORK.clone()).unwrap());
        }
        assert!(Policy::parse(b"! \n").is_err());
        assert!(Policy::parse(b"[z-a]").is_err());
        assert!(Policy::parse(b"foo\\").is_err());
        assert!(p.excluded(b"b", &mut 0).is_err());
        assert!(Policy::parse(&vec![b'x'; MAX_PATTERN + 1]).is_err());
    }
}
