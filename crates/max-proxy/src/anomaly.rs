//! Lightweight response-body anomaly heuristics.

/// A detected anomaly signal and optional excerpt for analysts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnomalyHit {
    pub signal: String,
    pub excerpt: String,
}

const SIGNALS: &[(&str, &str)] = &[
    ("database_error_string", "SQLSTATE["),
    ("database_error_string", "SQL syntax"),
    ("database_error_string", "mysql_fetch"),
    ("database_error_string", "ORA-"),
    ("database_error_string", "PostgreSQL"),
    ("database_error_string", "sqlite3.OperationalError"),
    ("stack_trace", "Traceback (most recent call last)"),
    ("stack_trace", "Exception in thread"),
    ("stack_trace", " at java."),
    ("debug_disclosure", "phpinfo()"),
    ("debug_disclosure", "ASP.NET is configured"),
];

/// Scan a response body (lossy UTF-8) for known error / disclosure patterns.
pub fn detect_anomaly(body: &[u8]) -> Option<AnomalyHit> {
    let text = String::from_utf8_lossy(body);
    for (signal, needle) in SIGNALS {
        if let Some(idx) = text.find(needle) {
            let end = (idx + needle.len() + 48).min(text.len());
            let excerpt = text[idx..end].chars().take(80).collect::<String>();
            return Some(AnomalyHit {
                signal: (*signal).to_string(),
                excerpt,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sqlstate() {
        let hit = detect_anomaly(b"error: SQLSTATE[HY000] General error").unwrap();
        assert_eq!(hit.signal, "database_error_string");
        assert!(hit.excerpt.contains("SQLSTATE"));
    }

    #[test]
    fn clean_body_is_none() {
        assert!(detect_anomaly(b"{\"ok\":true}").is_none());
    }
}
