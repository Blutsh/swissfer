//! Altcha proof-of-work for transfer creation.
//!
//! Before it opens a transfer, SwissTransfer wants proof that the client spent some
//! CPU time. It hands out a salt and the SHA-256 of that salt followed by a secret
//! number; the client finds the number by trying them in order and sends it back
//! with the server's own signature. The website does this in the background on
//! every upload, and so does this module.

use std::time::Instant;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::api::{request, Method, Session};
use crate::errors::SwishError;
use crate::swissfiles::SWISSTRANSFER_API;

/// Fetch a challenge, solve it, and return the value the `altcha` field expects.
pub fn solve(session: &Session) -> Result<String, SwishError> {
    let response = request(
        &format!("{}/altcha-challenge", SWISSTRANSFER_API),
        Method::Get,
        None,
        None,
        Some(vec!["Accept: application/json".to_string()]),
        Some(session),
    )?;

    let challenge: serde_json::Value = serde_json::from_str(&response.text())?;
    let unexpected = || SwishError::InvalidResponse {
        response: format!("unexpected Altcha challenge: {}", response.text()),
    };

    let salt = challenge["salt"].as_str().ok_or_else(unexpected)?;
    let target = challenge["challenge"].as_str().ok_or_else(unexpected)?;
    let max_number = challenge["maxNumber"].as_u64().ok_or_else(unexpected)?;
    if challenge["algorithm"] != "SHA-256" {
        return Err(unexpected());
    }

    let started = Instant::now();
    let number = find_number(salt, target, max_number).ok_or_else(unexpected)?;
    let took = started.elapsed().as_millis() as u64;
    log::debug!("Altcha solved in {} ms", took);

    let payload = json!({
        "algorithm": "SHA-256",
        "challenge": target,
        "number": number,
        "salt": salt,
        "signature": challenge["signature"],
        "took": took,
    });

    Ok(STANDARD.encode(payload.to_string()))
}

/// The number for which SHA-256(salt + number) is `target`, a lowercase hex digest.
fn find_number(salt: &str, target: &str, max_number: u64) -> Option<u64> {
    let salted = Sha256::new_with_prefix(salt);

    (0..=max_number).find(|number| {
        let digest = salted.clone().chain_update(number.to_string()).finalize();
        format!("{:x}", digest) == target
    })
}

#[cfg(test)]
mod tests {
    use super::find_number;

    const SALT: &str = "salt?expires=1&";
    /// SHA-256 of `salt?expires=1&1234`.
    const TARGET: &str = "8db4a2eee26c7d82a21a787c7dff37927d58596875ba70ab2d8effa55cdb9532";

    #[test]
    fn finds_the_number_behind_a_challenge() {
        assert_eq!(find_number(SALT, TARGET, 5000), Some(1234));
        assert_eq!(find_number(SALT, TARGET, 1234), Some(1234));
    }

    #[test]
    fn gives_up_past_the_maximum() {
        assert_eq!(find_number(SALT, TARGET, 1233), None);
    }
}
