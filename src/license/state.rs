//! What a licensed app keeps on this machine, and what it may do now.
//!
//! [`LicenseState`] lives in the app's own data folder as JSON. Keep it out
//! of any document a user moves between machines: a license is activated
//! for one machine.
//!
//! The trial clock never runs backwards: the state remembers the latest time
//! it saw, and a clock set back to stretch a trial reads as that time.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{
    DAY_SECS, RECHECK_SECS, TRIAL_DAYS,
    client::CheckOutcome,
    file::{LicenseClaims, normalize_key},
};

/// The trial clock, this machine's id, and the license once there is one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseState {
    /// This machine's id, made at first launch. A license is bound to it.
    pub machine: String,
    /// When the trial began: the first launch.
    pub trial_started: i64,
    /// The latest time the app saw, so a clock set back cannot rewind the
    /// trial.
    pub last_seen: i64,
    /// The license key, as entered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The signed license file the server issued for this machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// When the server last answered a re-check.
    #[serde(default)]
    pub last_check: i64,
    /// The server said the license was revoked.
    #[serde(default)]
    pub revoked: bool,
}

/// What the app may do now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Access {
    /// In the trial, with whole days left (at least 1 while any time is).
    Trial { days_left: i64, ends_at: i64 },
    /// A license for this machine.
    Licensed(LicenseClaims),
    /// The trial ran out and there is no license.
    TrialOver,
    /// The server revoked the license (a refund, or this machine was
    /// deactivated).
    Revoked,
}

impl Access {
    /// Whether the full app is unlocked: a trial or a license. When it is
    /// not, an app still shows the user's own data (it may turn off
    /// editing), never hides it.
    pub fn is_unlocked(&self) -> bool {
        matches!(self, Self::Trial { .. } | Self::Licensed(_))
    }

    pub fn is_licensed(&self) -> bool {
        matches!(self, Self::Licensed(_))
    }
}

impl LicenseState {
    /// A first launch: the trial starts now.
    pub fn new(now: i64) -> Self {
        Self {
            machine: new_machine_id(),
            trial_started: now,
            last_seen: now,
            ..Self::default()
        }
    }

    /// The state in `path`, or a new one when there is none yet. A file that
    /// cannot be read starts over too, so a damaged file never locks a user
    /// out of the app.
    pub fn load(path: &Path, now: i64) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Self>(&bytes).ok())
            .filter(|state| !state.machine.is_empty())
            .unwrap_or_else(|| Self::new(now))
    }

    /// Writes the state to `path` (through a temporary file, so a crash never
    /// leaves half a file).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension("json.tmp");
        std::fs::write(&temporary, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&temporary, path)
    }

    /// `now`, or the latest time seen if the clock went back. Remembers it.
    pub fn observe(&mut self, now: i64) -> i64 {
        if now > self.last_seen {
            self.last_seen = now;
        }
        self.last_seen
    }

    /// What the app may do at `now`, checking the license file against the
    /// app's `public_key`.
    pub fn access(&mut self, app: &str, public_key: &str, now: i64) -> Access {
        let now = self.observe(now);
        if self.revoked {
            return Access::Revoked;
        }
        if let Some(file) = &self.license
            && let Ok(claims) = LicenseClaims::verify(file, public_key, app, &self.machine)
        {
            return Access::Licensed(claims);
        }
        let ends_at = self.trial_started + TRIAL_DAYS * DAY_SECS;
        if now < ends_at {
            let left = ends_at - now;
            Access::Trial {
                days_left: (left + DAY_SECS - 1) / DAY_SECS,
                ends_at,
            }
        } else {
            Access::TrialOver
        }
    }

    /// Keeps a license the server issued for `key`.
    pub fn set_license(&mut self, key: &str, file: String, now: i64) {
        self.key = Some(normalize_key(key));
        self.license = Some(file);
        self.revoked = false;
        self.last_check = self.observe(now);
    }

    /// Forgets the license (after deactivating this machine). The trial does
    /// not start again.
    pub fn clear_license(&mut self) {
        self.key = None;
        self.license = None;
        self.revoked = false;
    }

    /// Whether a licensed app should ask the server again.
    pub fn needs_check(&self, now: i64) -> bool {
        self.license.is_some() && now.max(self.last_seen) - self.last_check >= RECHECK_SECS
    }

    /// Takes in a re-check's answer. Only `Revoked` locks; an unreachable
    /// server changes nothing and is asked again next launch.
    pub fn record_check(&mut self, outcome: CheckOutcome, now: i64) {
        let now = self.observe(now);
        match outcome {
            CheckOutcome::Active => {
                self.revoked = false;
                self.last_check = now;
            }
            CheckOutcome::Revoked => {
                self.revoked = true;
                self.last_check = now;
            }
            CheckOutcome::Unreachable => {}
        }
    }
}

/// A random 128-bit machine id, in hex.
fn new_machine_id() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0u8; 16];
    if SystemRandom::new().fill(&mut bytes).is_err() {
        // No system randomness: fall back to the clock, which is still
        // unique enough to tell this machine's activation from another's.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        bytes = nanos.to_le_bytes();
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::license::file::tests::{claims, signed, test_keys};

    const START: i64 = 1_800_000_000;

    #[test]
    fn a_trial_counts_down_fourteen_days_then_ends() {
        let mut state = LicenseState::new(START);
        assert_eq!(
            state.access("tally", "", START),
            Access::Trial {
                days_left: 14,
                ends_at: START + 14 * DAY_SECS
            }
        );
        assert!(matches!(
            state.access("tally", "", START + 13 * DAY_SECS + 1),
            Access::Trial { days_left: 1, .. }
        ));
        assert_eq!(
            state.access("tally", "", START + 14 * DAY_SECS),
            Access::TrialOver
        );
        assert!(!Access::TrialOver.is_unlocked());
    }

    #[test]
    fn setting_the_clock_back_does_not_rewind_the_trial() {
        let mut state = LicenseState::new(START);
        assert_eq!(
            state.access("tally", "", START + 20 * DAY_SECS),
            Access::TrialOver
        );
        assert_eq!(state.access("tally", "", START), Access::TrialOver);
        assert_eq!(state.last_seen, START + 20 * DAY_SECS);
    }

    #[test]
    fn a_license_for_this_machine_unlocks_after_the_trial() {
        let (pair, public) = test_keys();
        let mut state = LicenseState::new(START);
        state.machine = "m1".into();
        state.set_license("tally-aaaa", signed(&pair, &claims()), START);
        assert_eq!(state.key.as_deref(), Some("TALLY-AAAA"));
        assert_eq!(
            state.access("tally", &public, START + 100 * DAY_SECS),
            Access::Licensed(claims())
        );

        // Another machine's file, copied here, is only a trial.
        state.machine = "m2".into();
        assert_eq!(
            state.access("tally", &public, START + 100 * DAY_SECS),
            Access::TrialOver
        );
    }

    #[test]
    fn only_a_revoked_answer_locks_a_license() {
        let (pair, public) = test_keys();
        let mut state = LicenseState::new(START);
        state.machine = "m1".into();
        state.set_license("TALLY-AAAA", signed(&pair, &claims()), START);
        assert!(!state.needs_check(START + 29 * DAY_SECS));
        assert!(state.needs_check(START + 30 * DAY_SECS));

        state.record_check(CheckOutcome::Unreachable, START + 31 * DAY_SECS);
        assert!(state.needs_check(START + 31 * DAY_SECS));
        assert!(
            state
                .access("tally", &public, START + 31 * DAY_SECS)
                .is_licensed()
        );

        state.record_check(CheckOutcome::Active, START + 32 * DAY_SECS);
        assert!(!state.needs_check(START + 33 * DAY_SECS));

        state.record_check(CheckOutcome::Revoked, START + 70 * DAY_SECS);
        assert_eq!(
            state.access("tally", &public, START + 70 * DAY_SECS),
            Access::Revoked
        );
    }

    #[test]
    fn the_state_round_trips_and_a_damaged_file_starts_a_fresh_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("license.json");
        let mut state = LicenseState::new(START);
        state.observe(START + 5);
        state.save(&path).unwrap();
        assert_eq!(LicenseState::load(&path, START + 10), state);

        std::fs::write(&path, b"{not json").unwrap();
        let fresh = LicenseState::load(&path, START + 10);
        assert_eq!(fresh.trial_started, START + 10);
        assert_eq!(fresh.machine.len(), 32);
        assert_ne!(fresh.machine, state.machine);
    }
}
