use crate::dashboard::{DashboardSnapshot, unsupported_contract_message};

pub trait DashboardProvider: Send {
    fn next_snapshot(&mut self) -> Result<DashboardSnapshot, String>;

    fn next_snapshot_checked(&mut self) -> Result<DashboardSnapshot, String> {
        let snapshot = self.next_snapshot()?;
        if snapshot.supports_known_contract() {
            return Ok(snapshot);
        }
        Err(unsupported_contract_message(&snapshot))
    }
}
