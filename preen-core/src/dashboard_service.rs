use crate::dashboard::DashboardSnapshot;
use crate::dashboard_provider::DashboardProvider;
use crate::error::CoreError;

pub struct DashboardApplicationService {
    provider: Box<dyn DashboardProvider>,
}

impl DashboardApplicationService {
    pub fn new(provider: Box<dyn DashboardProvider>) -> Self {
        Self { provider }
    }

    pub fn next_snapshot(&mut self) -> Result<DashboardSnapshot, CoreError> {
        self.provider
            .next_snapshot_checked()
            .map_err(map_provider_error)
    }
}

fn map_provider_error(message: String) -> CoreError {
    if message.contains("unsupported dashboard snapshot contract") {
        return CoreError::Compat { message };
    }
    CoreError::Os {
        message: format!("dashboard provider failed: {message}"),
    }
}
