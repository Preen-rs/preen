use crate::dashboard::DashboardSnapshot;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginListItemView {
    pub pack_id: String,
    pub version: String,
    pub source: String,
    pub rev: String,
    pub installed: bool,
    pub trusted_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginListView {
    pub total_plugins: usize,
    pub items: Vec<PluginListItemView>,
}

impl PluginListView {
    pub fn from_snapshot(snapshot: &DashboardSnapshot) -> Self {
        let items = snapshot
            .plugins
            .iter()
            .map(|plugin| PluginListItemView {
                pack_id: plugin.pack_id.clone(),
                version: plugin.version.clone(),
                source: plugin.source.clone(),
                rev: plugin.rev.clone(),
                installed: plugin.installed,
                trusted_identity: plugin.trusted_identity.clone(),
            })
            .collect::<Vec<_>>();

        Self {
            total_plugins: items.len(),
            items,
        }
    }
}
