//! Implements the format of what capabilities are returned in the threat report.
use serde::Serialize;

/// Stores and categorizes all types of capabilities that `confine` is able to detect.
#[derive(Serialize, Default)]
pub struct ThreatCapabilities {
    // Defines the capabilities that are used to evade any type of system auditing
    pub evasion: Evasion,

    // Indicators of writing configurations to persist malware after starting back up
    pub persistence: Persistence,

    // Process renaming in order to deceive the system
    pub deception: bool,
}

#[derive(Serialize, Default)]
pub struct Evasion {
    // checks if blocking calls are made
    pub stalling: bool,

    // checks if `ptrace` is used to determine if debugging is done
    pub antidebug: bool,

    // TODO: detect for anti sandboxing
    pub antisandbox: bool,

    // checks if `ptrace` is attempting inject or intrude on other processes
    pub process_infect: bool,
}

#[derive(Serialize, Default)]
pub struct Persistence {
    // set if startup service paths are interacted with
    pub init_persistence: bool,

    // set if time-based crontab paths are interacted with
    pub time_persistence: bool,

    // set if sample modifies any local user configurations
    pub config_persistence: bool,
}

impl Persistence {
    /// Given a parsed pathstring, determine if it is a commonly used path for some type of
    /// persistence strategy.
    pub fn check(&mut self, path: String) {
        // check if services are created in any known paths
        let init_persistence: Vec<&str> = vec![
            "/etc/rc.d/rc.local",
            "/etc/rc.conf",
            "/etc/init.d/",
            "/etc/rcX.d/",
            "/etc/rc.local",
        ];
        if init_persistence.iter().any(|&p| path.contains(p)) {
            self.init_persistence = true;
        }

        // check for config persistence
        let config_persistence: Vec<&str> =
            vec![".bashrc", ".bash_profile", ".zshrc", ".zsh_profile"];
        if config_persistence.iter().any(|&p| path.contains(p)) {
            self.config_persistence = true;
        }

        // check if time-based jobs are created in known paths
        let time_persistence: Vec<&str> =
            vec!["/etc/cron.hourly/", "/etc/crontab", "/etc/cron.daily/"];
        if time_persistence.iter().any(|&t| path.contains(t)) {
            self.time_persistence = true;
        }
    }
}
