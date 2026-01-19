mod host;
mod pvboot;

pub use host::LinuxContext;
pub use pvboot::Linux64BitBootContext;

#[derive(Debug, Clone)]
pub enum VCpuSetupContext {
    /// A first-time boot vcpu context.
    InitialBoot,
    /// A pvboot context.
    Linux64BitBoot(Linux64BitBootContext),
    /// A host Linux context loaded from the stack pointer when
    /// just dump from jailhouse kernel module.
    HostContext(host::LinuxContext),
}
