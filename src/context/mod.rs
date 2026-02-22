mod ctx;
#[allow(unused)]
mod pvboot;

pub use ctx::GuestContext;

/// Context type for setting up a vCPU.
#[derive(Debug, Clone)]
pub enum VCpuSetupContext {
    /// A first-time boot vcpu context.
    InitialBoot,
    /// A host Linux context loaded from the stack pointer when
    /// just dump from jailhouse kernel module.
    HostContext(GuestContext),
    /// A paravirtualized guest context for booting via the Gate.
    PVGuestContext(GuestContext),
}
