//! Boot context definitions for x86_64 virtual machines.
//!
//! This module provides two types of boot contexts:
//! - `Linux64BitBootContext`: Standard Linux 64-bit boot protocol context
//! - `ParavirtBootContext`: Paravirtualized boot context with shared GDT/IDT/TSS
//!
//! The paravirt context is designed for fast guest switching using VMFUNC EPTP switching.

use alloc::vec;
use alloc::vec::Vec;
use axaddrspace::{GuestPhysAddr, HostPhysAddr};
use core::mem;

use x86::Ring;
use x86::segmentation::SegmentSelector;
use x86_64::VirtAddr;
use x86_64::registers::control::{Cr0Flags, Cr4Flags, EferFlags};
use x86_64::structures::DescriptorTablePointer;

use crate::generated::msr_index::*;
use crate::msr::{Msr, MsrEntry};
use crate::segmentation::{Segment, SegmentAccessRights};

// ============================================================================
// Standard Linux 64-bit Boot Protocol Constants
// ============================================================================

pub const BOOT_RFLAGS: u64 = 0x0000_0000_0000_0002u64;
/// Initial stack for the boot CPU.
pub const BOOT_STACK_POINTER: u64 = 0x8ff0;

/// The 'zero page', a.k.a linux kernel bootparams.
pub const ZERO_PAGE_START: u64 = 0x7000;

pub const BOOT_GDT_OFFSET: u64 = 0x500;
pub const BOOT_IDT_OFFSET: u64 = 0x520;

pub const BOOT_GDT_MAX: usize = 4;

const EFER_LMA: u64 = 0x400;
const EFER_LME: u64 = 0x100;

const X86_CR0_PE: u64 = 0x1;
const X86_CR0_ET: u64 = 0x10;
const X86_CR0_PG: u64 = 0x8000_0000;
const X86_CR4_PAE: u64 = 0x20;

// Initial pagetables.
pub(super) const PML4_START: u64 = 0x9000;

// ============================================================================
// Paravirt Boot Protocol Constants
// ============================================================================

/// Magic number for paravirt shared info validation: "AXPV" in little-endian
pub const PV_SHARED_INFO_MAGIC: u32 = 0x5650_5841;

/// Version of the paravirt shared info structure
pub const PV_SHARED_INFO_VERSION: u32 = 1;

/// Creates and populates required MSR entries for booting Linux on X86_64.
pub fn create_boot_msr_entries() -> Vec<MsrEntry> {
    let msr_entry_default = |msr| MsrEntry {
        index: msr,
        data: 0x0,
    };

    vec![
        msr_entry_default(Msr::IA32_SYSENTER_CS),
        msr_entry_default(Msr::IA32_SYSENTER_ESP),
        msr_entry_default(Msr::IA32_SYSENTER_EIP),
        // x86_64 specific msrs, we only run on x86_64 not x86.
        msr_entry_default(Msr::STAR),
        msr_entry_default(Msr::CSTAR),
        msr_entry_default(Msr::KERNEL_GSBASE),
        msr_entry_default(Msr::SYSCALL_MASK),
        msr_entry_default(Msr::LSTAR),
        // end of x86_64 specific code
        msr_entry_default(Msr::IA32_TSC),
        MsrEntry {
            index: Msr::IA32_MISC_ENABLE,
            data: u64::from(MSR_IA32_MISC_ENABLE_FAST_STRING),
        },
        // set default memory type for physical memory outside configured
        // memory ranges to write-back by setting MTRR enable bit (11) and
        // setting memory type to write-back (value 6).
        // https://wiki.osdev.org/MTRR
        MsrEntry {
            index: Msr::MTRR_DEF_TYPE,
            data: (1 << 11) | 0x6,
        },
    ]
}

/// Per-vCPU information shared between Gate and Linux.
/// This structure is used for communication about vCPU state.
/// Size: 64 bytes (cache-line aligned for performance)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PvVcpuInfo {
    /// vCPU state (see PV_VCPU_STATE_* constants)
    pub state: u32,
    /// Pending events bitmap
    pub pending_events: u32,
    /// GS base register value (per-CPU data pointer)
    pub gs_base: u64,
    /// FS base register value (TLS pointer)
    pub fs_base: u64,
    /// Kernel GS base (for swapgs)
    pub kernel_gs_base: u64,
    /// Reserved for future use (padding to 64 bytes)
    pub _reserved: [u64; 4],
}

/// vCPU state: offline
pub const PV_VCPU_STATE_OFFLINE: u32 = 0;
/// vCPU state: online and ready to run
pub const PV_VCPU_STATE_ONLINE: u32 = 1;
/// vCPU state: currently running
pub const PV_VCPU_STATE_RUNNING: u32 = 2;
/// vCPU state: idle (no tasks)
pub const PV_VCPU_STATE_IDLE: u32 = 3;
/// vCPU state: parked (yielded CPU)
pub const PV_VCPU_STATE_PARKED: u32 = 4;

/// Shared information structure between Gate and Linux guests.
/// This structure is placed at a fixed guest physical address (PV_SHARED_INFO_GPA).
///
/// The Gate initializes this structure before switching to Linux.
/// Linux reads from it to get configuration and writes to it to communicate with Gate.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct PvSharedInfo {
    /// Magic number for validation: PV_SHARED_INFO_MAGIC ("AXPV")
    pub magic: u32,
    /// Version of this structure: PV_SHARED_INFO_VERSION
    pub version: u32,
    /// Unique ID for this guest instance
    pub id: u32,

    /// Maximum number of vCPUs configured for this guest
    pub max_vcpus: u32,
    /// Currently online vCPUs
    pub online_vcpus: u32,

    /// Flags (see PV_SHARED_FLAG_* constants)
    pub flags: u32,
    /// Reserved for alignment
    pub _reserved1: u32,

    /// Guest virtual address of the shared GDT
    pub gdt_vaddr: u64,
    /// Guest virtual address of the shared IDT
    pub idt_vaddr: u64,
    /// Guest virtual address of the per-guest TSS
    pub tss_vaddr: u64,
    /// Guest physical address of boot_params (zero page)
    pub boot_params_gpa: u64,

    /// Linux kernel entry point virtual address
    pub linux_entry: u64,
    /// Linux CR3 (page table root physical address)
    pub linux_cr3: u64,
    /// Linux initial stack pointer
    pub linux_rsp: u64,
    /// Linux kernel command line physical address
    pub cmdline_gpa: u64,

    /// Per-vCPU information array
    pub vcpu_info: [PvVcpuInfo; 32],

    /// Reserved space for future extensions
    pub _reserved2: [u64; 32],
}

/// Flag: Gate has finished initialization
pub const PV_SHARED_FLAG_GATE_READY: u32 = 1 << 0;
/// Flag: Linux should skip GDT initialization
pub const PV_SHARED_FLAG_SKIP_GDT_INIT: u32 = 1 << 1;
/// Flag: Linux should skip IDT initialization
pub const PV_SHARED_FLAG_SKIP_IDT_INIT: u32 = 1 << 2;
/// Flag: Linux should skip TSS initialization
pub const PV_SHARED_FLAG_SKIP_TSS_INIT: u32 = 1 << 3;
/// Flag: Linux should skip LAPIC initialization
pub const PV_SHARED_FLAG_SKIP_LAPIC_INIT: u32 = 1 << 4;

impl PvSharedInfo {
    /// Validate the magic number and version.
    pub fn is_valid(&self) -> bool {
        self.magic == PV_SHARED_INFO_MAGIC && self.version == PV_SHARED_INFO_VERSION
    }

    /// Check if a specific flag is set.
    pub fn has_flag(&self, flag: u32) -> bool {
        self.flags & flag != 0
    }

    /// Set a flag.
    pub fn set_flag(&mut self, flag: u32) {
        self.flags |= flag;
    }

    /// Clear a flag.
    pub fn clear_flag(&mut self, flag: u32) {
        self.flags &= !flag;
    }
}
