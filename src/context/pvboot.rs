//! Boot context definitions for x86_64 virtual machines.
//!
//! This module provides two types of boot contexts:
//! - `Linux64BitBootContext`: Standard Linux 64-bit boot protocol context
//! - `ParavirtBootContext`: Paravirtualized boot context with shared GDT/IDT/TSS
//!
//! The paravirt context is designed for fast guest switching using VMFUNC EPTP switching.

use alloc::vec;
use alloc::vec::Vec;

use crate::generated::msr_index::*;
use crate::msr::{Msr, MsrEntry};

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
