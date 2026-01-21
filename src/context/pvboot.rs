use alloc::vec;
use alloc::vec::Vec;
use core::mem;

use x86::segmentation::SegmentSelector;
use x86::{Ring, segmentation, task};
use x86_64::VirtAddr;
use x86_64::instructions::tables::{lgdt, lidt, sidt};
use x86_64::registers::control::{Cr0, Cr0Flags, Cr3, Cr3Flags, Cr4, Cr4Flags, Efer, EferFlags};
use x86_64::structures::DescriptorTablePointer;
use x86_64::{addr::PhysAddr, structures::paging::PhysFrame};

use crate::generated::msr_index::*;
use crate::msr::Msr;
use crate::regs::GeneralRegisters;
use crate::segmentation::{Segment, SegmentAccessRights};

const SAVED_LINUX_REGS: usize = 8;

const BOOT_RFLAGS: u64 = 0x0000_0000_0000_0002u64;
/// Initial stack for the boot CPU.
const BOOT_STACK_POINTER: u64 = 0x8ff0;

/// The 'zero page', a.k.a linux kernel bootparams.
const ZERO_PAGE_START: u64 = 0x7000;

const BOOT_GDT_OFFSET: u64 = 0x500;
const BOOT_IDT_OFFSET: u64 = 0x520;

const BOOT_GDT_MAX: usize = 4;

const EFER_LMA: u64 = 0x400;
const EFER_LME: u64 = 0x100;

const X86_CR0_PE: u64 = 0x1;
const X86_CR0_ET: u64 = 0x10;
const X86_CR0_PG: u64 = 0x8000_0000;
const X86_CR4_PAE: u64 = 0x20;

// Initial pagetables.
const PML4_START: u64 = 0x9000;

#[derive(Clone)]
pub struct Linux64BitBootContext {
    // General purpose registers
    pub rsp: u64,
    pub rip: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rflags: u64,

    // Segment registers
    pub es: Segment,
    pub cs: Segment,
    pub ss: Segment,
    pub ds: Segment,
    pub fs: Segment,
    pub gs: Segment,
    pub tss: Segment,
    // Descriptor tables
    pub gdt: DescriptorTablePointer,
    pub idt: DescriptorTablePointer,

    // Control registers & special registers
    pub cr0: Cr0Flags,
    pub cr3: u64,
    pub cr4: Cr4Flags,
    pub efer: EferFlags,

    // Model specific registers
    pub msr_entries: Vec<MsrEntry>,

    // Floating-Point Unit (FPU) registers
    pub fcw: u16,
    pub mxcsr: u32,
}

impl core::fmt::Debug for Linux64BitBootContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "Linux64BitBootContext {{")?;
        writeln!(f, "  rsp: {:#x}", self.rsp)?;
        writeln!(f, "  rip: {:#x}", self.rip)?;
        writeln!(f, "  rbp: {:#x}", self.rbp)?;
        writeln!(f, "  rsi: {:#x}", self.rsi)?;
        writeln!(f, "  rflags: {:#x}", self.rflags)?;
        writeln!(f, "  cs: {}", self.cs)?;
        writeln!(f, "  ds: {}", self.ds)?;
        writeln!(f, "  es: {}", self.es)?;
        writeln!(f, "  fs: {}", self.fs)?;
        writeln!(f, "  gs: {}", self.gs)?;
        writeln!(f, "  ss: {}", self.ss)?;
        writeln!(f, "  tss: {}", self.tss)?;
        writeln!(f, "  gdt: {:?}", self.gdt)?;
        writeln!(f, "  idt: {:?}", self.idt)?;
        writeln!(f, "  cr0: {:#x} {:?}", self.cr0.bits(), self.cr0)?;
        writeln!(f, "  cr3: {:#x}", self.cr3)?;
        writeln!(f, "  cr4: {:?}", self.cr4)?;
        writeln!(f, "  efer: {:?}", self.efer)?;
        writeln!(f, "  msr_entries: {:?}", self.msr_entries)?;
        writeln!(f, "  fcw: {:#x}", self.fcw)?;
        writeln!(f, "  mxcsr: {:#x}", self.mxcsr)?;
        writeln!(f, "}}")
    }
}

/// Constructor for a conventional segment GDT (or LDT) entry. Derived from the kernel's segment.h.
pub fn gdt_entry(flags: u16, base: u32, limit: u32) -> u64 {
    ((u64::from(base) & 0xff00_0000u64) << (56 - 24))
        | ((u64::from(flags) & 0x0000_f0ffu64) << 40)
        | ((u64::from(limit) & 0x000f_0000u64) << (48 - 16))
        | ((u64::from(base) & 0x00ff_ffffu64) << 16)
        | (u64::from(limit) & 0x0000_ffffu64)
}

impl Default for Linux64BitBootContext {
    fn default() -> Self {
        let gdt_table: [u64; BOOT_GDT_MAX] =
            // Configure GDT entries as specified by Linux 64bit boot protocol
            [
                gdt_entry(0, 0, 0),            // NULL
                gdt_entry(0xa09b, 0, 0xfffff), // CODE
                gdt_entry(0xc093, 0, 0xfffff), // DATA
                gdt_entry(0x808b, 0, 0xfffff), // TSS
            ];

        let code_seg = Segment::from_raw_entry_value(gdt_table[1], 1);
        let data_seg = Segment::from_raw_entry_value(gdt_table[2], 2);
        let tss_seg = Segment::from_raw_entry_value(gdt_table[3], 3);

        Self {
            rsp: BOOT_STACK_POINTER,
            rip: 0,
            rbp: BOOT_STACK_POINTER,
            rsi: ZERO_PAGE_START,
            rflags: BOOT_RFLAGS,
            cs: code_seg,
            ds: data_seg,
            es: data_seg,
            fs: data_seg,
            gs: data_seg,
            ss: data_seg,
            tss: tss_seg,
            gdt: DescriptorTablePointer {
                limit: u16::try_from(mem::size_of_val(&gdt_table)).unwrap() - 1,
                base: VirtAddr::new(BOOT_GDT_OFFSET),
            },
            idt: DescriptorTablePointer {
                limit: u16::try_from(mem::size_of::<u64>()).unwrap() - 1,
                base: VirtAddr::new(BOOT_IDT_OFFSET),
            },
            cr0: Cr0Flags::EXTENSION_TYPE
                | Cr0Flags::PROTECTED_MODE_ENABLE
                | Cr0Flags::PAGING
                | Cr0Flags::NOT_WRITE_THROUGH
                | Cr0Flags::CACHE_DISABLE,
            cr3: PML4_START,
            cr4: Cr4Flags::PHYSICAL_ADDRESS_EXTENSION,
            efer: EferFlags::LONG_MODE_ENABLE | EferFlags::LONG_MODE_ACTIVE,
            msr_entries: create_boot_msr_entries(),
            fcw: 0x37f,
            mxcsr: 0x1f80,
        }
    }
}

impl Linux64BitBootContext {
    pub fn set_rip(&mut self, rip: u64) {
        self.rip = rip;
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct MsrEntry {
    pub index: Msr,
    pub data: u64,
}

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
