# KVM PPC minimal VM example

This example demonstrates using the KVM API directly to launch a VM on PowerPC Book3E processor, specifically the e5500 running a 32-bit Linux host. The inspiration came from [Using the KVM API](https://lwn.net/Articles/658511/), an article published on https://lwn.net. The article covered creating a VM on the x86, and the PowerPC Book3E differed slightly so I used QEMU as my source of information along with reference manuals. The repository is staging ground for eventually adding support to our fork of [kvmtool](https://github.com/ThalesIgnite/kvmtool), branch powerpc_book3e, so both repostiories are covered here, highlighting when something only applies to one.

## e5500

"The PowerPC e5500 is a 64-bit Power Architecture-based microprocessor core from Freescale Semiconductor." - [Wikipedia on PowerPC e5500](https://en.wikipedia.org/wiki/PowerPC_e5500). It implements the [Power ISA v2.06](https://en.wikipedia.org/wiki/Power_Architecture#Power_ISA_v.2.06) along with [Book III-E/Book3E/BookE extensions for virtualization](https://en.wikipedia.org/wiki/Power_Architecture#Books) for the embedded side. This is not to be confused with the orthogonal Book III-S/Book3S/BookS extensions for virtualization for the server side. The two specifications differ enough not to be compatible at all. The two have two different Power Architecture Platform Reference ([ePAPR](https://elinux.org/images/c/cf/Power_ePAPR_APPROVED_v1.1.pdf) and sPAPR) specifying booting requirements, procedures and hypercalls.

## Prerequisites

The kernel needs to be compiled with Virtualization support (CONFIG_VIRTUALIZATION=y, KVM_E500MC=y), and KVM in-kernel MPIC emulation (KVM_MPIC=y) - more on this below.

### Additional details

QEMU command I used to run VMs was:
```
qemu-system-ppc64 -enable-kvm -M ppce500 -kernel uImage -serial stdio -initrd rootfs.cpio
```

with uImage and rootfs.cpio being my built kernel and initramfs, respectively. The versions used were:
- Freescale Yocto 1.7 QEMU
- uImage built from [Freescale/linux-fslc](https://github.com/Freescale/linux-fslc.git), branch 4.8.x+fslc, commit 6a4464c7a4cfcab719eab54a98e34f7c61efc5e6
- rootfs.cpio built from buildroot-2016.08.1 (available from https://buildroot.org/)

### MPIC Emulation

MPIC is the programmable interrupt controller and is a derivative specification of the OpenPIC specification - [Wikipedia on OpenPIC and MPIC](https://en.wikipedia.org/wiki/OpenPIC_and_MPIC) with some differences for the Freescale implementation - [Kernel Documentation on Freescale MPIC Interrupt Controller Node](https://elixir.bootlin.com/linux/v4.16-rc3/source/Documentation/devicetree/bindings/powerpc/fsl/mpic.txt). Freescale MPIC interrupt controller doesn't support virtualization and must be emulated, either in the userspace application or in the host kernel. Since there's already in-kernel emulation support, it's better to use it than copy QEMU's userspace emulation.

## Simple program execution

The significantly differing bit to the x86 example in the LWN article - [Using the KVM API](https://lwn.net/Articles/658511/) - is the initializtion of the TLB, marking a region RWX for both user and supervisor/kernel modes:

```
struct ppcmas_tlb_t *tlb = kvm_vcpu_initialize_tlb(vcpufd);
...
// populate single tlb entry for initial CPU run
// qemu also chose 512
tlb[512].mas1 = MAS1_VALID | (0 << MAS1_TSIZE_SHIFT);
tlb[512].mas2 = 0;
tlb[512].mas7_3 = MAS3_UR | MAS3_UW | MAS3_UX | MAS3_SR | MAS3_SW | MAS3_SX;

if (kvm_vcpu_invalidate_tlb_cache(vcpufd) < 0) {
	fprintf(stderr, "could not invalidate TLB cache\n");
}
```

## Booting Linux as a guest (kvmtool specific)

Linux requires following the [ePAPR specification](https://elinux.org/images/c/cf/Power_ePAPR_APPROVED_v1.1.pdf), this means predefined register values and an initilized FDT - [Flattened Device Tree](https://elinux.org/Device_Tree_Reference#FDT_format) - in memory. This is described in section 5.4.1 Boot CPU Initial Register State, e.g. R3 shall contain the Effective address of the device tree image, and this address shall be 8 bytes aligned in memory. [head_fsl_booke.S](https://elixir.bootlin.com/linux/v4.16-rc3/source/arch/powerpc/kernel/head_fsl_booke.S) details the startup code using this information. This code gets loaded to the U-boot specified load address, in our case 0x0.

## State of the repositories

### This repo

The code is good enough to run basic programs.

### kvmtool

The code is good enough to run basic programs and can execute the initial stages of booting Linux from an uImage.

## Known caveats

- Although ePAPR mentions hypercalls, I haven't seen this working when trying it (i.e. it didn't trigger an VMEXIT into the application):
  ```
  sc 1
  ```
  Note that I have tried to follow [Documentation/virtual/kvm/ppc-pv.txt](https://elixir.bootlin.com/linux/v4.16-rc3/source/Documentation/virtual/kvm/ppc-pv.txt)
- ldx command is not emulated by the host kernel, you will get here [arch/powerpc/kvm/powerpc.c#L317](https://elixir.bootlin.com/linux/v4.16-rc3/source/arch/powerpc/kvm/powerpc.c#L317) even with the latest kernels.
- kvmtool does not have a gdb stub so debugging is what you bring with you
- kvmtool support virtio console and U6_16550A (which requires IO). It may not be possible to use virtio console early on and  as PowerPC doesn't support IO (only MMIO), it may be neccessary to add a new serial driver for ns16550 to kvmtool.

## Suggestions

- Use a Python GDB script to print the regs out in the same format to help compare traces between GDB debugging a QEMU running kernel and kvmtool running kernel
- Make use of Early debugging console (PPC_EARLY_DEBUG) which is an in-memory console

## References

1. KVM documenation - [Documentation/virtual/kvm](https://elixir.bootlin.com/linux/v4.16-rc3/source/Documentation/virtual/kvm)
1. Flattened Device Tree - https://elinux.org/Device_Tree_Reference#FDT_format
1. Book E: Enhanced PowerPC Architecture - https://www.nxp.com/docs/en/user-guide/BOOK_EUM.pdf
1. EREF: A Programmer’s Reference Manual for Freescale Power Architecture Processors - https://www.nxp.com/files-static/32bit/doc/ref_manual/EREF_RM.pdf
1. ePAPR specification - https://elinux.org/images/c/cf/Power_ePAPR_APPROVED_v1.1.pdf
1. Using the KVM API - https://lwn.net/Articles/658511/
1. OpenPIC and MPIC - https://en.wikipedia.org/wiki/OpenPIC_and_MPIC
1. Freescale MPIC Interrupt Controller Node - https://elixir.bootlin.com/linux/v4.16-rc3/source/Documentation/devicetree/bindings/powerpc/fsl/mpic.txt
