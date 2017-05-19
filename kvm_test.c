#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <linux/kvm.h>
#include <sys/mman.h>
#include <stdint.h>
#include <signal.h>

#define BOOKE206_MAX_TLBN 4
#define EPAPR_MAGIC (0x45504150)
#define MAS1_VALID 0x80000000

typedef struct ppcmas_tlb_t {
	uint32_t mas8;
	uint32_t mas1;
	uint64_t mas2;
	uint64_t mas7_3;
} ppcmas_tlb_t;

void print_regs(struct kvm_regs *regs) {
	int i;

	fprintf(stderr, "regs->ctr = %llx\nregs->lr = %llx\nregs->xer = %llx\nregs->msr = %llx\nregs->pc = %llx\n", regs->ctr, regs->lr, regs->xer, regs->msr, regs->pc);
	
	fprintf(stderr, "regs->srr0 = %llx\nregs->srr1 = %llx\n", regs->srr0, regs->srr1);
	
	fprintf(stderr, "regs->sprg0 = %llx\nregs->sprg1 = %llx\nregs->sprg2 = %llx\nregs->sprg3 = %llx\nregs->sprg4 = %llx\nregs->sprg5 = %llx\nregs->sprg6 = %llx\nregs->sprg7 = %llx\n", regs->sprg0, regs->sprg1, regs->sprg2, regs->sprg3, regs->sprg4, regs->sprg5, regs->sprg6, regs->sprg7);
	
	fprintf(stderr, "regs->pid = %llx\n", regs->pid);
	
	for (i = 0;i < 32; i++) {
		fprintf(stderr, "regs->gpr[%d] = %llx\n", i, regs->gpr[i]);
	}
	
	fprintf(stderr, "regs->cr = %llx\n", regs->cr);
}

int main(int argc, char *argv[])
{
	int ret = 0;
	int kvm, vmfd, vcpufd;
	int kvm_ver, kvm_ext_present;
	struct kvm_regs vcpu_regs;
	struct kvm_sregs vcpu_sregs;
	struct kvm_one_reg reg;
	uint32_t debug_inst_opcode;
	unsigned int entries = 0;
	int i;
	uint32_t bits;

	kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);

	if (-1 == kvm) {
		fprintf(stderr, "kvm open failed: %s\n", strerror(errno));
		ret = errno;
		goto kvm_fail;
	}

	kvm_ver = ioctl(kvm, KVM_GET_API_VERSION, NULL);
	if (-1 == kvm_ver) {
		fprintf(stderr, "failed to get kvm api version: %s\n", strerror(errno));
		ret = errno;
		goto kvm_ver_fail;
	}

	printf("kvm api version is: %d\n", kvm_ver);

	kvm_ext_present = ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY);
	if (-1 == kvm_ext_present) {
		fprintf(stderr, "failed to check for extensions: %s\n", strerror(errno));
		ret = errno;
		goto kvm_check_ext_fail;
	}	
	if (!kvm_ext_present) {
		fprintf(stderr, "KVM_CAP_USER_MEMORY extension not present!\n");
		ret = -1;
		goto kvm_ext_unavailable;
	}

	vmfd = ioctl(kvm, KVM_CREATE_VM, (unsigned long)0);
	if(-1 == vmfd) {
		fprintf(stderr, "could not create VM: %s\n", strerror(errno));
		ret = errno;
		goto kvm_vm_create_failed;
	}

	vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, (unsigned long)0);
	if(-1 == vcpufd) {
		fprintf(stderr, "could not create vcpu: %s\n", strerror(errno));
		ret = errno;
		goto create_vcpu_failed;
	}

	int kvm_run_mmap_size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);

	printf("kvm_run mmap size: %d\n", kvm_run_mmap_size);

	struct kvm_run *vcpu_kvm_run = mmap(NULL, kvm_run_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);
	if(0 == vcpu_kvm_run) {
		fprintf(stderr, "could not map vcpu kvm_run structure: %s\n", strerror(errno));
		ret = errno;
		goto vcpu_kvm_run_mmap_failed;
	}

	struct kvm_book3e_206_tlb_params params = {0};
	params.tlb_sizes[0] = 512;
	params.tlb_ways[0] = 4;
	params.tlb_sizes[1] = 64;
	params.tlb_ways[1] = 64;
	params.tlb_sizes[2] = 0;
	params.tlb_ways[2] = 0;
	params.tlb_sizes[3] = 0;
	params.tlb_ways[3] = 0;

	struct ppcmas_tlb_t *tlbm;
	tlbm = malloc((512 + 64) * sizeof(ppcmas_tlb_t));
	memset(tlbm, 0, (512 + 64) * sizeof(ppcmas_tlb_t));

        for(i = 0; i < 512; i++) {
		tlbm[i].mas1 &= ~MAS1_VALID;
	}

	for(i = 0; i < 64; i++) {
		tlbm[512 + i].mas1 &= ~MAS1_VALID;
	}

	struct kvm_config_tlb cfg = {0};
	cfg.array = (uintptr_t)tlbm;
	cfg.array_len = (512 + 64) * sizeof(ppcmas_tlb_t);
	cfg.params = (uintptr_t)&params;
	cfg.mmu_type = KVM_MMU_FSL_BOOKE_NOHV;

	struct kvm_enable_cap encap = {0};
	encap.cap = KVM_CAP_SW_TLB;
	encap.args[0] = (uintptr_t)&cfg;

	ret = ioctl(vcpufd, KVM_ENABLE_CAP, &encap);
	if (ret < 0) {
		fprintf(stderr, "couldn't enable KVM_CAP_SW_TLB\n");
	}

	reg.id = KVM_REG_PPC_DEBUG_INST;
	reg.addr = (uintptr_t) &debug_inst_opcode;
	ret = ioctl(vcpufd, KVM_GET_ONE_REG, &reg);
	fprintf(stderr, "ret = %d, reg = %X\n", ret, debug_inst_opcode);

	sigset_t sigset;
	sigemptyset(&sigset);

	struct kvm_signal_mask *sigmask = malloc(sizeof(struct kvm_signal_mask) + sizeof(sigset));
	sigmask->len = 8;
	memcpy(sigmask->sigset, &sigset, sizeof(sigset));

	ret = ioctl(vcpufd, KVM_SET_SIGNAL_MASK, sigmask);
	if (ret < 0) {
		fprintf(stderr, "couldn't set sigmask\n");
	}

	memset(&encap, 0, sizeof(encap));
	encap.cap = KVM_CAP_PPC_BOOKE_WATCHDOG;
	ret = ioctl(vcpufd, KVM_ENABLE_CAP, &encap);
	if (ret < 0) {
		fprintf(stderr, "Could not enable watchdog!\n");
	}

	void *guest_mem = mmap(NULL, 0x8000000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(0 == guest_mem) {
		fprintf(stderr, "could not map 4k memory block: %s\n", strerror(errno));
		ret = errno;
		goto guest_mem_map_failed;
	}

	madvise(guest_mem, 0x8000000, MADV_DONTFORK);

	memset(guest_mem, 0, 0x8000000);

	((uint32_t*)guest_mem)[0x00] = 0x38000008;
	((uint32_t*)guest_mem)[0x01] = 0x38200007;
	((uint32_t*)guest_mem)[0x02] = 0x38400006;
	((uint32_t*)guest_mem)[0x03] = 0x38600005;
	((uint32_t*)guest_mem)[0x04] = 0x7c800a14;
	((uint32_t*)guest_mem)[0x05] = debug_inst_opcode;

	fprintf(stderr, "guest mem addr = %p\n", guest_mem);

	struct kvm_userspace_memory_region region = {
		.slot = 0,
		.guest_phys_addr = 0x0,
		.userspace_addr = (uintptr_t)guest_mem,
		.flags = 0,
		.memory_size = 0x8000000,
	};

	ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);
	if(0 != ret) {
		fprintf(stderr, "could not set user memory region: %s\n", strerror(errno));
		goto set_user_mem_region_failed;
	}

	struct kvm_create_device cd = {0};
	cd.type = KVM_DEV_TYPE_FSL_MPIC_42;
       	ret = ioctl(vmfd, KVM_CREATE_DEVICE, &cd);
	if (ret < 0) {
		fprintf(stderr, "could not create device\n");
	}

	fprintf(stderr, "MPIC Device fd: %d\n", cd.fd);

	struct kvm_irq_routing *irq_routes = malloc(sizeof(struct kvm_irq_routing) + 256*sizeof(struct kvm_irq_routing_entry));

        memset(irq_routes, 0, sizeof(struct kvm_irq_routing) + 256*sizeof(struct kvm_irq_routing_entry));

	irq_routes->flags = 0;
	irq_routes->nr = 256;

	for (i = 0; i < 256; i++) {
		struct kvm_irq_routing_entry *e = &irq_routes->entries[i];

		e->type = KVM_IRQ_ROUTING_IRQCHIP;
		e->flags = 0;
		e->gsi = i;
		e->u.irqchip.irqchip = 0;
		e->u.irqchip.pin = i;
	}

	ret = ioctl(vmfd, KVM_SET_GSI_ROUTING, irq_routes);
	if (ret < 0) {
		fprintf(stderr, "could not add routes\n");
	}

	memset(&encap, 0, sizeof(encap));
	encap.cap = KVM_CAP_IRQ_MPIC;
	encap.args[0] = cd.fd;
	encap.args[1] = 0;

	ret = ioctl(vcpufd, KVM_ENABLE_CAP, &encap);
	if (ret < 0) {
		fprintf(stderr, "could not connect MPIC\n");
	}

	vcpu_sregs.u.e.features = 0;
	vcpu_sregs.u.e.features |= KVM_SREGS_E_BASE;
	vcpu_sregs.u.e.features |= KVM_SREGS_E_ARCH206;
	vcpu_sregs.u.e.features |= KVM_SREGS_E_ARCH206_MMU;
	ret = ioctl(vcpufd, KVM_GET_SREGS, &vcpu_sregs);
	if (ret < 0) {
		fprintf(stderr, "couldn't get sregs\n");
	}

	fprintf(stderr, "pvr = %x\n", vcpu_sregs.pvr);
	//ret = ioctl(vcpufd, KVM_SET_SREGS, &vcpu_sregs);
	//if (ret < 0) {
	//	fprintf(stderr, "unable to set sregs\n");
	//}

	ioctl(vcpufd, KVM_GET_REGS, &vcpu_regs);

	vcpu_regs.ctr = 0;
	vcpu_regs.lr = 0;
	vcpu_regs.xer = 0;
	vcpu_regs.msr = 0x10000000;
	vcpu_regs.pc = 0;

	vcpu_regs.srr0 = 0;
	vcpu_regs.srr1 = 0;

	vcpu_regs.sprg0 = 0;
	vcpu_regs.sprg1 = 0;
	vcpu_regs.sprg2 = 0;
	vcpu_regs.sprg3 = 0;
	vcpu_regs.sprg4 = 0;
	vcpu_regs.sprg5 = 0;
	vcpu_regs.sprg6 = 0;
	vcpu_regs.sprg7 = 0;

	vcpu_regs.pid = 0x0;

	vcpu_regs.gpr[1] = (16<<20) - 8;
	vcpu_regs.gpr[3] = 0;
	vcpu_regs.gpr[4] = 0;
	vcpu_regs.gpr[5] = 0;
	vcpu_regs.gpr[6] = EPAPR_MAGIC;
	vcpu_regs.gpr[7] = 4096;
	vcpu_regs.gpr[8] = 0;
	vcpu_regs.gpr[9] = 0;

	vcpu_regs.cr = 0x0;

	fprintf(stderr, "msr: %llx, pc: %llx\n", vcpu_regs.msr, vcpu_regs.pc);
	print_regs(&vcpu_regs);
	ioctl(vcpufd, KVM_SET_REGS, &vcpu_regs);

	uint64_t fpscr = 0;

	reg.id = KVM_REG_PPC_FPSCR;
	reg.addr = (uintptr_t)&fpscr;

	ioctl(vcpufd, KVM_SET_ONE_REG, &reg);

	unsigned char *bitmap = (unsigned char *)malloc((576+7)/8);
	memset(bitmap, 0xFF, (576+7)/8);

	tlbm[512].mas1 = MAS1_VALID | 0x800;
	tlbm[512].mas2 = 0;
	tlbm[512].mas7_3 = 0x3f;

	struct kvm_dirty_tlb dirty_tlb = {0};
	dirty_tlb.bitmap = (uintptr_t)bitmap;
	dirty_tlb.num_dirty = 576;

	ret = ioctl(vcpufd, KVM_DIRTY_TLB, &dirty_tlb);
	if (ret < 0) {
		fprintf(stderr, "could not set dirty TLB\n");
	}

	bits = 0x0;
	reg.id = KVM_REG_PPC_TCR;
	reg.addr = (uintptr_t)&bits;

	ioctl(vcpufd, KVM_SET_ONE_REG, &reg);

	bits = 0xffffffff;
	reg.id = KVM_REG_PPC_CLEAR_TSR;
	reg.addr = (uintptr_t)&bits;
	
	ioctl(vcpufd, KVM_SET_ONE_REG, &reg);

        struct kvm_irq_level irq_event = {0};
	irq_event.irq = 42;
	irq_event.level = 0;

//	if ((ret = ioctl(vmfd, KVM_IRQ_LINE, &irq_event)) < 0)
//		fprintf(stderr, "KVM_IRQ_LINE failed\n");

	bits = 0xf0000000;
	reg.id = KVM_REG_PPC_CLEAR_TSR;
	reg.addr = (uintptr_t)&bits;
	
	ioctl(vcpufd, KVM_SET_ONE_REG, &reg);

	//struct kvm_guest_debug debug = {0};
	//debug.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_SW_BP;

        //ret = ioctl(vcpufd, KVM_SET_GUEST_DEBUG, &debug);
	//if (ret < 0) {
	//	fprintf(stderr, "couldn't set guest debug\n");
	//}

	while (1) {
		ioctl(vcpufd, KVM_RUN, 0);
		fprintf(stderr, "kvm_run exit!\n");
		switch(vcpu_kvm_run->exit_reason) {
			case KVM_EXIT_HLT:
				printf("vcpu halted\n");
				break;
			case KVM_EXIT_FAIL_ENTRY:
				fprintf(stderr, "KVM_EXIT_FAIL_ENTRY: hardware entry failure reason = 0x%llx\n", (unsigned long long)vcpu_kvm_run->fail_entry.hardware_entry_failure_reason);
				break;
			case KVM_EXIT_INTERNAL_ERROR:
				fprintf(stderr, "KVM_EXIT_INTERNAL_ERROR: internal error, suberror = 0x%x\n", vcpu_kvm_run->internal.suberror);
				break;
			case KVM_EXIT_DEBUG:
				ioctl(vcpufd, KVM_GET_REGS, &vcpu_regs);
				print_regs(&vcpu_regs);
				return 0;
			default:
				break;
		}
	}

vcpu_kvm_run_mmap_failed:
	close(vcpufd);
create_vcpu_failed:

set_user_mem_region_failed:
	munmap(guest_mem, 4096);
guest_mem_map_failed:
	close(vmfd);
kvm_vm_create_failed:
	
kvm_ext_unavailable:

kvm_check_ext_fail:

kvm_ver_fail:
	close(kvm);
kvm_fail:
	return ret;
}
