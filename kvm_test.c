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

struct ppcmas_tlb_t *kvm_vcpu_initialize_tlb(int vcpufd) {
	int i, ret;

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
		free(tlbm);
		tlbm = NULL;
		return NULL;
	}

	return tlbm;
}

int kvm_vcpu_get_debug_opcode(int vcpufd, uint32_t *debug_inst_opcode) {
	struct kvm_one_reg reg = {0};

	reg.id = KVM_REG_PPC_DEBUG_INST;
	reg.addr = (uintptr_t) debug_inst_opcode;
	return ioctl(vcpufd, KVM_GET_ONE_REG, &reg);
}

int kvm_vcpu_set_sigmask(int vcpufd, sigset_t *sigset) {
	struct kvm_signal_mask *sigmask = malloc(sizeof(struct kvm_signal_mask) + sizeof(sigset_t));
	// ppc kernel supports up to 64 signals
	sigmask->len = 8;
	memcpy(sigmask->sigset, sigset, sizeof(sigset_t));

	return ioctl(vcpufd, KVM_SET_SIGNAL_MASK, sigmask);
}

int kvm_vcpu_enable_watchdog(int vcpufd)
{
	struct kvm_enable_cap encap = {0};
	encap.cap = KVM_CAP_PPC_BOOKE_WATCHDOG;
	return ioctl(vcpufd, KVM_ENABLE_CAP, &encap);
}

int kvm_vm_set_user_memory_region(int vmfd, int guest_phys_addr, void *memory, size_t size)
{
	struct kvm_userspace_memory_region region = {
		.slot = 0,
		.guest_phys_addr = guest_phys_addr,
		.userspace_addr = (uintptr_t)memory,
		.flags = 0,
		.memory_size = size,
	};

	return ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);
}

int kvm_vm_create_mpic(int vmfd) {
	int ret;

	struct kvm_create_device cd = {0};
	cd.type = KVM_DEV_TYPE_FSL_MPIC_42;
       	ret = ioctl(vmfd, KVM_CREATE_DEVICE, &cd);
	if (ret < 0) return ret;

	return cd.fd;
}

int kvm_vm_set_irq_routing(int vmfd) {
	int i, ret;

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
	free(irq_routes);
	return ret;
}

int kvm_vcpu_connect_sole_mpic(int vcpufd, int mpicfd)
{
	struct kvm_enable_cap encap = {0};
	encap.cap = KVM_CAP_IRQ_MPIC;
	encap.args[0] = mpicfd;
	encap.args[1] = 0;

	return ioctl(vcpufd, KVM_ENABLE_CAP, &encap);
}

int kvm_vcpu_reset_regs(int vcpufd)
{
	int ret;
	struct kvm_regs vcpu_regs;

	ret = ioctl(vcpufd, KVM_GET_REGS, &vcpu_regs);
	if (ret < 0) return ret;

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

	return ioctl(vcpufd, KVM_SET_REGS, &vcpu_regs);
}

int kvm_vcpu_print_regs(int vcpufd) {
	int i, ret;
	struct kvm_regs regs;

	ret = ioctl(vcpufd, KVM_GET_REGS, &regs);

	if (ret < 0) return ret;

	fprintf(stderr, "regs.ctr = %llx\nregs.lr = %llx\nregs.xer = %llx\nregs.msr = %llx\nregs.pc = %llx\n", regs.ctr, regs.lr, regs.xer, regs.msr, regs.pc);
	
	fprintf(stderr, "regs.srr0 = %llx\nregs.srr1 = %llx\n", regs.srr0, regs.srr1);
	
	fprintf(stderr, "regs.sprg0 = %llx\nregs.sprg1 = %llx\nregs.sprg2 = %llx\nregs.sprg3 = %llx\nregs.sprg4 = %llx\nregs.sprg5 = %llx\nregs.sprg6 = %llx\nregs.sprg7 = %llx\n", regs.sprg0, regs.sprg1, regs.sprg2, regs.sprg3, regs.sprg4, regs.sprg5, regs.sprg6, regs.sprg7);
	
	fprintf(stderr, "regs.pid = %llx\n", regs.pid);
	
	for (i = 0; i < 32; i++) {
		fprintf(stderr, "regs.gpr[%d] = %llx\n", i, regs.gpr[i]);
	}
	
	fprintf(stderr, "regs.cr = %llx\n", regs.cr);

	return 0;
}

int kvm_vcpu_set_reg(int vcpufd, uint64_t id, uint64_t value)
{
	struct kvm_one_reg reg;

	reg.id = id;
	reg.addr = (uintptr_t)&value;

	ioctl(vcpufd, KVM_SET_ONE_REG, &reg);
}

int kvm_vcpu_invalidate_tlb_cache(int vcpufd)
{
	int ret;

	unsigned char *bitmap = (unsigned char *)malloc((576+7)/8);
	memset(bitmap, 0xFF, (576+7)/8);

	struct kvm_dirty_tlb dirty_tlb = {0};
	dirty_tlb.bitmap = (uintptr_t)bitmap;
	dirty_tlb.num_dirty = 576;

	ret = ioctl(vcpufd, KVM_DIRTY_TLB, &dirty_tlb);
	free(bitmap);

	return ret;
}

int kvm_vm_irq_line(int vmfd, int irq, int level)
{
        struct kvm_irq_level irq_event = {0};
	irq_event.irq = irq;
	irq_event.level = level;

	return ioctl(vmfd, KVM_IRQ_LINE, &irq_event);
}

int main(int argc, char *argv[])
{
	int ret = 0;
	unsigned int entries = 0;
	int i;

	int kvmfd = open("/dev/kvm", O_RDWR | O_CLOEXEC);

	if (kvmfd < 0) {
		fprintf(stderr, "kvm open failed: %s\n", strerror(errno));
		ret = errno;
		goto kvm_fail;
	}

	int kvm_ver = ioctl(kvmfd, KVM_GET_API_VERSION, NULL);
	printf("kvm api version is: %d\n", kvm_ver);
	if (kvm_ver != 12) {
		fprintf(stderr, "only version 12 is supported\n");
		ret = -1;
		goto kvm_ver_fail;
	}

	if (!ioctl(kvmfd, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY)) {
		fprintf(stderr, "KVM_CAP_USER_MEMORY extension not present!\n");
		ret = -1;
		goto kvm_ext_unavailable;
	}

	int vmfd = ioctl(kvmfd, KVM_CREATE_VM, (unsigned long)0);
	if(vmfd < 0) {
		fprintf(stderr, "could not create VM: %s\n", strerror(errno));
		ret = errno;
		goto kvm_vm_create_failed;
	}

	int vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, (unsigned long)0);
	if(vcpufd < 0) {
		fprintf(stderr, "could not create vcpu: %s\n", strerror(errno));
		ret = errno;
		goto create_vcpu_failed;
	}

	int kvm_run_mmap_size = ioctl(kvmfd, KVM_GET_VCPU_MMAP_SIZE, NULL);
	printf("kvm_run mmap size: %d\n", kvm_run_mmap_size);

	struct kvm_run *vcpu_kvm_run = mmap(NULL, kvm_run_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);
	if(0 == vcpu_kvm_run) {
		fprintf(stderr, "could not map vcpu kvm_run structure: %s\n", strerror(errno));
		ret = errno;
		goto kvm_run_mmap_failed;
	}

	struct ppcmas_tlb_t *tlb = kvm_vcpu_initialize_tlb(vcpufd);
	if (!tlb) {
		fprintf(stderr, "could not initialize tlb\n");
	}

	uint32_t debug_inst_opcode;
	if(kvm_vcpu_get_debug_opcode(vcpufd, &debug_inst_opcode) < 0) {
		fprintf(stderr, "coult not get debug opcode!\n");
	}
	fprintf(stderr, "debug_inst_opcode = %X\n", ret, debug_inst_opcode);

	sigset_t sigset;
	sigemptyset(&sigset);
	if(kvm_vcpu_set_sigmask(vcpufd, &sigset) < 0) {
		fprintf(stderr, "could not set sigmask!\n");
	}

	if(kvm_vcpu_enable_watchdog(vcpufd) < 0) {
		fprintf(stderr, "could not enable watchdog!\n");
	}

	void *guest_mem = mmap(NULL, 0x8000000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(0 == guest_mem) {
		fprintf(stderr, "could not map guest memory: %s\n", strerror(errno));
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

	if(0 != kvm_vm_set_user_memory_region(vmfd, 0x0, guest_mem, 0x8000000)) {
		fprintf(stderr, "could not set user memory region: %s\n", strerror(errno));
		goto set_user_mem_region_failed;
	}

	int mpicfd = kvm_vm_create_mpic(vmfd);
	if (mpicfd < 0) {
		fprintf(stderr, "could not create MPIC\n");
	}
	fprintf(stderr, "MPIC Device fd: %d\n", mpicfd);

	if (kvm_vm_set_irq_routing(vmfd) < 0) {
		fprintf(stderr, "could not set irq routing\n");
	}

	if (kvm_vcpu_connect_sole_mpic(vcpufd, mpicfd) < 0) {
		fprintf(stderr, "could not connect MPIC\n");
	}

	if(kvm_vcpu_reset_regs(vcpufd) < 0) {
		fprintf(stderr, "could not reset regs!\n");
	}

	if(kvm_vcpu_print_regs(vcpufd) < 0) {
		fprintf(stderr, "could not print regs!\n");
	}

	if (kvm_vcpu_set_reg(vcpufd, KVM_REG_PPC_FPSCR, 0) < 0) {
		fprintf(stderr, "could not clear FPSCR\n");
	}

	// populate single tlb entry for initial CPU run
	tlb[512].mas1 = MAS1_VALID | 0x800;
	tlb[512].mas2 = 0;
	tlb[512].mas7_3 = 0x3f;

	if (kvm_vcpu_invalidate_tlb_cache(vcpufd) < 0) {
		fprintf(stderr, "could not invalidate TLB cache\n");
	}

	if (kvm_vcpu_set_reg(vcpufd, KVM_REG_PPC_TCR, 0) < 0) {
		fprintf(stderr, "could not clear TCR\n");
	}

	if (kvm_vcpu_set_reg(vcpufd, KVM_REG_PPC_CLEAR_TSR, 0xffffffff) < 0) {
		fprintf(stderr, "could not clear TSR\n");
	}

	//if (kvm_vm_irq_line(vmfd, 42, 0) < 0) {
	//	fprintf(stderr, "could not irq line!\n");
	//}

	if (kvm_vcpu_set_reg(vcpufd, KVM_REG_PPC_CLEAR_TSR, 0xf0000000) < 0) {
		fprintf(stderr, "could not clear TSR\n");
	}

	int done = 0;
	while (!done) {
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
				kvm_vcpu_print_regs(vcpufd);
				done = 1;
				break;
			default:
				break;
		}
	}

set_user_mem_region_failed:
	munmap(guest_mem, 0x8000000);
	guest_mem = NULL;
guest_mem_map_failed:
	free(tlb);
	tlb = NULL;
	munmap(vcpu_kvm_run, kvm_run_mmap_size);
	vcpu_kvm_run = NULL;
kvm_run_mmap_failed:
	close(vcpufd);
create_vcpu_failed:
	close(vmfd);
kvm_vm_create_failed:
kvm_ext_unavailable:
kvm_ver_fail:
	close(kvmfd);
kvm_fail:
	return ret;
}
