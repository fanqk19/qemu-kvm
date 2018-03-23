#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <sys/mman.h>
#include <linux/kvm.h>
#include <linux/errno.h>

#define KVM_API_VERSION 12
#define RAM_SIZE 128000000
#define VCPU_ID 0

#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, fmt, ## __VA_ARGS__); } while (0)

// accel/kvm/kvm-all.c KVMState
struct KVMState {
   int fd;
   int vmfd;
};

// include/sysemu/kvm_int.h KVMSlot
typedef struct KVMSlot
{
    uint64_t start_addr;
    uint64_t memory_size;
    void *ram;
    int slot;
    int flags;
} KVMSlot;

// include/qom/cpu.h CPUState
// target/i386/cpu.h X86CPU
typedef struct CPUState {
    int kvm_fd;
    struct kvm_run *kvm_run;
} X86CPU;

struct KVMState *kvm_state;

// target/i386/kvm.c kvm_put_sregs
static int kvm_put_sregs(X86CPU *cpu) {
    struct kvm_sregs sregs;
    if (ioctl(cpu->kvm_fd, KVM_GET_SREGS, &sregs) < 0) {
        fprintf(stderr, "KVM_GET_SREGS failed\n");
        exit(1);
    }
    sregs.cs.base = 0x1000;
    if (ioctl(cpu->kvm_fd, KVM_SET_SREGS, &sregs) < 0) {
        fprintf(stderr, "KVM_SET_SREGS failed\n");
        exit(1);
    }
}

// target/i386/kvm.c kvm_getput_regs
static int kvm_getput_regs(X86CPU *cpu, int set) {
    if(set) {
        struct kvm_regs regs;
        regs.rflags = 0x2;
        if (ioctl(cpu->kvm_fd, KVM_SET_REGS, &regs) < 0) {
            fprintf(stderr, "KVM_SET_REGS failed\n");
            exit(1);
        }
    }
}

// target/i386/kvm.c kvm_arch_put_registers
int kvm_arch_put_registers(struct CPUState *cpu) {
    int ret = 0;
    kvm_put_sregs(cpu);
    kvm_getput_regs(cpu, 1);
    return ret;
}

/******************************************************************************/
/*kvm-all*/
/******************************************************************************/

// accel/kvm/kvm-all.c kvm_init_vcpu
int kvm_init_vcpu(struct CPUState *cpu) {
    int ret = 0;
    long mmap_size;

    cpu->kvm_fd = ioctl(kvm_state->vmfd, KVM_CREATE_VCPU, VCPU_ID);
    if (cpu->kvm_fd < 0) {
        fprintf(stderr, "kvm_create_vcpu failed\n");
        ret = -1;
        goto err;
    }

    mmap_size = ioctl(kvm_state->fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (mmap_size < 0) {
        ret = mmap_size;
        fprintf(stderr, "KVM_GET_VCPU_MMAP_SIZE failed\n");
        goto err;
    }

    cpu->kvm_run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                        cpu->kvm_fd, 0);
    if (cpu->kvm_run == MAP_FAILED) {
        ret = -1;
        fprintf(stderr, "mmap'ing vcpu state failed\n");
        goto err;
    }

    return ret;
err:
    if (cpu->kvm_fd >= 0) {
        close(cpu->kvm_fd);
    }
    return ret;
}

// accel/kvm/kvm-all.c kvm_cpu_exec
int kvm_cpu_exec(struct CPUState *cpu)
{
    struct kvm_run *run = cpu->kvm_run;
    int ret, run_ret;
    kvm_arch_put_registers(cpu);
    do{
        sleep(1);
        DPRINTF("start KVM_RUN\n"); 
        run_ret = ioctl(cpu->kvm_fd, KVM_RUN, 0);
        if (run_ret < 0) {
            fprintf(stderr, "error: kvm run failed %s\n",
                    strerror(-run_ret));
            ret = -1;
            break;
        }

        switch (run->exit_reason) {
        case KVM_EXIT_IO:
            DPRINTF("handle_io\n");
            DPRINTF("out port: %d, data: %d\n",
                   run->io.port,  
                   *(int *)((char *)run + run->io.data_offset));
            ret = 0;
            break;
        case KVM_EXIT_MMIO:
            DPRINTF("handle_mmio\n");
            ret = 0;
            break;
        case KVM_EXIT_IRQ_WINDOW_OPEN:
            DPRINTF("irq_window_open\n");
            ret = -1;
            break;
        case KVM_EXIT_SHUTDOWN:
            DPRINTF("shutdown\n");
            ret = -1;
            break;
        case KVM_EXIT_UNKNOWN:
            fprintf(stderr, "KVM: unknown exit, hardware reason  %" PRIx64 "\n",
                    (uint64_t)run->hw.hardware_exit_reason);
            ret = -1;
            break;
        case KVM_EXIT_INTERNAL_ERROR:
            DPRINTF("internal_error\n");
            break;
        case KVM_EXIT_SYSTEM_EVENT:
            DPRINTF("system_event\n");
            break;
        default:
            DPRINTF("kvm_arch_handle_exit\n");
            break;
        }
    }while (ret == 0);

    return ret;
}

// accel/kvm/kvm-all.c kvm_destroy_vcpu
int kvm_destroy_vcpu(struct CPUState *cpu) {
    int ret = 0;
    long mmap_size;

    mmap_size = ioctl(kvm_state->fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (mmap_size < 0) {
        ret = mmap_size;
        fprintf(stderr, "KVM_GET_VCPU_MMAP_SIZE failed\n");
        goto err;
    }

    ret = munmap(cpu->kvm_run, mmap_size);
    if (ret < 0) {
        goto err;
    }

err:
    close(cpu->kvm_fd);
    return ret;
}

// vl.c                   main ->
// cccel/accel.c          configure_accelerator -> accel_init_machine -> 
// accel/kvm/kvm-all.c    init_machine -> kvm_init
static int kvm_init() {
    int ret;
    //open /dev/kvm
    kvm_state->fd = open("/dev/kvm", O_RDWR);
    if (kvm_state->fd < 0) {
        fprintf(stderr, "Could not access KVM kernel module\n");
        return -1;
    }

    //check api version
    if (ioctl(kvm_state->fd, KVM_GET_API_VERSION, 0) != KVM_API_VERSION) {
        fprintf(stderr, "kvm version not supported\n");
        return -1;
    }

    //create vm
    do {
        ret = ioctl(kvm_state->fd, KVM_CREATE_VM, 0);
    } while (ret == -EINTR);
    if (ret < 0) {
        fprintf(stderr, "ioctl(KVM_CREATE_VM) failed: %d %s\n", -ret,
                strerror(-ret));
        return -1;
    }
    kvm_state->vmfd = ret;
}

// accel/kvm/kvm-all.c kvm_set_user_memory_region
static int kvm_set_user_memory_region(KVMSlot *slot) {
    int ret = 0;
    struct kvm_userspace_memory_region mem;

    mem.flags = slot->flags;
    mem.slot = slot->slot;
    mem.guest_phys_addr =  slot->start_addr;
    mem.memory_size = slot->memory_size;
    mem.userspace_addr = (unsigned long)slot->ram;

    ret = ioctl(kvm_state->vmfd, KVM_SET_USER_MEMORY_REGION, &mem);
    return ret;
}

/******************************************************************************/
/*cpus*/
/******************************************************************************/

// cpus.c qemu_kvm_cpu_thread_fn
static void *qemu_kvm_cpu_thread_fn(void *arg)
{
    int ret = 0;
    struct CPUState *cpu = arg;

    ret = kvm_init_vcpu(cpu);
    if (ret < 0) {
        fprintf(stderr, "kvm_init_vcpu failed: %s", strerror(-ret));
        exit(1);
    }

    kvm_cpu_exec(cpu);
    kvm_destroy_vcpu(cpu);
}

// cpus.c qemu_kvm_start_vcpu
void qemu_kvm_start_vcpu(struct CPUState *vcpu) {
    pthread_t vcpu_thread;
    if (pthread_create(&(vcpu_thread), (const pthread_attr_t *)NULL, qemu_kvm_cpu_thread_fn, vcpu) != 0) {
        fprintf(stderr, "can not create kvm cpu thread\n");
        exit(1);
    }

    pthread_join(vcpu_thread, NULL);
}

// hw/i386/pc_piix.c   DEFINE_I440FX_MACHINE -> pc_init1 ->
// hw/i386/pc.c        pc_cpus_init -> pc_new_cpu -> 
// target/i386/cpu.c   x86_cpu_realizefn ->
// cpus.c              qemu_init_vcpu 
void qemu_init_vcpu(struct CPUState *cpu) {
    qemu_kvm_start_vcpu(cpu);
}

/******************************************************************************/
/*main*/
/******************************************************************************/

// hw/core/loader.c rom_add_file
int rom_add_file(uint64_t ram_start, uint64_t ram_size, char *file) {
    int ret = 0;
    int fd = open(file, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "Could not open option rom '%s'\n", file);
        ret = -1;
        goto err;
    }
    int datasize = lseek(fd, 0, SEEK_END);
    if (datasize == -1) {
        fprintf(stderr, "rom: file %-20s: get size error\n", file);
        ret = -1;
        goto err;
    }
    if (datasize > ram_size) {
        fprintf(stderr, "rom: file %-20s: datasize=%d > ramsize=%zd)\n",
                file, datasize, ram_size);
        ret = -1;
        goto err;
    }
    lseek(fd, 0, SEEK_SET);
    int rc = read(fd, ram_start, datasize);
    if (rc != datasize) {
        fprintf(stderr, "rom: file %-20s: read error: rc=%d (expected %zd)\n",
                file, rc, datasize);
        ret = -1;
        goto err;
    }
err:
    if (fd != -1)
        close(fd);
    return ret;
}

int mem_init(struct KVMSlot *slot, char *file) {
    slot->ram = mmap(NULL, slot->memory_size, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                                  -1, 0);
    if ((void *)slot->ram == MAP_FAILED) {
        fprintf(stderr, "mmap vm ram failed\n");
        return -1;
    }

    //set vm's mem region
    if (kvm_set_user_memory_region(slot) < 0) {
        fprintf(stderr, "set user memory region failed\n");
        return -1;
    }

    //load binary to vm's ram
    if (rom_add_file((uint64_t)slot->ram, slot->memory_size, file) < 0) {
        fprintf(stderr, "load rom file failed\n");
        return -1;
    }
}

int main(int argc, char **argv) {
    kvm_state = malloc(sizeof(struct KVMState));
    struct CPUState *vcpu = malloc(sizeof(struct CPUState));
    struct KVMSlot *slot = malloc(sizeof(struct KVMSlot));
    slot->memory_size = RAM_SIZE;
    slot->start_addr = 0;
    slot->slot = 0;

    kvm_init();
    mem_init(slot, argv[1]);
    qemu_init_vcpu(vcpu);

    munmap((void *)slot->ram, slot->memory_size);
    close(kvm_state->vmfd);
    close(kvm_state->fd);
    free(slot);
    free(vcpu);
    free(kvm_state);
}
