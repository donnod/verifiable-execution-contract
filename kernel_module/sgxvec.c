#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <asm/io.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <linux/types.h>
#include <asm/cacheflush.h>
#include <asm/cpufeature.h>

#ifndef __KERNEL__
#define __KERNEL__
#endif

struct task_struct* task;

#define DISABLE_APIC_CMD 0
#define ENABLE_APIC_CMD 1

typedef struct sgx_cat_cmd {
    int mode;
    int cpuid;
} sgx_cat_cmd;

void vec_disable_apic(void * info) {
  unsigned int v;
  v = apic_read(APIC_SPIV);
  v &= ~(APIC_SPIV_APIC_ENABLED);
  apic_write(APIC_SPIV, v);
}

void vec_enable_apic(void * info) {
  unsigned int v;
  v = apic_read(APIC_SPIV);
  v |= (APIC_SPIV_APIC_ENABLED);
  apic_write(APIC_SPIV, v);
}

ssize_t my_proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *data)
{
  sgx_cat_cmd buf;
  if (count != sizeof(sgx_cat_cmd))
    return -EINVAL;
  if (copy_from_user(&buf, buffer, count)) {
    return -EFAULT;
  }
  printk("SGXVEC mode %d cpuid %d, run on core %d\n", buf.mode, buf.cpuid, smp_processor_id());
  task = current;
  switch(buf.mode) {
    case (DISABLE_APIC_CMD):
      smp_call_function_single(buf.cpuid, vec_disable_apic, 0, 1);
      break;
    case (ENABLE_APIC_CMD):
      smp_call_function_single(buf.cpuid, vec_enable_apic, 0, 1);
      break;
    default:
      printk("[!]Unknown instruction.\n");
      break;
  }
  return count;
}

int __init init_SGXVEC(void)
{
  struct proc_dir_entry *my_proc_file = NULL;

  static const struct file_operations my_proc_fops = {
    .owner = THIS_MODULE,
    .write = my_proc_write,
  };
  my_proc_file = proc_create("sgxvec", S_IRUSR |S_IWUSR | S_IRGRP | S_IROTH |  S_IWOTH, NULL, &my_proc_fops);
  if(my_proc_file == NULL)
    return -ENOMEM;

  printk("SGXVEC Module Init.\n");
  return 0;
}

void __exit exit_SGXVEC(void)
{
  remove_proc_entry("sgxvec", NULL);
  printk("SGXVEC Module Exit.\n");
}

module_init(init_SGXVEC);
module_exit(exit_SGXVEC);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("A kernel module: SGXVEC");
