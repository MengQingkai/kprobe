/*
 * NOTE: This example is works on x86 and powerpc.
 * Here's a sample kernel module showing the use of kprobes to dump a
 * stack trace and selected registers when do_fork() is called.
 *
 * For more information on theory of operation of kprobes, see
 * Documentation/kprobes.txt
 *
 * You will see the trace data in /var/log/messages and on the console
 * whenever do_fork() is invoked to create a new process.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/tcp.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <net/tcp.h>

u32 *before_seq;


/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp = {
    .symbol_name    = "tcp_recvmsg",
};

/* kprobe pre_handler: called just before the probed instruction is executed */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct tcp_sock *tp;
    struct sock *sk;
    u32 *seq;

    sk=regs->di;
    if(sk==NULL)
    {
        printk("sk error\n");
        return 0;
    }
    tp=tcp_sk(sk);
    if(tp==NULL)
    {
        printk("tp error\n");
        return 0;
    }
    seq=&tp->copied_seq;
    if(seq==NULL)
    {
        printk("seq error\n");
        return 0;
    }

//    printk("tcp_port:%lx\n",sk->tcp_port);

    if(sk->tcp_port==0x7017)
    {
        printk("seq: %u\n",*seq);
        //before_seq = &tp->copied_seq;

        return 0;
    }
    return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
/*
static void handler_post(struct kprobe *p, struct pt_regs *regs,
                unsigned long flags)
{

}
*/
/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
/*
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
   
    return 0;
}
*/
static int __init kprobe_init(void)
{
    int ret;
    kp.pre_handler = handler_pre;
    //kp.post_handler = handler_post;
    //kp.fault_handler = handler_fault;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_INFO "register_kprobe failed, returned %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "Planted kprobe at %p\n", kp.addr);
    return 0;
}

static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "kprobe at %p unregistered\n", kp.addr);
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
