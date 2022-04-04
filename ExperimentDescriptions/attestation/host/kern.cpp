//
// Created by oberon on 01/04/2022.
//

#include </usr/include/linux/kernel.h>
#include "kern.h"

int va2pa(int va){
    struct task_struct *t;
    struct pid *pid;
    pid=find_get_pid(0);
    t=get_pid_task(pid,PIDTYPE_PID);
    return 0;
}