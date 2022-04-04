//
// Created by oberon on 01/04/2022.
//

#include "kern.h"
#include "../../../../linux/include/linux/pid.h"


void get_init_task(struct task_struct **t){
    struct pid *pid;
    pid = find_get_pid(0);
    *t = get_pid_task(pid,PIDTYPE_PID);
}