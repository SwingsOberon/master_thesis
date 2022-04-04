//
// Created by oberon on 01/04/2022.
//

#include <linux/sched.h>

#ifndef OPTEE_EXAMPLE_ATTEST_KERN_H
#define OPTEE_EXAMPLE_ATTEST_KERN_H

#ifdef __cplusplus
extern "C" {
#endif

void get_init_task(struct task_struct **t);



#ifdef __cplusplus
}
#endif

#endif //OPTEE_EXAMPLE_ATTEST_KERN_H
