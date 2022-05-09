//
// Created by oberon on 14/04/2022.
//

#include <fcntl.h> /* open */
#include <stdint.h> /* uint64_t  */
#include <stdio.h> /* printf */
#include <stdlib.h> /* size_t */
#include <unistd.h> /* pread, sysconf */
#include <dirent.h> /* DIR */
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#ifndef ATTESTATION_VIRT_TO_PHYS_USER_H
#define ATTESTATION_VIRT_TO_PHYS_USER_H

typedef struct {
    uint64_t pfn : 55;
    unsigned int soft_dirty : 1;
    unsigned int file_page : 1;
    unsigned int swapped : 1;
    unsigned int present : 1;
} PagemapEntry;

int virt_to_phys_user(uintptr_t *paddr, pid_t pid, uintptr_t vaddr);

pid_t get_proc_pid();

void get_proc_vaddr(uintptr_t *vaddr, size_t *size);

#endif //ATTESTATION_VIRT_TO_PHYS_USER_H
