#define _XOPEN_SOURCE 700

#include "virt_to_phys_user.h"
#include "attestation_ta.h"

/* Parse the pagemap entry for the given virtual address.
 *
 * @param[out] entry      the parsed entry
 * @param[in]  pagemap_fd file descriptor to an open /proc/pid/pagemap file
 * @param[in]  vaddr      virtual address to get entry for
 * @return 0 for success, 1 for failure
 */
int pagemap_get_entry(PagemapEntry *entry, int pagemap_fd, uintptr_t vaddr)
{
    fprintf(stderr, "pagemap_get_entry\n");
    size_t nread;
    ssize_t ret;
    uint64_t data;
    uintptr_t vpn;

    vpn = vaddr / sysconf(_SC_PAGE_SIZE);
    nread = 0;
    while (nread < sizeof(data)) {
        ret = pread(pagemap_fd, ((uint8_t*)&data) + nread, sizeof(data) - nread,
                vpn * sizeof(data) + nread);
        nread += ret;
        if (ret <= 0) {
            return 1;
        }
    }
    entry->pfn = data & (((uint64_t)1 << 55) - 1);
    entry->soft_dirty = (data >> 55) & 1;
    entry->file_page = (data >> 61) & 1;
    entry->swapped = (data >> 62) & 1;
    entry->present = (data >> 63) & 1;
    return 0;
}

/* Convert the given virtual address to physical using /proc/PID/pagemap.
 *
 * @param[out] paddr physical address
 * @param[in]  pid   process to convert for
 * @param[in] vaddr virtual address to get entry for
 * @return 0 for success, 1 for failure
 */
int virt_to_phys_user(uintptr_t *paddr, pid_t pid, uintptr_t vaddr)
{
    fprintf(stderr, "virt_to_phys_user\n");
    char pagemap_file[BUFSIZ];
    int pagemap_fd;

    snprintf(pagemap_file, sizeof(pagemap_file), "/proc/%ju/pagemap", (uintmax_t)pid);
    pagemap_fd = open(pagemap_file, O_RDONLY);
    if (pagemap_fd < 0) {
        return 1;
    }
    PagemapEntry entry;
    if (pagemap_get_entry(&entry, pagemap_fd, vaddr)) {
        return 1;
    }
    close(pagemap_fd);
    *paddr = (entry.pfn * sysconf(_SC_PAGE_SIZE)) + (vaddr % sysconf(_SC_PAGE_SIZE));
    return 0;
}

pid_t get_proc_pid() {
    fprintf(stderr, "get_proc_pid\n");
    pid_t pid = 1;
    /*
    char proc[255];
    //Find the first PID in the /proc folder and put the path to the page file (maps) in the proc variable
    DIR *d;
    struct dirent *dir;
    fprintf(stdout, "opendir(/proc)\n");
    d = opendir("/proc");
    if (d) {
        fprintf(stdout, "readdir\n");
        while ((dir = readdir(d)) != NULL) {
            fprintf(stdout, "%s\n", dir->d_name);
            if (isdigit(dir->d_name[0]) && strtol(dir->d_name, NULL, 10) > 100) {
                strcpy(proc, "/proc/");
                strcat(proc, dir->d_name);
                strcat(proc, "/maps");
                pid = strtol(dir->d_name, NULL, 10);
                break;
            }
            fprintf(stdout, "endwhile\n");
        }
        closedir(d);
    }
    fprintf(stdout, "proc = %s\n", proc);*/
    //Currently 1 is returned as pid, this is the init_proc from where all processes are iterated on
    return pid;
}

void get_proc_vaddr(uintptr_t *vaddr, size_t *size) {
    fprintf(stderr, "get_proc_vaddr\n");
    char buff[255];
    char proc[255] = "/proc/1/maps";
    char pagestart[13];
    char pageend[13];
    FILE *fp;
    //Find the first executable page from the init_proc
    fprintf(stderr, "fopen(proc)\n");
    fp = fopen(proc, "r");
    bool found = false;
    fprintf(stderr, "start while(!found)\n");
    while (!found) {
        if (fgets(buff, 255, (FILE*)fp) != NULL)
            fprintf(stdout, "%s", buff);
        else
            fprintf(stdout, "fgets(buff, fp) == NULL");
        if (buff[28] == 'x') {
            found = true;
            strncpy(pagestart, buff, 12);
            pagestart[12] = '\0';
            strncpy(pageend, &buff[13], 12);
            pageend[12] = '\0';
            *vaddr = (uintptr_t) strtol(pagestart, NULL, 16);
            fprintf(stdout, "vaddr = %ld\n", *vaddr);
            *size = (strtol(pageend, NULL, 16) - strtol(pagestart, NULL, 16))/PAGE_SIZE;//Size needs to be in amount of pages and a page is 2KB
            fprintf(stdout, "size = %ld\n", *size);
        }
    }
}
