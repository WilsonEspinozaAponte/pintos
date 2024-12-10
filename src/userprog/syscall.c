#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static bool is_valid_pointer(const void *ptr) {
    struct thread *cur = thread_current();
    return ptr != NULL && is_user_vaddr(ptr) && pagedir_get_page(cur->pagedir, ptr) != NULL;
}

static bool check_valid_buffer(const void *buffer, unsigned size) {
    char *addr = (char *)buffer;
    for (unsigned i = 0; i < size; i += PGSIZE) {
        if (!is_valid_pointer(addr + i)) {
            return false;
        }
    }
    if (!is_valid_pointer(addr + size - 1)) {
        return false;
    }
    return true;
}

static void handle_exit(int status) 
{
    struct thread *cur = thread_current();
    printf("%s: exit(%d)\n", cur->name, status);
    thread_exit();  // Terminar el hilo actual
}

static int handle_write(int fd, const void *buffer, unsigned size) 
{
    printf("handle_write: fd=%d, buffer=%p, size=%u\n", fd, buffer, size);

    if (!check_valid_buffer(buffer, size)) {
        handle_exit(-1);
    }

    struct thread *cur = thread_current();

    if (fd == 1) {  // STDOUT
        putbuf(buffer, size);
        return size;
    }

    if (fd < 0) {  // Descriptores negativos no son válidos
        return -1;
    }

    struct list_elem *e;
    for (e = list_begin(&cur->fd_list); e != list_end(&cur->fd_list); e = list_next(e)) {
        struct file_descriptor *fd_struct = list_entry(e, struct file_descriptor, elem);
        if (fd_struct->id == fd) {
            return file_write(fd_struct->file, buffer, size);
        }
    }

    return -1;  // Descriptor no encontrado
}

static void syscall_handler (struct intr_frame *f) 
{
    if (!is_valid_pointer(f->esp)) {
        handle_exit(-1);
    }

    uint32_t *esp = f->esp;
    int syscall_num = esp[0];

    switch (syscall_num) {
        case SYS_WRITE:
            {
                if (!is_valid_pointer(esp + 1) || !is_valid_pointer(esp + 2) || !is_valid_pointer(esp + 3)) {
                    handle_exit(-1);
                }

                int fd = esp[1];
                void *buffer = (void *)esp[2];
                unsigned size = esp[3];

                if (!check_valid_buffer(buffer, size)) {
                    handle_exit(-1);
                }

                f->eax = handle_write(fd, buffer, size);
            }
            break;

        case SYS_EXIT:
            {
                if (!is_valid_pointer(esp + 1)) {
                    handle_exit(-1);
                }
                int status = esp[1];
                handle_exit(status);
            }
            break;

        default:
            printf("Syscall sin implementar: %d\n", syscall_num);
            handle_exit(-1);
    }
}