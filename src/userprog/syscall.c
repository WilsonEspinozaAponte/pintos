#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdlib.h> 
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"    
#include "devices/shutdown.h"    // Para shutdown_power_off

// Definición de constantes 
#define STDOUT_FILENO 1

// Definición de tipo para manejadores de syscalls 
typedef void (*syscall_handler_func)(struct intr_frame *);

// Número máximo de syscalls soportadas
#define MAX_SYSCALLS 20

// Tabla de punteros a funciones para syscalls 
static syscall_handler_func syscall_handlers[MAX_SYSCALLS];

// Lock para sincronización 
static struct lock syscall_lock;

// Funciones de manejo de syscalls
static void handle_halt(struct intr_frame *f);
static void handle_exit(struct intr_frame *f);
static void handle_write(struct intr_frame *f);

static bool is_valid_pointer(const void *ptr);
static void retrieve_arguments(struct intr_frame *f, int *args, int count);
static void handle_exit_syscall(int status);
static void syscall_handler(struct intr_frame *f);

// Inicialización de syscalls
void syscall_init(void) 
{
    lock_init(&syscall_lock);
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

    /* Inicialización de la tabla de manejadores de syscalls */
    for (int i = 0; i < MAX_SYSCALLS; i++) {
        syscall_handlers[i] = NULL;
    }
    syscall_handlers[SYS_HALT] = handle_halt;
    syscall_handlers[SYS_EXIT] = handle_exit;
    syscall_handlers[SYS_WRITE] = handle_write;
}

// Validación de punteros de usuario 
static bool
is_valid_pointer(const void *ptr)
{
    if (ptr == NULL)
        return false;
    if (!is_user_vaddr(ptr))
        return false;
    // Verifica que la dirección esté mapeada en la página del proceso
    if (pagedir_get_page(thread_current()->pagedir, ptr) == NULL)
        return false;
    return true;
}

// Recuperación de argumentos de la syscall
static void
retrieve_arguments(struct intr_frame *f, int *args, int count)
{
    uint32_t *esp = (uint32_t *)f->esp;

    for (int i = 0; i < count; i++) {
        // Calcula la dirección del argumento 
        void *arg_ptr = (void *)(esp + 1 + i);

        // Valida la dirección del argumento 
        if (!is_valid_pointer(arg_ptr)) {
            handle_exit_syscall(-1);
        }

        // Recupera el argumento 
        args[i] = *(esp + 1 + i);
    }
}

static void
syscall_handler(struct intr_frame *f)
{
    // Validación de la dirección de la pila 
    if (!is_valid_pointer(f->esp)) {
        handle_exit_syscall(-1);
    }

    int syscall_number = *((int *)f->esp);

    // Verifica que el número de syscall sea válido 
    if (syscall_number < 0 || syscall_number >= MAX_SYSCALLS || syscall_handlers[syscall_number] == NULL) {
        handle_exit_syscall(-1);
    }

    syscall_handlers[syscall_number](f);
}


// Manejador de SYS_HALT 
static void
handle_halt(struct intr_frame *f UNUSED)
{
    shutdown_power_off();
}

//  Manejador de SYS_EXIT 
static void
handle_exit(struct intr_frame *f)
{
    int args[1];
    retrieve_arguments(f, args, 1);
    handle_exit_syscall(args[0]);
}

// Función para manejar la salida de un proceso
static void
handle_exit_syscall(int status)
{
    struct thread *curr = thread_current();
    curr->pcb->exit_code = status;
    printf("%s: exit(%d)\n", curr->name, status);
    thread_exit();
}

// Manejador de SYS_WRITE 
static void
handle_write(struct intr_frame *f)
{
    int args[3];
    retrieve_arguments(f, args, 3);

    int fd = args[0];
    const void *buffer = (const void *)args[1];
    unsigned size = (unsigned)args[2];

    // Valida el buffer de escritura 
    if (!is_valid_pointer(buffer)) {
        handle_exit_syscall(-1);
    }

    // Adquiere el lock para sincronización 
    lock_acquire(&syscall_lock);
    int bytes_written = 0;

    if (fd == STDOUT_FILENO) {
        putbuf(buffer, size);
        bytes_written = size;
    } else {
        // Como no hay un SYS_OPEN, cualquier fd != 1 es inválido 
        lock_release(&syscall_lock);
        handle_exit_syscall(-1);
    }

    // Libera el lock 
    lock_release(&syscall_lock);

    // Retorna el número de bytes escritos 
    f->eax = bytes_written;
}
