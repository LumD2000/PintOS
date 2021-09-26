#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler(struct intr_frame *);

static int sys_halt(const uint8_t *arg_base);
static int sys_exit(const uint8_t *arg_base);
static int sys_exec(const uint8_t *arg_base);
static int sys_wait(const uint8_t *arg_base);
static int sys_create(const uint8_t *arg_base);
static int sys_remove(const uint8_t *arg_base);
static int sys_open(const uint8_t *arg_base);
static int sys_filesize(const uint8_t *arg_base);
static int sys_read(const uint8_t *arg_base);
static int sys_write(const uint8_t *arg_base);
static int sys_seek(const uint8_t *arg_base);
static int sys_tell(const uint8_t *arg_base);
static int sys_close(const uint8_t *arg_base);

static int(*syscalls[])(const uint8_t *arg_base) =
{
  [SYS_HALT] sys_halt,
  [SYS_EXIT] sys_exit,
  [SYS_EXEC] sys_exec,
  [SYS_WAIT] sys_wait,
  [SYS_CREATE] sys_create,
  [SYS_REMOVE] sys_remove,
  [SYS_OPEN] sys_open, 
  [SYS_FILESIZE] sys_filesize,
  [SYS_READ] sys_read,
  [SYS_WRITE] sys_write,
  [SYS_SEEK] sys_seek,
  [SYS_TELL] sys_tell,
  [SYS_CLOSE] sys_close            
};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Reads a byte at UADDR if it is below PHYS_BASE.
   Returns pointer to the byte if successful, -1 if segfault. */
static int is_valid_user(const uint8_t *uaddr){
  return is_user_vaddr(uaddr) ? *uaddr : -1; 
}

static int get_arg(const uint8_t *uaddr, int *num){
	
  int a,b,c,d;

  a = is_valid_user(uaddr);
  b = is_valid_user(uaddr + 1);
  c = is_valid_user(uaddr + 2);
  d = is_valid_user(uaddr + 3);
  
  /* Address is not in user space. */
  if (a == -1 || b == -1 || c == -1 || d == -1) return 0;
  
  else {
	  *num = (((uint8_t) a | ((uint8_t) b << 8)) | ((uint8_t) c << 16)) | ((uint8_t) d << 24);
	  return 1;
  }
}

static int get_arg_string(const uint8_t *uaddr, char **str){
	
	uint8_t *uaddrstring;
	int byte;
	
	//get the string value
	if (!get_arg(uaddr, str)) return 0;
	
	uaddrstring = (uint8_t*)str;
	
	//checks if string is properly terminated
	for (byte = is_valid_user(uaddrstring); byte != -1; byte = is_valid_user(uaddrstring++)) {
		
		if (byte == 0) return 1;
		
	}
	
	return 0;
}

static void
syscall_handler(struct intr_frame *f UNUSED) 
{
  uint8_t * num;

  if(!get_arg(f->esp, &num))
    thread_exit ();
  if(num > 0 && num < sizeof syscalls / sizeof *syscalls && syscalls[num] != NULL)
    f->eax = syscalls[num]((uint8_t *) f->esp + sizeof(int));
  else
    f->eax = -1;
}

static int close(const uint8_t *uaddr) {
	
	int fd; 
	if (!get_arg(uaddr, &fd)) thread_exit();
	
	fd_close(fd);
	
	return 0;
	
}