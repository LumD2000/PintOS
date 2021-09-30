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
	if (!get_arg(uaddr, (int*)str)) return 0;
	
	uaddrstring = (uint8_t*)str;
	
	//checks if string is properly terminated
	for (byte = is_valid_user(uaddrstring); byte != -1; byte = is_valid_user(uaddrstring++)) {
		
		if (byte == 0) return 1;
		
	}
	
	return 0;
}
/*The 80x86 convention for function return values is to place them 
in the EAX register. System calls that return a value can do so by 
modifying the eax member of struct intr_frame.*/

static void
syscall_handler(struct intr_frame *f) 
{
  unsigned num;

  if(!get_arg(f->esp,(int*) &num))
    thread_exit ();
  if(num > 0 && num < sizeof syscalls / sizeof *syscalls && syscalls[num] != NULL)
    f->eax = syscalls[num] ((uint8_t *) f->esp + sizeof(int));
  else
    f->eax = -1;
}

/* 
Terminates Pintos by calling shutdown_power_off()(declared in "threads/init.h). This should be
seldom used, because you lose some information about possible deadlock situations, etc.
*/

/*
Also I checked for the shutdown_power_off function in threads/init.h and I didn't see the function. Don't know if
thats something we call need to create in the init header file
*/

static int sys_halt(const uint8_t *arg_base){
	return -1;
}

/*
Terminates the current user program, returning "status" to the kernel. If the process's parent
"waits" for it (see below), this is the status that will be returned. Conventionally, a "status"
of 0 indicates success and non-zero values indicate errors.
*/

static int sys_exit(const uint8_t *arg_base){
  /* Brandon's attempt on working on the exit function
  struct list_elem *elem;
  struct thread *current = thread_current();

  for (elem = list_begin (&current->parent->cp); elem != list_end (&current->parent->cp); elem = list_next (elem)) {
    struct child_status *child = list_entry(elem, struct child_status, element);
    if(child->child_tid == current->child_tid) {
      child->used = true;
      child->exit_status = arg_base;
    }
  }

  current->exit_status = arg_base;
  printf("%s: exit(%d)\n", current->name, arg_base, child);
  thread_exit(); 
  */
	return -1;
}

/*
Runs the executable whose name is given in "cmd_line", passing any given arguements, and returns
the new process's program id(pid). Must return pid-1, which otherwise should not be a valid pid, if the program cannot load or run for any reason. Thus, the parent process cannot return from the "exec" until it knows whether the child process successfully loaded its executable. You must use appropriate synchronization to ensure this.
*/

static int sys_exec(const uint8_t *arg_base){
	return -1;
}/*must return the new process's program id(pid), must return pid-1(?idk if its return value of -1 or return value of pid minus 1)*/

/*
Waits for a child process "pid" and retrives the child's exit status.
If "pid" is still alive, waits until it terminates. Then, returns the status that "pid" passed to "exit". If "pid" did not call "exit()", but was terminated by the kernel (e.g. killed due to an exception), "wait(pid)" must return -1. It is perfectly legal for a parent process to wait for a child processs that have already terminated by the time the parent calls "wait", but the kernel must still allow the parent to retrieve its child's exit status, or learn that the child was terminated by the kernel.
"wait" must fail and return -1 immediately if any of the following conditions is true:
    
    *"pid" does not refer to a direct child of the calling process. "pid" is a direct child of the calling process if and only if the calling process received "pid" as a return value from asuccessful call to "exec"
    Note: That children are not inherited: if A spawns child B and B spawns child process C, then A cannot wait for C, even if B is dead. A call to "wait(C)" by process A must fail. Similarly, orphaned processes are not assigned to a new parent if their parent process exits before they do.
    *The process that calls "wait" on "pid". That is, a process may wait for any given child at most once.
Processes may spawn any number of children, wait for them in any order, and may even exit without having waited for some or all of their children. Your design should consider all the ways in which waits can occur. All of a process's resources, including its "struct thread", must be freed whether its parent ever waits for it or not, and regardless of whether the child exits before or after its parent.
You must ensure PintOS does not terminate until the initial process exits. The supplied PintOS code tries to so this by calling "process_wait()" (in "userprog/process.c") from "main()" (in "threads/init.c"). We suggest that you implement "process_wait()" according to the comment at the top of the function and then implement the "wait" system call in terms of "process_wait()".
Implementing this system call requires considerably more work than any of the rest.
*/

static int sys_wait(const uint8_t *arg_base){
	return -1;
}

/*Creates a new file called file initially initial_size bytes in size. 
Returns true if successful, false otherwise. Creating a new file does 
not open it: opening the new file is a separate operation which would 
require a open system call.*/

static int sys_create(const uint8_t *arg_base){
	return -1;
}

/*
Deletes the file called "file". Returns true if successful, false otherwise. A file may be removed regardless of whether it is open or closed, and removing an open file does not close it. See "Removing an Open File", for details
*/
/*Returns true if successful, false is not*/
static int sys_remove(const uint8_t *arg_base){
	return -1;
}

/*
Opens the file called "file". Returns a non-negative integer handle called a "file descriptor"(fd), or -1 if the file could not be open.
File descriptors numbered 0 and 1 are reserved for the console: fd 0 ("STDIN_FILENO") is standard input, fd 1 ("STDOUT_FILENO") is standard output. The "open" system call will never return either of these file descriptors, which are valid as system call arguements only as explicitly described below.
Each process has an independent set of file descriptors. File descriptors are not inherited by the child process.
When a single file is opened more than once, whether by a single process or a different processes, each "open" returns a new file descriptors. Different file descriptors for a single file are closed independently in separate calls to "close" and they do not share a file position.
*/

static int sys_open(const uint8_t *arg_base){
	
    int fd;

    return fd; /**Returns a non-negative integer handle called a "file decriptor"(fd)*/
}

/*
Returns the size, in bytes, of the file open as "fd"
*/

static int sys_filesize(const uint8_t *arg_base){
	return -1;
}


/*
Reads "size" bytes from the file open as "fd" into "buffer. Returns the number of bytes actually read (0 at the end of file), or -1 if the file could not be read (due to a condition other than end of file). "fd" 0 reads from the keyboard using "input_getc()".
*/
/*Returns 0 is it has reached end of file, returns -1 if file could not be read*/

static int sys_read(const uint8_t *arg_base){
	return -1;
}

/*
Writes "size" bytes from "buffer" to the open file "fd". Returns the number of bytes actually written, which maybe less then "size" if some bytes could not be written.
Writing past end-of-file would normally extend the file, but file growth is not implemented by the basic file system. The expected behavior is to write as many bytes as possible up to end-of-file and return the actual number written, or 0 if no bytes could be written at all.
Fd 1 writes to the console. Your code to write to the console should write all of the "buffer" in one call to "putbuf()", at least as long as "size" is not bigger than a few hundred bytes. (It is reasonable to break up larger buffers.) Otherwise, lines of text output by different processes may end up interleaved on the console, confusing both human eaders and our grading scripts.
*/
/*Returns the actually number written, or 0 is no bytes were written*/

static int sys_write(const uint8_t *arg_base){
	return -1;
}

/*
Changes the next byte to be read or written in open file "fd" to "position", expressed in bytes from the beginning of the file. (Thus, a "position" of 0 is the file's start.)
A seek past the current end of a file is not an error. A later read obtains 0 bytes, indicating end of file. A later write extends the file, filling any unwritten gap with zeros. (However, in Pintos files have a fixed length until project 4 is complete, so writes past end of file will return an error.) These semantics are implemented in the file system and do not require any special effort in system call implementation.
*/

static int sys_seek(const uint8_t *arg_base){
	return -1;
}

/*
Returns the postion of the next byte to be read or written in open file "fd", expressed in bytesfrom the beginning of the file."
*/

static int sys_tell(const uint8_t *arg_base){
	return -1;
}

/*
Closes file descriptor "fd". Exiting or terminating a process implicitly closes all its open file descriptors, as if by calling this function for each one.
*/

static int sys_close(const uint8_t *uaddr) {
	
	/*int fd; 
	if (!get_arg(uaddr, &fd)) thread_exit();
	
	fclose(fd);*/
	
	return 0;
	
}