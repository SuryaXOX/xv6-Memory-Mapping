#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "x86.h"
#include "proc.h"
#include "spinlock.h"
#include <stdbool.h>

struct {
  struct spinlock lock;
  struct proc proc[NPROC];
} ptable;

static struct proc *initproc;

int nextpid = 1;
extern void forkret(void);
extern void trapret(void);

static void wakeup1(void *chan);

void
pinit(void)
{
  initlock(&ptable.lock, "ptable");
}

// Must be called with interrupts disabled
int
cpuid() {
  return mycpu()-cpus;
}

// Must be called with interrupts disabled to avoid the caller being
// rescheduled between reading lapicid and running through the loop.
struct cpu*
mycpu(void)
{
  int apicid, i;
  
  if(readeflags()&FL_IF)
    panic("mycpu called with interrupts enabled\n");
  
  apicid = lapicid();
  // APIC IDs are not guaranteed to be contiguous. Maybe we should have
  // a reverse map, or reserve a register to store &cpus[i].
  for (i = 0; i < ncpu; ++i) {
    if (cpus[i].apicid == apicid)
      return &cpus[i];
  }
  panic("unknown apicid\n");
}

// Disable interrupts so that we are not rescheduled
// while reading proc from the cpu structure
struct proc*
myproc(void) {
  struct cpu *c;
  struct proc *p;
  pushcli();
  c = mycpu();
  p = c->proc;
  popcli();
  return p;
}

//PAGEBREAK: 32
// Look in the process table for an UNUSED proc.
// If found, change state to EMBRYO and initialize
// state required to run in the kernel.
// Otherwise return 0.
static struct proc*
allocproc(void)
{
  struct proc *p;
  char *sp;

  acquire(&ptable.lock);

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(p->state == UNUSED)
      goto found;

  release(&ptable.lock);
  return 0;

found:
  p->state = EMBRYO;
  p->pid = nextpid++;

  // Initialize the memory_mapped_regions pointer to NULL.
  p->mmap_list = NULL;

  release(&ptable.lock);

  // Allocate kernel stack.
  if((p->kstack = kalloc()) == 0){
    p->state = UNUSED;
    return 0;
  }
  sp = p->kstack + KSTACKSIZE;

  // Leave room for trap frame.
  sp -= sizeof *p->tf;
  p->tf = (struct trapframe*)sp;

  // Set up new context to start executing at forkret,
  // which returns to trapret.
  sp -= 4;
  *(uint*)sp = (uint)trapret;

  sp -= sizeof *p->context;
  p->context = (struct context*)sp;
  memset(p->context, 0, sizeof *p->context);
  p->context->eip = (uint)forkret;

  return p;
}

//PAGEBREAK: 32
// Set up first user process.
void
userinit(void)
{
  struct proc *p;
  extern char _binary_initcode_start[], _binary_initcode_size[];

  p = allocproc();
  
  initproc = p;
  if((p->pgdir = setupkvm()) == 0)
    panic("userinit: out of memory?");
  inituvm(p->pgdir, _binary_initcode_start, (int)_binary_initcode_size);
  p->sz = PGSIZE;
  memset(p->tf, 0, sizeof(*p->tf));
  p->tf->cs = (SEG_UCODE << 3) | DPL_USER;
  p->tf->ds = (SEG_UDATA << 3) | DPL_USER;
  p->tf->es = p->tf->ds;
  p->tf->ss = p->tf->ds;
  p->tf->eflags = FL_IF;
  p->tf->esp = PGSIZE;
  p->tf->eip = 0;  // beginning of initcode.S

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  // this assignment to p->state lets other cores
  // run this process. the acquire forces the above
  // writes to be visible, and the lock is also needed
  // because the assignment might not be atomic.
  acquire(&ptable.lock);

  p->state = RUNNABLE;

  release(&ptable.lock);
}

// Grow current process's memory by n bytes.
// Return 0 on success, -1 on failure.
int
growproc(int n)
{
  uint sz;
  struct proc *curproc = myproc();

  sz = curproc->sz;
  if(n > 0){
    if((sz = allocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  } else if(n < 0){
    if((sz = deallocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  }
  curproc->sz = sz;
  switchuvm(curproc);
  return 0;
}

// Create a new process copying p as the parent.
// Sets up stack to return as if from system call.
// Caller must set state of returned proc to RUNNABLE.
int fork(void) {
  int i, pid;
  struct proc *np;
  struct proc *curproc = myproc();

  // Allocate process.
  if ((np = allocproc()) == 0) {
    return -1;
  }

  // Copy process state from proc.
  if ((np->pgdir = copyuvm(curproc->pgdir, curproc->sz)) == 0) {
    kfree(np->kstack);
    np->kstack = 0;
    np->state = UNUSED;
    return -1;
  }
  np->sz = curproc->sz;
  np->parent = curproc;
  *np->tf = *curproc->tf;

  // Copy mmap regions from parent to child
  if (curproc->mmap_list) {
    MemoryMappedRegion *curr = curproc->mmap_list;
    MemoryMappedRegion *prev = NULL;
    while (curr) {
      MemoryMappedRegion *new_region = (MemoryMappedRegion *) kalloc();
      *new_region = *curr;

      if (curr->flags & MAP_SHARED) {
        // Both parent and child should point to the same physical pages
        // This is done inherently by copying the page directory entries earlier
      } else if (curr->flags & MAP_PRIVATE) {
        // Make child's pages copy-on-write
        // TODO: Implement this part based on your xv6's support for CoW
      }

      if (prev) {
        prev->next = new_region;
      } else {
        np->mmap_list = new_region;
      }

      prev = new_region;
      curr = curr->next;
    }
  }

  // Clear %eax so that fork returns 0 in the child.
  np->tf->eax = 0;

  for (i = 0; i < NOFILE; i++) {
    if (curproc->ofile[i]) {
      np->ofile[i] = filedup(curproc->ofile[i]);
    }
  }
  np->cwd = idup(curproc->cwd);

  safestrcpy(np->name, curproc->name, sizeof(curproc->name));

  pid = np->pid;

  acquire(&ptable.lock);

  np->state = RUNNABLE;

  release(&ptable.lock);

  return pid;
}


// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait() to find out it exited.
void
exit(void)
{
    struct proc *curproc = myproc();
    struct proc *p;
    int fd;
    MemoryMappedRegion *current_region, *temp_region;

    if(curproc == initproc)
        panic("init exiting");

    // Close all open files.
    for(fd = 0; fd < NOFILE; fd++){
        if(curproc->ofile[fd]){
            fileclose(curproc->ofile[fd]);
            curproc->ofile[fd] = 0;
        }
    }

    begin_op();
    iput(curproc->cwd);
    end_op();
    curproc->cwd = 0;

    // Clean up memory-mapped regions.
    current_region = curproc->mmap_list;
    while(current_region != NULL) {
        if(current_region->flags & MAP_SHARED && current_region->file_descriptor != -1) {
            // If it's a file-backed shared region, you might want to synchronize the memory contents
            // back to the file. This will depend on your implementation.
            // For simplicity, I'm just releasing the region here.
        }
        
        temp_region = current_region;
        current_region = current_region->next;
        kfree((char*)temp_region); // Assuming you have a kfree function to free kernel memory.
    }
    curproc->mmap_list = NULL; // Reset the memory-mapped list.

    acquire(&ptable.lock);

    // Parent might be sleeping in wait().
    wakeup1(curproc->parent);

    // Pass abandoned children to init.
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
        if(p->parent == curproc){
            p->parent = initproc;
            if(p->state == ZOMBIE)
                wakeup1(initproc);
        }
    }

    // Jump into the scheduler, never to return.
    curproc->state = ZOMBIE;
    sched();
    panic("zombie exit");
}


// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int
wait(void)
{
  struct proc *p;
  int havekids, pid;
  struct proc *curproc = myproc();
  
  acquire(&ptable.lock);
  for(;;){
    // Scan through table looking for exited children.
    havekids = 0;
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->parent != curproc)
        continue;
      havekids = 1;
      if(p->state == ZOMBIE){
        // Found one.
        pid = p->pid;
        kfree(p->kstack);
        p->kstack = 0;
        freevm(p->pgdir);
        p->pid = 0;
        p->parent = 0;
        p->name[0] = 0;
        p->killed = 0;
        p->state = UNUSED;
        release(&ptable.lock);
        return pid;
      }
    }

    // No point waiting if we don't have any children.
    if(!havekids || curproc->killed){
      release(&ptable.lock);
      return -1;
    }

    // Wait for children to exit.  (See wakeup1 call in proc_exit.)
    sleep(curproc, &ptable.lock);  //DOC: wait-sleep
  }
}

//PAGEBREAK: 42
// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run
//  - swtch to start running that process
//  - eventually that process transfers control
//      via swtch back to the scheduler.
void
scheduler(void)
{
  struct proc *p;
  struct cpu *c = mycpu();
  c->proc = 0;
  
  for(;;){
    // Enable interrupts on this processor.
    sti();

    // Loop over process table looking for process to run.
    acquire(&ptable.lock);
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->state != RUNNABLE)
        continue;

      // Switch to chosen process.  It is the process's job
      // to release ptable.lock and then reacquire it
      // before jumping back to us.
      c->proc = p;
      switchuvm(p);
      p->state = RUNNING;

      swtch(&(c->scheduler), p->context);
      switchkvm();

      // Process is done running for now.
      // It should have changed its p->state before coming back.
      c->proc = 0;
    }
    release(&ptable.lock);

  }
}

// Enter scheduler.  Must hold only ptable.lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->ncli, but that would
// break in the few places where a lock is held but
// there's no process.
void
sched(void)
{
  int intena;
  struct proc *p = myproc();

  if(!holding(&ptable.lock))
    panic("sched ptable.lock");
  if(mycpu()->ncli != 1)
    panic("sched locks");
  if(p->state == RUNNING)
    panic("sched running");
  if(readeflags()&FL_IF)
    panic("sched interruptible");
  intena = mycpu()->intena;
  swtch(&p->context, mycpu()->scheduler);
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void
yield(void)
{
  acquire(&ptable.lock);  //DOC: yieldlock
  myproc()->state = RUNNABLE;
  sched();
  release(&ptable.lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch here.  "Return" to user space.
void
forkret(void)
{
  static int first = 1;
  // Still holding ptable.lock from scheduler.
  release(&ptable.lock);

  if (first) {
    // Some initialization functions must be run in the context
    // of a regular process (e.g., they call sleep), and thus cannot
    // be run from main().
    first = 0;
    iinit(ROOTDEV);
    initlog(ROOTDEV);
  }

  // Return to "caller", actually trapret (see allocproc).
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void
sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();
  
  if(p == 0)
    panic("sleep");

  if(lk == 0)
    panic("sleep without lk");

  // Must acquire ptable.lock in order to
  // change p->state and then call sched.
  // Once we hold ptable.lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup runs with ptable.lock locked),
  // so it's okay to release lk.
  if(lk != &ptable.lock){  //DOC: sleeplock0
    acquire(&ptable.lock);  //DOC: sleeplock1
    release(lk);
  }
  // Go to sleep.
  p->chan = chan;
  p->state = SLEEPING;

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  if(lk != &ptable.lock){  //DOC: sleeplock2
    release(&ptable.lock);
    acquire(lk);
  }
}

//PAGEBREAK!
// Wake up all processes sleeping on chan.
// The ptable lock must be held.
static void
wakeup1(void *chan)
{
  struct proc *p;

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(p->state == SLEEPING && p->chan == chan)
      p->state = RUNNABLE;
}

// Wake up all processes sleeping on chan.
void
wakeup(void *chan)
{
  acquire(&ptable.lock);
  wakeup1(chan);
  release(&ptable.lock);
}

// Kill the process with the given pid.
// Process won't exit until it returns
// to user space (see trap in trap.c).
int
kill(int pid)
{
  struct proc *p;

  acquire(&ptable.lock);
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->pid == pid){
      p->killed = 1;
      // Wake process from sleep if necessary.
      if(p->state == SLEEPING)
        p->state = RUNNABLE;
      release(&ptable.lock);
      return 0;
    }
  }
  release(&ptable.lock);
  return -1;
}

//PAGEBREAK: 36
// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void
procdump(void)
{
  static char *states[] = {
  [UNUSED]    "unused",
  [EMBRYO]    "embryo",
  [SLEEPING]  "sleep ",
  [RUNNABLE]  "runble",
  [RUNNING]   "run   ",
  [ZOMBIE]    "zombie"
  };
  int i;
  struct proc *p;
  char *state;
  uint pc[10];

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->state == UNUSED)
      continue;
    if(p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    cprintf("%d %s %s", p->pid, state, p->name);
    if(p->state == SLEEPING){
      getcallerpcs((uint*)p->context->ebp+2, pc);
      for(i=0; i<10 && pc[i] != 0; i++)
        cprintf(" %p", pc[i]);
    }
    cprintf("\n");
  }
}

// Adds a new memory-mapped region to the list.
// Returns 0 on success, -1 on failure (e.g., if memory allocation fails).
int add_memory_mapped_region(struct proc *p, uintptr_t start_address, size_t length, int flags, int file_descriptor, off_t offset) {
    // Allocate memory for the new region
    MemoryMappedRegion *new_region = (MemoryMappedRegion *)kalloc();
    if (!new_region) {
        return -1;  // Allocation failed
    }

    // Populate the new region's fields
    new_region->start_address = start_address;
    new_region->length = length;
    new_region->flags = flags;
    new_region->file_descriptor = file_descriptor;
    new_region->offset = offset;
    new_region->next = NULL;

    // Add the new region to the process's list
    if (!p->mmap_list) {
        p->mmap_list = new_region;  // This is the first region
    } else {
        MemoryMappedRegion *current = p->mmap_list;
        while (current->next) {
            current = current->next;  // Traverse to the end of the list
        }
        current->next = new_region;
    }

    return 0;  // Success
}

// Removes a memory-mapped region from the list based on the start address.
// Returns 0 on success, -1 if the region is not found.
int remove_memory_mapped_region(struct proc *p, uintptr_t start_address) {
    if (!p->mmap_list) {
        return -1;  // List is empty
    }

    MemoryMappedRegion *current = p->mmap_list;
    MemoryMappedRegion *prev = NULL;

    while (current) {
        if (current->start_address == start_address) {
            if (prev) {
                prev->next = current->next;
            } else {
                p->mmap_list = current->next;  // Update the head of the list
            }
            kfree((char *)current);
            return 0;  // Success
        }

        prev = current;
        current = current->next;
    }

    return -1;  // Region not found
}

// Finds a memory-mapped region in the list based on the start address.
// Returns a pointer to the region if found, NULL otherwise.
MemoryMappedRegion* find_memory_mapped_region(struct proc *p, uintptr_t start_address) {
    MemoryMappedRegion *current = p->mmap_list;
    while (current) {
        if (current->start_address == start_address) {
            return current;  // Region found
        }
        current = current->next;
    }

    return NULL;  // Region not found
}

void free_memory_mapped_regions(struct proc* p) {
    MemoryMappedRegion* current = p->mmap_list;
    MemoryMappedRegion* next;

    while (current != NULL) {
        next = current->next;
        // If it's file-backed, you might need to close the file or handle any other cleanup
        if (current->file_descriptor != -1) {
            close(current->file_descriptor);  // Assuming a close function is available
        }
        kfree((char*)current);  // Assuming kfree is your memory deallocation function
        current = next;
    }
    p->mmap_list = NULL;
}

bool is_access_allowed(MemoryMappedRegion* region, int desired_flags) {
    // Here, check the region's flags against the desired_flags.
    // For instance, if the region is PROT_READ and the access is a write, return false.
    if ((desired_flags & PROT_WRITE) && !(region->flags & PROT_WRITE)) {
        return false;
    }
    // ... any other checks based on flags ...
    return true;
}

void handle_file_backed_access(MemoryMappedRegion* region, uintptr_t faulting_address, struct proc* p) {
    // Calculate offset into the file
    off_t file_offset = region->offset + (faulting_address - region->start_address);

    // Allocate a page
    char* buffer = (char*)kalloc();
    if (!buffer) {
        kill(p);
        return;
    }

    // Read the file content into the buffer
    struct file* f = p->ofile[region->file_descriptor];
    fileseek(f, file_offset);
    fileread(f, buffer, PGSIZE); // Assuming PGSIZE is the page size

    // Map the buffer to the faulting address
    mappage(p->pgdir, (void*)faulting_address, V2P(buffer), PTE_W | PTE_U);
}


void handle_page_fault(uintptr_t faulting_address, struct proc* p) {
    MemoryMappedRegion* region = find_memory_mapped_region_for_address(p, faulting_address);
    
    if (region == NULL) {
        // This was not a memory-mapped access, handle the page fault as usual
        kill(p);  // or however you handle such page faults
        return;
    }

    if (!is_access_allowed(region, PROT_READ | PROT_WRITE)) {
        // Access violation
        kill(p);  // or send a signal, or however you handle access violations
        return;
    }

    if (region->file_descriptor != -1) {
        handle_file_backed_access(region, faulting_address, p);
    }
    
    // ... any other page fault handling ...
}

void* mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    struct proc *curproc = myproc(); // Get current process
    
    // Lock the process table or any other required resources
    acquire(&ptable.lock);

    // Check if it's a file-backed mapping and fd is valid
    if (!(flags & MAP_ANONYMOUS) && (fd < 0 || fd >= NOFILE || curproc->ofile[fd] == 0)) {
        release(&ptable.lock);
        return (void*)-1; // return error
    }

    // If MAP_FIXED is not set, find a region between the specified range
    if (!(flags & MAP_FIXED)) {
        // Here, you would typically iterate through the process's address space
        // and find a gap of the required length between 0x60000000 and 0x80000000
        // For simplicity, let's assume you find an address:
        addr = (void*) 0x60000000; // TODO: Implement a more robust solution
    }

    // Create a new mapped region
    MemoryMappedRegion *new_region = (MemoryMappedRegion*)kalloc();
    if (!new_region) {
        release(&ptable.lock);
        return (void*)-1; // return error
    }

    // Initialize the region
    new_region->start_address = (uintptr_t) addr;
    new_region->length = length;
    new_region->flags = flags;
    new_region->file_descriptor = (flags & MAP_ANONYMOUS) ? -1 : fd;
    new_region->offset = offset;
    new_region->next = curproc->mmap_list;

    // Add the region to the process's list
    curproc->mmap_list = new_region;

    // Release the lock
    release(&ptable.lock);

    return addr; // Return the starting address
}


void cleanup_mmap(struct proc* p) {
    struct MemoryMappedRegion* current = p->mmap_list;
    while (current) {
        struct MemoryMappedRegion* to_free = current;
        current = current->next;
        kfree((char*)to_free);
    }
    p->mmap_list = 0;
}

int munmap(void* addr, size_t length) {
    struct proc *curproc = myproc();
    MemoryMappedRegion *prev = NULL, *curr = curproc->mmap_list;

    while (curr) {
        if (curr->start_address == (uintptr_t)addr && curr->length == length) {
            
            // Check for file-backed with MAP_SHARED and write back
            if (curr->file_descriptor != -1 && (curr->flags & MAP_SHARED)) {
                // Use the file descriptor (curr->file_descriptor) to write back changes
                // You'll need a function or method to do this; pseudocode:
                // write_to_file(curr->file_descriptor, addr, length);
            }

            // Remove pages and update page table
            // Here, you'd go through the virtual address space spanned by [addr, addr+length)
            // and remove the corresponding pages, then update the page table.
            // Pseudocode:
            // remove_pages(addr, length);

            // Update the list
            if (prev) {
                prev->next = curr->next;
            } else {
                curproc->mmap_list = curr->next;
            }

            kfree((char*)curr);
            return 0; // Success
        }

        prev = curr;
        curr = curr->next;
    }

    return -1; // Failed, region not found
}

