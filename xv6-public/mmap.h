#ifndef MMAP_H
#define MMAP_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h> 

/* Define mmap flags */
#define MAP_PRIVATE   0x0001
#define MAP_SHARED    0x0002
#define MAP_ANONYMOUS 0x0004
#define MAP_ANON      MAP_ANONYMOUS
#define MAP_FIXED     0x0008
#define MAP_GROWSUP   0x0010

/* Protections on memory mapping */
#define PROT_READ     0x1
#define PROT_WRITE    0x2

typedef struct MemoryMappedRegion {
    uintptr_t start_address;         // Starting address of the memory-mapped region
    size_t length;                   // Length of the region
    int flags;                       // Flags for the memory-mapped region
    int file_descriptor;             // File descriptor if the region is backed by a file. -1 if not.
    off_t offset;                    // Offset into the file for file-backed mappings
    struct MemoryMappedRegion* next; // Pointer to the next memory-mapped region, if using a linked list
} MemoryMappedRegion;


#endif /* MMAP_H */
