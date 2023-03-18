#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>

#include "disk.h"
#include "fs.h"

/** API Value Definitions **/
#define SIGNATURE_MAX 8
#define FAT_INDEX 1

// A filename in the root directory is 16 bytes max
#define SUPERBLOCK_INDEX 0
#define SUPERBLOCK_PADDING 4079
#define ROOT_DIR_ENTRY_SIZE 32
#define ROOT_DIR_PADDING_SIZE 10
#define FAT_EOC 0xFFFF
#define FILE_DESCRIPTOR_TABLE_SIZE 32
#define FAT_ARR_SIZE 2048

/* TODO: Attach the attribute "packed" to these data structs */

// The first block of the disk and contains info about the filesystem
struct superBlock {
    uint64_t signature;
    int16_t dsk_blck_amount;
    int16_t root_dir_index;
    int16_t data_blck_index;
    int16_t data_blck_amount;
    int8_t fat_blck_amount;
    int8_t padding[SUPERBLOCK_PADDING];
};

// An entry in the root directory
struct root_entry {
    int8_t filename[FS_FILENAME_LEN];
    int32_t file_size; // in bytes
    int16_t file_first_index;
    int8_t padding[ROOT_DIR_PADDING_SIZE];
};

struct fat_array {
    uint16_t arr[FAT_ARR_SIZE];
};

// All information about the filesystem - super block, FAT, and root directory
struct fs_system {
    struct superBlock sp;
    struct root_entry root_dir[FS_FILE_MAX_COUNT];

    // TODO: Is this the number of fat blocks?
    //uint16_t** fat_blocks;
    struct fat_array* fat_blocks;
};

struct fd_table_entry {
    char filename[FS_FILENAME_LEN];
    size_t offset;
    bool used;
};

struct free_fat_entry {
    int block_index;
    int arr_index;
};

// Create file system struct pointer
struct fs_system* file_system;

/* Table of file descriptors */
struct fd_table_entry fd_table[FILE_DESCRIPTOR_TABLE_SIZE];

/* Temporary variable to hole the index of a free fat entry */
struct free_fat_entry fat_entry;

/* Keeps track of numbers of open files */
unsigned fd_open_count = 0;

const char SIG[SIGNATURE_MAX] = "ECS150FS";

// Verify super block data from mount function
int sys_error_check() {
    uint8_t character;
    /* Check if file signature matches the diskname */
    for (int i = 0; i < SIGNATURE_MAX; i++) {
        character = file_system->sp.signature >> (SIGNATURE_MAX * i) & 0xFF;
        if((char)character != SIG[i]) {
                //printf("Signature error\n");
                return -1;
        }
    }
    /* Compare calculated disk block count to super block disk block count */
    int disk_blocks = block_disk_count();
    if (disk_blocks != file_system->sp.dsk_blck_amount) {
        //fprintf(stderr, "Error: Disk Block Length is invalid\n");
        return -1;
    }

    /* Compare calculated fat block count to super block fat block count */
    int disk_fat_count = disk_blocks * 2 / BLOCK_SIZE;

    if(disk_fat_count < BLOCK_SIZE) disk_fat_count = 1;

    if (disk_fat_count != file_system->sp.fat_blck_amount) {
        //fprintf(stderr, "Error: FAT Length is invalid\n");
        return -1;
    }

    /* Compare calculated data blocks to super block data block amount */
    // Total blocks = fat blocks - 1 [super block] - 1 [root dir] - data blocks
    int disk_data_blcks = disk_blocks - (2 + disk_fat_count);
    if (disk_data_blcks != file_system->sp.data_blck_amount) {
        //fprintf(stderr, "Error: Data Block Length is invalid\n");
        return -1;
    }

    /* Compare calculated root dir index to super block root dir index */
    // Root dir index = 1 [super block] + fat blocks
    if (disk_fat_count + 1 != file_system->sp.root_dir_index) {
        //fprintf(stderr, "Error: Root Directory index is invalid\n");
        return -1;
    }

    /* Compare calculated data block index to super block data block index */
    // Data block index = 1 [super block] + fat blocks + 1 [root dir]
    if (disk_fat_count + 2 != file_system->sp.data_blck_index) {
        //fprintf(stderr, "Error: Data Block index is invalid\n");
        return -1;
    }

    return 0;
}

/** Open virtual disk and load metadata information **/
int fs_mount(const char *diskname) {
    /* TODO: Phase 1 */

    // Verify valid disk name length
    int diskNameLen = strlen(diskname);
    if ((SIGNATURE_MAX < diskNameLen) || (!diskNameLen)) {
        //printf("disklen err\n");
        return -1;
    }

    // Attempt to open disk
    int success = !block_disk_open(diskname);
    if (!success) {
        //printf("failed to open disk\n");
        return -1;
    }

    // Allocate memory for the filesystem struct
    file_system = malloc(sizeof(struct fs_system));

    /* Read the super block and store the data in sp struct */
    block_read(SUPERBLOCK_INDEX, &file_system->sp);

    // Verify super block data
    if (sys_error_check()){
    	//printf("system check err\n");
        return -1;
    }

    /* Create the FAT array with the corresponding size of elements */
    file_system->fat_blocks = (struct fat_array*)malloc(file_system->sp.fat_blck_amount * sizeof(struct fat_array));
    
	/* Go through the FAT blocks and store the data in the FAT array */
    for (int i = 1; i < file_system->sp.fat_blck_amount + 1; i++) {
        block_read(i, &file_system->fat_blocks[i - 1]);
    }

    // Read root directory block and write into root_entries
    // There the root directory is one block big. No for loop needed
    block_read(file_system->sp.root_dir_index, &file_system->root_dir);

    return 0;
}

/** Close the virtual disk and clean internal data structures **/
int fs_umount(void) {
    /* TODO: Phase 1 */

    if(file_system == NULL) return -1;

    for(int i = 0; i < FILE_DESCRIPTOR_TABLE_SIZE; i++) {
        if(strlen(fd_table[i].filename) != 0) return -1;
    }
    // Persistent Storage - Write all FAT data out to the disk
    //Shouldn't i be 1 instead of 2?
    for (int i = FAT_INDEX; i < file_system->sp.fat_blck_amount + 1; i++) {
        printf("sizeof arr = %lu\n", sizeof(file_system->fat_blocks[i - FAT_INDEX]));
        block_write(i, &file_system->fat_blocks[i - FAT_INDEX]);
    }
    // Persistent Storage - Write all root directory data out to the disk
    block_write(file_system->sp.root_dir_index, &file_system->root_dir);
    // Clean internal data structures - Deallocate memory
    free(file_system->fat_blocks);
    free(file_system);
   
    // Close virtual disk
    int success = !block_disk_close();
    if (!success) {
        return -1;
    }
    return 0;
}

/* Get number of avalaible FAT indexes */
int get_free_fat() {
    int free_fat = 0;
    for(int r = 0; r < file_system->sp.fat_blck_amount; r++) {
        for(int c = 0; c < FAT_ARR_SIZE; c++) {
            if(file_system->fat_blocks[r].arr[c] == 0) {
                free_fat++;
            }
        }
    }
    return free_fat;
}

/* Get number of available entries in the root directory */
int get_free_dir() {
    int free_dir = 0;
    for(int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if(strlen((char*)file_system->root_dir[i].filename) == 0) {
            free_dir++;
        }
    }

    return free_dir;
}

// Prints information about the mounted file system
int fs_info(void) {
    /* TODO: Phase 1 */

    if (file_system == NULL) {
        //fprintf(stderr, "Error: No file system mounted\n");
        return -1;
    }

    printf("FS Info: \n");

    printf("total_blk_count=%d\n", file_system->sp.dsk_blck_amount);

    unsigned fatBytes = file_system->sp.data_blck_amount * 2;
    printf("fat_blk_count=%d\n", fatBytes / BLOCK_SIZE);

    printf("rdir_blk=%d\n", file_system->sp.root_dir_index);
    printf("data_blk%d\n", file_system->sp.data_blck_index);

    printf("data_blk_count=%d\n", file_system->sp.data_blck_amount);

    /* TODO: Determine and Calculate Ratios */
    printf("fat_free_ratio=%d/%d\n", get_free_fat(), file_system->sp.data_blck_amount);
    printf("rdir_free_ratio=%d/%d\n", get_free_dir(), FS_FILE_MAX_COUNT);

    return 0;
}

bool isValidName(const char *filename) {
    /* Verify the filename is null terminated and has a valid length */
    for (unsigned c = 0; c < FS_FILENAME_LEN; c++){
        if (filename[c] == '\0'){
            return true;
        }
    }

    //fprintf(stderr, "Filename is either too large or not null terminated\n");
    return false;
}

int fs_create(const char *filename) {
    /* TODO: Phase 2 */

    /* Check if the file system was mounted. If not then return -1. */
    if (file_system == NULL) {
        //fprintf(stderr, "File System not mounted\n");
        return -1;
    }

    /* Check if the provided filename is valid. If not then return -1 */
    if (!isValidName(filename)) {
        return -1;
    }

    /* Index of the free entry in the root directory */
    int free_entry_index = -1;
    /* Temporary variable to hold the filename of the different entries
       in the root directory */
    char *entry_filename;

    for (unsigned i = 0; i < FS_FILE_MAX_COUNT; i++) {
        /* Converts the int8_t filename array to an array of characters */
        entry_filename = (char *) file_system->root_dir[i].filename;

        /* Compare the different entries filename of the root directory with
        provided filename. Return -1 if the filename matches one of the entires'  */
        if (strcmp(filename, entry_filename) == 0) return -1;

        /* Check if the entry filename is empty assign the index of that entry to
            free_entry_index.*/
        if (strlen(entry_filename) == 0) {
            free_entry_index = i;
            break;
        }

        /* Clean entry_filename before being reused */
        memset(entry_filename, 0, sizeof(char));
    }

    if (free_entry_index != -1) {
        for (int i = 0; i < (int)strlen(filename); i++) {
            /* Convert each character of filename to int8_t */
            file_system->root_dir[free_entry_index].filename[i] = (int8_t) filename[i];
        }

        file_system->root_dir[free_entry_index].file_size = 0;
        file_system->root_dir[free_entry_index].file_first_index = FAT_EOC;
    } else {
        return -1;
    }

    return 0;
}

int get_fat_blck_index(int fat_arr_index) {
    /* Returns the index of the corresponding fat_block */
    if(fat_arr_index == 0) {
        return 0;
    } else {
        return fat_arr_index / FAT_ARR_SIZE;
    }
}

int fs_delete(const char *filename) {
        /* TODO: Phase 2 */

        if(file_system == NULL) return -1;

        if(!isValidName(filename)) return -1;

        uint16_t fat_arr_index = -1, root_dir_index = -1;

        for(int i = 0; i < FILE_DESCRIPTOR_TABLE_SIZE; i++) {
                if(strcmp(fd_table[i].filename, filename) == 0) return -1;
        }

        for(int i = 0; i < FS_FILE_MAX_COUNT; i++) {
                if(strcmp((char*)file_system->root_dir[i].filename, filename) == 0) {
                        fat_arr_index = file_system->root_dir[i].file_first_index;
                        root_dir_index = i;
                        break;
                }
                if(i+1 == FS_FILE_MAX_COUNT) return -1;
        }

        if(fat_arr_index == FAT_EOC) {
                memset(file_system->root_dir[root_dir_index].filename, 0, sizeof(char));
                file_system->root_dir[root_dir_index].file_size = 0;
                file_system->root_dir[root_dir_index].file_first_index = FAT_EOC;
                return 0;
        }


        int block_index = fat_arr_index;
        int fat_block_index = get_fat_blck_index(fat_arr_index);

        while(file_system->fat_blocks[fat_block_index].arr[fat_arr_index] != FAT_EOC) {
                block_index = file_system->fat_blocks[fat_block_index].arr[fat_arr_index];
                file_system->fat_blocks[fat_block_index].arr[fat_arr_index] = 0;
                fat_arr_index = block_index;
                fat_block_index = get_fat_blck_index(fat_arr_index);
        }

        file_system->fat_blocks[fat_block_index].arr[fat_arr_index] = 0;

        memset(file_system->root_dir[root_dir_index].filename, 0, sizeof(char));
        file_system->root_dir[root_dir_index].file_size = 0;
        file_system->root_dir[root_dir_index].file_first_index = FAT_EOC;

        return 0;
}

int fs_ls(void) {
    /* TODO: Phase 2 */
    fprintf(stdout, "FS Ls \n");

    for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        char *entry_filename = (char *) file_system->root_dir[i].filename;

        if (strlen(entry_filename) != 0) {
            fprintf(stdout, "file: %s, ", entry_filename);
            fprintf(stdout, "size: %d, ", file_system->root_dir[i].file_size);
            fprintf(stdout, "data_blk: %d\n", file_system->root_dir[i].file_first_index);
        }
    }
    return 0;
}

int fs_open(const char *filename) {
    /* TODO: Phase 3 */
    if(file_system == NULL) {
        //fprintf(stderr, "No file system mounted\n");
        return -1;
    }

    if(!isValidName(filename)) {
        //fprintf(stderr, "Invalid filename\n");
        return -1;
    }

    if(fd_open_count == FILE_DESCRIPTOR_TABLE_SIZE) {
        //fprintf(stderr, "File descriptor table is full\n");
        return -1;
    }

    bool exist = false;

    /* Checks if the file exist in the root directory */
    for(int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if(strcmp((char*)file_system->root_dir[i].filename, filename) == 0) {
            exist = true;
            break;
        }
    }

    if(!exist) {
       // fprintf(stderr, "ERROR: File does not exits\n");
        return -1;
    }

    int fd = -1;

	/* 	Find the index of a free directory entry */
    for(int i = 0; i < FILE_DESCRIPTOR_TABLE_SIZE; i++) {
        if(fd_table[i].used == 0) {
            strncpy(fd_table[i].filename, filename, strlen(filename));
            fd_table[i].offset = 0;
            fd_table[i].used = true;
            fd = i;
            break;
        }
    }

    if(fd == -1) return -1;

    fd_open_count++;

    return fd;
}

int isvalidFD(int fd) {
    if(file_system == NULL) {
        //fprintf(stderr, "No file system mounted\n");
        return -1;
    }

    if(fd < 0 || fd >= FILE_DESCRIPTOR_TABLE_SIZE) {
        //fprintf(stderr, "Invalid file descriptor\n");
        return -1;
    }

    if(strlen(fd_table[fd].filename) == 0) {
        //fprintf(stderr, "Current file descriptor was not opened\n");
        return -1;
    }

    return 0;
}

int fs_close(int fd) {
    /* TODO: Phase 3 */
    int isValid = !isvalidFD(fd);

    if(!isValid) return -1;

    /* Clear the filename and set the offset of file descriptor to 0 */
    memset(fd_table[fd].filename, 0, sizeof(char));
    fd_table[fd].offset = 0;
    fd_table[fd].used = false;
    print_fd();

    fd_open_count--;

    return 0;
}

int fs_stat(int fd) {
    /* TODO: Phase 3 */
    int isValid = !isvalidFD(fd);

    if(!isValid) return -1;

    /* Loop through the root directory and return corresponding size of file */
    for(int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        char* root_entry_fname = (char*)file_system->root_dir[i].filename;
        if(strcmp(fd_table[fd].filename, root_entry_fname) == 0) {
            return file_system->root_dir[i].file_size;
        }
    }

    /* Should not normally reach this section */
    //fprintf(stderr, "The file does not exist\n");
    return 0;
}

int fs_lseek(int fd, size_t offset) {
    /* TODO: Phase 3 */
    int isValid = !isvalidFD(fd);

    if(!isValid) return -1;

    if(offset > (size_t)fs_stat(fd)) {
        //fprintf(stderr, "Offset exceeds file size\n");
        return -1;
    }

    fd_table[fd].offset = offset;

    return 0;
}

int get_data_blck_index(int fd, size_t offset) {
    int offset_size = -1;
    uint16_t data_blk_index = -1;

    /* Calculate the block count that the offset span */
    offset_size = (offset / BLOCK_SIZE) + 1;

    int file_start_index = -1;

    for(int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        bool str_equal = strcmp((char*)file_system->root_dir[i].filename, fd_table[fd].filename) == 0;
        if(str_equal) {
            /* Get the starting index of the file */
            file_start_index = file_system->root_dir[i].file_first_index;
            break;
        } else if(!str_equal && i == FS_FILE_MAX_COUNT-1) {
            //Couldn't find the file in the root directory
            return -1;
        }
    }

    //If nothing was written in the file
    if(file_start_index == FAT_EOC) return FAT_EOC;

    /* Determine in which fat block the fat index is located */
    int fat_blck_index = get_fat_blck_index(file_start_index);
    int fat_arr_index = file_start_index;

    /* Returns the corresponding data block when the offset_size is 1 */
    if(offset_size == 1) return fat_arr_index;

    data_blk_index = file_system->fat_blocks[fat_blck_index].arr[fat_arr_index];
    for(int i = 1; i < offset_size-1; i++) {
        /* Get the correspoding index of the data block */
       data_blk_index = file_system->fat_blocks[fat_blck_index].arr[data_blk_index];
    }

    return data_blk_index;
}

int find_free_fat_index() {
    int block_index = -1;
    int arr_index = -1;

	/* Find the first available fat entry */
    for(int i = 0; i < file_system->sp.fat_blck_amount; i++) {
        for(int c = 0; c < FAT_ARR_SIZE; c++) {
            if(file_system->fat_blocks[i].arr[c] == 0) {
                block_index = i;
                arr_index = c;
                break;
            }
        }

		/* Returns an error when none were found */
        if(i+1 == file_system->sp.fat_blck_amount) return -1;
    }

	/* Update the entry found with the new data block index */
    file_system->fat_blocks[block_index].arr[arr_index] = block_index*FAT_ARR_SIZE + arr_index;

	/* returns the index of the data block we want to write into */
    return block_index*FAT_ARR_SIZE + arr_index;
}


int fat_entry_end(int fd) {
    int index = -1;

	/* Find the index of specific using the file descriptor */
    for(int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if(strcmp(fd_table[fd].filename, (char*)file_system->root_dir[i].filename) == 0) {
            index = file_system[i].root_dir[i].file_first_index;
        }
    }

    if(index == -1) return -1;

    int prev_index = -1;

	/* go through the linked list of fat indexes 
		save the index preceding the FAT_EOC
	 */
    while(index != FAT_EOC) {
        int fat_blk_index = get_fat_blck_index(index);
        prev_index = index;
        index = file_system->fat_blocks[fat_blk_index].arr[index];
    }

    if(prev_index == -1) return -1;

	/* Find a new entry in the fat table and assign it to FAT_EOC to set end of
	file */
    int free_fat = get_free_fat();
    file_system->fat_blocks[free_fat/BLOCK_SIZE].arr[free_fat%BLOCK_SIZE] = FAT_EOC;

	/* Return index at which data can be written with index of end of file
	updated  */
    return prev_index;
}

int fs_write(int fd, void *buf, size_t count) {
    /* TODO: Phase 4 */
    if(file_system == NULL) return -1;

    int isValid_fd = !isvalidFD(fd);

    if(!isValid_fd || buf == NULL) return -1;


    /* Calculates the number of data blocks that the buffer can span */
    int block_count = (int)((fd_table[fd].offset + count) / BLOCK_SIZE);
    block_count = (fd_table[fd].offset + count) % BLOCK_SIZE == 0? block_count : block_count+1;

    char bouncer[BLOCK_SIZE];
    size_t fd_offset = fd_table[fd].offset;
    size_t buf_offset = 0;
    size_t bouncer_offset = fd_offset;
    size_t size_write = 0;

    int data_block_index = get_data_blck_index(fd, fd_table[fd].offset);

	/* If no data was written */
	// Find a free entry in fat table
    if(data_block_index == FAT_EOC) {
        data_block_index = find_free_fat_index();

        if(data_block_index == -1) return -1;

        memset(bouncer, 0, sizeof(char));
        block_write(data_block_index, bouncer);

        if(fat_entry.block_index == -1) {
            printf("The FAT entries are full...\n");
            return -1;
        }
    }

    for (int i = 0; i < block_count; i++) {
        block_read(data_block_index, bouncer);

		//Calculate the starting offset of the bouncer 
        bouncer_offset += fd_offset % BLOCK_SIZE;

		//size of data to write
        size_write = BLOCK_SIZE*(i+1) - fd_offset; 

        memcpy(bouncer+bouncer_offset, buf+buf_offset, size_write);

		//Update the different offsets
        fd_offset += size_write;
        buf_offset += size_write;
        bouncer_offset = 0;

		//If end of file is reached find new free fat entry and store data
        if(data_block_index == FAT_EOC) {
            data_block_index = fat_entry_end(fd);
            if(data_block_index == -1) return -1;

            char clean_data[BLOCK_SIZE];
            memset(clean_data, 0, sizeof(char));
            block_write(data_block_index, clean_data);
        }

        block_write(data_block_index, bouncer);
    }
    return 0;
}

int fs_read(int fd, void *buf, size_t count) {
    /* TODO: Phase 4 */
    if(file_system == NULL) return -1;

    int isValid_fd = !isvalidFD(fd);

    if(!isValid_fd || buf == NULL) return -1;


    /* Calculates the number of data blocks that the buffer can span */
    int block_count = (int)((fd_table[fd].offset + count) / BLOCK_SIZE);
    block_count = (fd_table[fd].offset + count) % BLOCK_SIZE == 0? block_count : block_count+1;

    char bouncer[BLOCK_SIZE];
    size_t fd_offset = fd_table[fd].offset;
    size_t buf_offset = 0;
    size_t size_read = 0;

    for(int i = 0; i < block_count; i++) {
        /* Get the index of the data block that the offset of file is located in */
        int data_block_index = get_data_blck_index(fd, fd_table[fd].offset);
        /* If we reached the end of the file, we exit the loop */
        if(data_block_index == FAT_EOC) break;

        /* Read entire block into bouncer */
        block_read(data_block_index+file_system->sp.data_blck_index, bouncer);

        if(count < BLOCK_SIZE) {
            /* Copy partial data of a block */
            memcpy(buf+buf_offset, bouncer, count);
            size_read = count;
            count = 0;
        } else {
            // Calculate size to write into buf /
            size_read = BLOCK_SIZE*(i+1) - fd_offset;
            // If fd_offset is a multiple of a block size we start at position
            //0 of bouncer. Else we start at the specified offset. /
            int start = fd_offset % BLOCK_SIZE == 0? 0 : fd_offset;
            memcpy(buf+buf_offset, bouncer+start, size_read);
            // Update the available space of buf /
            count -= size_read;
        }

        buf_offset += size_read;
        fd_offset += size_read;
        fd_table[fd].offset = fd_offset;
    }
    return 0;
}