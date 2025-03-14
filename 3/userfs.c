#include "userfs.h"

#include <string.h>
#include <stdlib.h>

#define FD_ARRAY_INIT_CAP 10
#define FD_ARRAY_GROW_CAP 2

enum {
	BLOCK_SIZE = 4 * 1024,
	MAX_FILE_SIZE = 1024 * 1024 * 100,
};

/** Global error code. Set from any function on any error. */
static enum ufs_error_code ufs_error_code = UFS_ERR_NO_ERR;

struct block {
	/** Block memory. */
	char *memory;
	/** How many bytes are occupied. */
	int occupied;
	/** Next block in the file. */
	struct block *next;
	/** Previous block in the file. */
	struct block *prev;

	/* PUT HERE OTHER MEMBERS */
};

struct file {
	/** Double-linked list of file blocks. */
	struct block *block_list;
	/**
	 * Last block in the list above for fast access to the end
	 * of file.
	 */
	struct block *last_block;
	/** How many file descriptors are opened on the file. */
	int refs;
	/** File name. */
	char *name;
	/** Files are stored in a double-linked list. */
	struct file *next;
	struct file *prev;

	int deleted;
};

/** List of all files. */
static struct file *file_list = NULL;

struct filedesc {
	struct file *file;

	int block_number;
	int block_offset;

	enum open_flags flags;
};

/**
 * An array of file descriptors. When a file descriptor is
 * created, its pointer drops here. When a file descriptor is
 * closed, its place in this array is set to NULL and can be
 * taken by next ufs_open() call.
 */
static struct filedesc **file_descriptors = NULL;
static int file_descriptor_count = 0;
static int file_descriptor_capacity = 0;

enum ufs_error_code
ufs_errno()
{
	return ufs_error_code;
}

static enum ufs_error_code
ufs_init()
{
	file_descriptors = calloc(FD_ARRAY_INIT_CAP, sizeof(struct filedesc *));
	if (file_descriptors == NULL) {
		return UFS_ERR_NO_MEM;
	}

	file_descriptor_count = 0;
	file_descriptor_capacity = FD_ARRAY_INIT_CAP;

	return UFS_ERR_NO_ERR;
}

static enum ufs_error_code
ufs_realloc_fd_array()
{
	int new_fd_capacity = file_descriptor_capacity;
	if (file_descriptor_count == file_descriptor_capacity) {
		new_fd_capacity = file_descriptor_capacity * FD_ARRAY_GROW_CAP;
	}
	else if (file_descriptor_count * FD_ARRAY_GROW_CAP < file_descriptor_capacity &&
			file_descriptor_capacity > FD_ARRAY_INIT_CAP) {
		new_fd_capacity = file_descriptor_capacity / FD_ARRAY_GROW_CAP;
	}

	if (new_fd_capacity == file_descriptor_capacity) {
		return UFS_ERR_NO_ERR;
	}

	struct filedesc **new_descriptors = realloc(
		file_descriptors,
		sizeof(struct filedesc *) * new_fd_capacity
	);
	if (new_descriptors == NULL) {
		return UFS_ERR_NO_MEM;
	}

	memset(new_descriptors + file_descriptor_count, 0, sizeof(struct filedesc *) * (new_fd_capacity - file_descriptor_count));

	file_descriptors = new_descriptors;
	file_descriptor_capacity = new_fd_capacity;

	return UFS_ERR_NO_ERR;
}

static enum ufs_error_code
ufs_file_add_block(struct file *f)
{
	struct block *result = calloc(1, sizeof(struct block));
	if (result == NULL) {
		return UFS_ERR_NO_MEM;
	}

	result->memory = calloc(BLOCK_SIZE, 1);
	if (result->memory == NULL) {
		free(result);
		return UFS_ERR_NO_MEM;
	}

	if (f->block_list == NULL) {
		f->last_block = f->block_list = result;
	}
	else {
		f->last_block->next = result;
		result->prev = f->last_block;
		f->last_block = result;
	}

	return UFS_ERR_NO_ERR;
}

static void
ufs_file_delete_block_list(struct block *block_iter)
{
	while (block_iter != NULL) {
		struct block *next = block_iter->next;
		free(block_iter->memory);
		free(block_iter);
		block_iter = next;
	}
}

static struct file *
ufs_create_file(const char *filename)
{
	struct file *new_file = calloc(1, sizeof(struct file));
	if (new_file == NULL) {
		return NULL;
	}

	new_file->name = strdup(filename);
	if (new_file->name == NULL) {
		free(new_file);
		return NULL;
	}

	if (ufs_file_add_block(new_file) != UFS_ERR_NO_ERR) {
		free(new_file->name);
		free(new_file);
		return NULL;
	}

	return new_file;
}

static void
ufs_delete_file(struct file *file)
{
	if (file->prev != NULL) {
		file->prev->next = file->next;
	}

	if (file->next != NULL) {
		file->next->prev = file->prev;
	}

	if (file == file_list) {
		file_list = file->next;
	}

	ufs_file_delete_block_list(file->block_list);
	free(file->name);
	free(file);
}

static struct filedesc *
ufs_create_filedesc(struct file *file, enum open_flags flags)
{
	struct filedesc *fd = calloc(1, sizeof(struct filedesc));
	if (fd == NULL) {
		return NULL;
	}

	fd->file = file;
	fd->flags = flags;

	return fd;
}

static int
ufs_fd_writable(struct filedesc *desc)
{
	return desc->flags == 0 ||
		(desc->flags & UFS_CREATE) != 0 ||
		(desc->flags & UFS_WRITE_ONLY) != 0 ||
		(desc->flags & UFS_READ_WRITE) != 0;
}

static int
ufs_fd_readable(struct filedesc *desc)
{
	return desc->flags == 0 ||
		(desc->flags & UFS_CREATE) != 0 ||
		(desc->flags & UFS_READ_ONLY) != 0 ||
		(desc->flags & UFS_READ_WRITE) != 0;
}

int
ufs_open(const char *filename, int flags)
{
	if (file_descriptors == NULL) {
		ufs_error_code = ufs_init();
		if (ufs_error_code != UFS_ERR_NO_ERR) {
			return -1;
		}
	}

	struct file *file = file_list;
	while (file != NULL) {
		if (strcmp(file->name, filename) == 0 && file->deleted == 0) {
			break;
		}

		file = file->next;
	}

	if (file == NULL) {
		if ((flags & UFS_CREATE) == 0) {
			ufs_error_code = UFS_ERR_NO_FILE;
			return -1;
		}

		file = ufs_create_file(filename);
		if (file == NULL) {
			ufs_error_code = UFS_ERR_NO_MEM;
			return -1;
		}

		file->prev = NULL;

		if (file_list != NULL) {
			file->next = file_list;
			file_list->prev = file;
		}

		file_list = file;
	}

	int file_desc = 0;
	while (file_desc < file_descriptor_capacity) {
		if (file_descriptors[file_desc] == NULL) {
			break;
		}

		++file_desc;
	}

	if (file_desc == file_descriptor_capacity) {
		ufs_error_code = ufs_realloc_fd_array();
		if (ufs_error_code != UFS_ERR_NO_ERR) {
			return -1;
		}
	}

	struct filedesc *fd = ufs_create_filedesc(file, flags);
	if (fd == NULL) {
		ufs_error_code = UFS_ERR_NO_MEM;
		return -1;
	}

	++file->refs;
	file_descriptors[file_desc] = fd;
	if (file_desc == file_descriptor_count) {
		++file_descriptor_count;
	}

	ufs_error_code = UFS_ERR_NO_ERR;
	return file_desc;
}

ssize_t
ufs_write(int fd, const char *buf, size_t size)
{
	if (fd < 0 || fd >= file_descriptor_count || file_descriptors[fd] == NULL) {
		ufs_error_code = UFS_ERR_NO_FILE;
		return -1;
	}

	struct filedesc *desc = file_descriptors[fd];
	if (!ufs_fd_writable(desc)) {
		ufs_error_code = UFS_ERR_NO_PERMISSION;
		return -1;
	}

	struct file *file = desc->file;
	struct block *file_block = file->block_list;
	int block_iter = 0;

	while (block_iter < desc->block_number) {
		file_block = file_block->next;
		++block_iter;
	}

	ssize_t written = 0;
	size_t byte_size = file_block->occupied + block_iter * BLOCK_SIZE;

	if (byte_size + size > MAX_FILE_SIZE) {
		ufs_error_code = UFS_ERR_NO_MEM;
		return -1;
	}

	while ((size_t) written < size) {
		if (desc->block_offset == BLOCK_SIZE) {
			file_block = file_block->next;
			if (file_block == NULL) {
				ufs_error_code = ufs_file_add_block(file);
				if (ufs_error_code != UFS_ERR_NO_ERR) {
					return written;
				}

				file_block = file->last_block;
			}

			desc->block_offset = 0;
			++desc->block_number;
		}

		size_t bytes_to_write = BLOCK_SIZE - desc->block_offset;
		if (size - written < bytes_to_write) {
			bytes_to_write = size - written;
		}

		memcpy(file_block->memory + desc->block_offset, buf + written, bytes_to_write);

		desc->block_offset += bytes_to_write;
		written += bytes_to_write;

		if (desc->block_offset > file_block->occupied) {
			file_block->occupied = desc->block_offset;
		}
	}

	ufs_error_code = UFS_ERR_NO_ERR;
	return written;
}

ssize_t
ufs_read(int fd, char *buf, size_t size)
{
	if (fd < 0 || fd >= file_descriptor_count || file_descriptors[fd] == NULL) {
		ufs_error_code = UFS_ERR_NO_FILE;
		return -1;
	}

	struct filedesc *desc = file_descriptors[fd];
	if (!ufs_fd_readable(desc)) {
		ufs_error_code = UFS_ERR_NO_PERMISSION;
		return -1;
	}

	struct file *file = desc->file;
	struct block *file_block = file->block_list;
	int block_iter = 0;

	while (block_iter < desc->block_number) {
		file_block = file_block->next;
		++block_iter;
	}

	ssize_t read = 0;

	while ((size_t) read < size) {
		if (desc->block_offset == BLOCK_SIZE) {
			file_block = file_block->next;
			if (file_block == NULL) {
				ufs_error_code = UFS_ERR_NO_ERR;
				return read;
			}

			desc->block_offset = 0;
			++desc->block_number;
		}

		size_t bytes_to_read = file_block->occupied - desc->block_offset;
		if (size - read < bytes_to_read) {
			bytes_to_read = size - read;
		}

		if (bytes_to_read == 0) {
			ufs_error_code = UFS_ERR_NO_ERR;
			return read;
		}

		memcpy(buf + read, file_block->memory + desc->block_offset, bytes_to_read);

		desc->block_offset += bytes_to_read;
		read += bytes_to_read;
	}

	ufs_error_code = UFS_ERR_NO_ERR;
	return read;
}

int
ufs_close(int fd)
{
	if (fd < 0 || fd > file_descriptor_count || file_descriptors[fd] == NULL) {
		ufs_error_code = UFS_ERR_NO_FILE;
		return -1;
	}

	struct filedesc *desc = file_descriptors[fd];
	struct file *file = desc->file;
	--file->refs;

	if (file->deleted == 1 && file->refs == 0) {
		ufs_delete_file(file);
	}

	free(desc);

	file_descriptors[fd] = NULL;

	if (file_descriptor_count - 1 == fd) {
		while (file_descriptor_count > 0 && file_descriptors[file_descriptor_count - 1] == NULL) {
			--file_descriptor_count;
		}
	}

	ufs_realloc_fd_array();

	ufs_error_code = UFS_ERR_NO_ERR;
	return 0;
}

int
ufs_delete(const char *filename)
{
	struct file *iter = file_list;
	while (iter != NULL) {
		if (strcmp(iter->name, filename) == 0 && iter->deleted == 0) {
			break;
		}

		iter = iter->next;
	}

	if (iter == NULL) {
		ufs_error_code = UFS_ERR_NO_FILE;
		return -1;
	}

	if (iter->refs != 0) {
		iter->deleted = 1;
	}
	else {
		ufs_delete_file(iter);
	}

	ufs_error_code = UFS_ERR_NO_ERR;
	return 0;
}

#if NEED_RESIZE

int
ufs_resize(int fd, size_t new_size)
{
	if (fd < 0 || fd > file_descriptor_count || file_descriptors[fd] == NULL) {
		ufs_error_code = UFS_ERR_NO_FILE;
		return -1;
	}

	if (new_size > MAX_FILE_SIZE) {
		ufs_error_code = UFS_ERR_NO_MEM;
		return -1;
	}

	struct filedesc *desc = file_descriptors[fd];
	if (!ufs_fd_writable(desc)) {
		ufs_error_code = UFS_ERR_NO_PERMISSION;
		return -1;
	}

	struct file *file = desc->file;
	struct block *block_iter = file->block_list;

	size_t curr_size = 0;
	int curr_block = 0;

	while (block_iter != NULL) {
		curr_size += block_iter->occupied;

		if (curr_size > new_size) {
			break;
		}

		block_iter = block_iter->next;
		++curr_block;
	}

	if (curr_size > new_size && block_iter != NULL) {
		ufs_file_delete_block_list(block_iter->next);
		file->last_block = block_iter;
		block_iter->occupied = new_size - curr_block * BLOCK_SIZE;

		for (int i = 0; i < file_descriptor_count; ++i) {
			struct filedesc *desc = file_descriptors[i];
			if (desc->file != file) {
				continue;
			}

			if (desc->block_number >= curr_block) {
				desc->block_number = curr_block;

				if (desc->block_offset > block_iter->occupied) {
					desc->block_offset = block_iter->occupied;
				}
			}
		}
	}
	else {
		curr_size += BLOCK_SIZE - block_iter->occupied;
		block_iter->occupied = BLOCK_SIZE;

		while (new_size > curr_size) {
			ufs_error_code = ufs_file_add_block(file);
			if (ufs_error_code != UFS_ERR_NO_ERR) {
				return -1;
			}

			file->last_block->occupied = BLOCK_SIZE;
			curr_size += BLOCK_SIZE;
			++curr_block;
		}

		file->last_block->occupied = new_size - curr_block * BLOCK_SIZE;
	}

	ufs_error_code = UFS_ERR_NO_ERR;
	return 0;
}

#endif

void
ufs_destroy(void)
{
	for (int i = 0; i < file_descriptor_count; ++i) {
		free(file_descriptors[i]);
	}

	free(file_descriptors);
	file_descriptors = NULL;

	while (file_list != NULL) {
		ufs_delete_file(file_list);
	}
}
