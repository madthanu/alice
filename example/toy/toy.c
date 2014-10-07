/* The following is a toy application that (tries to) atomically update a file,
 * then prints a message, and then (tries to) atomically create two links */

#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <stdio.h>

int main() {
	int fd = open("tmp", O_CREAT | O_RDWR, 0666);
	assert(fd > 0);
	int ret = write(fd, "world", 5);
	assert(ret == 5);
	ret = close(fd);
	assert(ret == 0);
	ret = rename("tmp", "file1");
	assert(ret == 0);
	printf("Updated\n");
	ret = link("file1", "link1");
	assert(ret == 0);
	ret = link("file1", "link2");
	assert(ret == 0);
}
