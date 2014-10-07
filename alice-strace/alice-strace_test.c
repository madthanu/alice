#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <assert.h>
int main() {
	int fd = open("/tmp/x", O_CREAT | O_RDWR, 0666);
	assert(fd > 0);
	write(fd, "hello", 5);
	pwrite(fd, "world", 5, 4);
	struct iovec x[3];
	x[0].iov_base = "aaa";
	x[0].iov_len = 3;
	x[1].iov_base = "bbb";
	x[1].iov_len = 3;
	x[2].iov_base = "ccc";
	x[2].iov_len = 3;
	writev(fd, x, 3);
	x[0].iov_base = "xxx";
	x[1].iov_base = "yyy";
	x[2].iov_base = "zzz";
	pwritev(fd, x, 3, 10);
}
