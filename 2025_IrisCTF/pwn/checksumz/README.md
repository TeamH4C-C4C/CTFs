# checksumz (432 Points)
## 0x0 Overview
해당 문제에서 주어지는 `README.md` 파일을 보고 커널 문제를 친절하게 낼 수 있다는 것에 큰 감동을 받았다.
커널 모듈의 소스 코드가 주어지기 때문에 분석에 큰 어려움이 존재하지 않고, 제공된 `README.md` 파일 덕분에 처음 커널을 학습하는데 있어 많은 도움을 줄 것이라 판단된다.


## 0x01 Analysis

소스코드를 확인하면 특별한 동작을 수행하지 않고, read, write, lseek, ioctl 기능이 포함되어 있다.
주어진 커널 모듈 소스코드는 아래와 같다:

<details><summary>chal.c</summary>

```c
// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This kernel module has serious security issues (and probably some implementation
 * issues), and might crash your kernel at any time. Please don't load this on any
 * system that you actually care about. I recommend using a virtual machine for this.
 * You have been warned.
 */

#define DEVICE_NAME "checksumz"
#define pr_fmt(fmt) DEVICE_NAME ": " fmt

#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/uio.h>
#include <linux/version.h>

#include "api.h"

static void adler32(const void *buf, size_t len, uint32_t* s1, uint32_t* s2) {
     const uint8_t *buffer = (const uint8_t*)buf;
 
     for (size_t n = 0; n < len; n++) {
        *s1 = (*s1 + buffer[n]) % 65521;
        *s2 = (*s2 + *s1) % 65521;
     }
}

/* ***************************** DEVICE OPERATIONS ***************************** */

static loff_t checksumz_llseek(struct file *file, loff_t offset, int whence) {
	struct checksum_buffer* buffer = file->private_data;

	switch (whence) {
		case SEEK_SET:
			buffer->pos = offset;
			break;
		case SEEK_CUR:
			buffer->pos += offset;
			break;
		case SEEK_END:
			buffer->pos = buffer->size - offset;
			break;
		default:
			return -EINVAL;
	}

	if (buffer->pos < 0)
		buffer->pos = 0;

	if (buffer->pos >= buffer->size)
		buffer->pos = buffer->size - 1;

	return buffer->pos;
}

static ssize_t checksumz_write_iter(struct kiocb *iocb, struct iov_iter *from) {
        struct checksum_buffer* buffer = iocb->ki_filp->private_data;
        size_t bytes = iov_iter_count(from);
 
        if (!buffer)
			return -EBADFD;
        if (!bytes)
			return 0;

		ssize_t copied = copy_from_iter(buffer->state + buffer->pos, min(bytes, 16), from);
 
		buffer->pos += copied;
		if (buffer->pos >= buffer->size)
			buffer->pos = buffer->size - 1;
		
        return copied;
}

static ssize_t checksumz_read_iter(struct kiocb *iocb, struct iov_iter *to) {
	struct checksum_buffer* buffer = iocb->ki_filp->private_data;
	size_t bytes = iov_iter_count(to);

	if (!buffer)
		return -EBADFD;
	if (!bytes)
		return 0;
	if (buffer->read >= buffer->size) {
		buffer->read = 0;
		return 0;
	}

	ssize_t copied = copy_to_iter(buffer->state + buffer->pos, min(bytes, 256), to);

	buffer->read += copied;
	buffer->pos += copied;
	if (buffer->pos >= buffer->size)
		buffer->pos = buffer->size - 1;

	return copied;
}

static long checksumz_ioctl(struct file *file, unsigned int command, unsigned long arg) {
	struct checksum_buffer* buffer = file->private_data;

	if (!file->private_data)
		return -EBADFD;
	
	switch (command) {
		case CHECKSUMZ_IOCTL_RESIZE:
			if (arg <= buffer->size && arg > 0) {
				buffer->size = arg;
				buffer->pos = 0;
			} else
				return -EINVAL;

			return 0;
		case CHECKSUMZ_IOCTL_RENAME:
			char __user *user_name_buf = (char __user*) arg;

			if (copy_from_user(buffer->name, user_name_buf, 48)) {
				return -EFAULT;
			}

			return 0;
		case CHECKSUMZ_IOCTL_PROCESS:
			adler32(buffer->state, buffer->size, &buffer->s1, &buffer->s2);
			memset(buffer->state, 0, buffer->size);
			return 0;
		case CHECKSUMZ_IOCTL_DIGEST:
			uint32_t __user *user_digest_buf = (uint32_t __user*) arg;
			uint32_t digest = buffer->s1 | (buffer->s2 << 16);

			if (copy_to_user(user_digest_buf, &digest, sizeof(uint32_t))) {
				return -EFAULT;
			}

			return 0;
		default:
			return -EINVAL;
	}

	return 0;
}

/* This is the counterpart to open() */
static int checksumz_open(struct inode *inode, struct file *file) {
	file->private_data = kzalloc(sizeof(struct checksum_buffer), GFP_KERNEL);

	struct checksum_buffer* buffer = (struct checksum_buffer*) file->private_data;

	buffer->pos = 0;
	buffer->size = 512;
	buffer->read = 0;
	buffer->name = kzalloc(1000, GFP_KERNEL);
	buffer->s1 = 1;
	buffer->s2 = 0;

	const char* def = "default";
	memcpy(buffer->name, def, 8);

	for (size_t i = 0; i < buffer->size; i++)
		buffer->state[i] = 0;

	return 0;
}

/* This is the counterpart to the final close() */
static int checksumz_release(struct inode *inode, struct file *file)
{
	if (file->private_data)
		kfree(file->private_data);
	return 0;
}

/* All the operations supported on this file */
static const struct file_operations checksumz_fops = {
	.owner = THIS_MODULE,
	.open = checksumz_open,
	.release = checksumz_release,
	.unlocked_ioctl = checksumz_ioctl,
	.write_iter = checksumz_write_iter,
	.read_iter = checksumz_read_iter,
	.llseek = checksumz_llseek,
};


/* ***************************** INITIALIZATION AND CLEANUP (You can mostly ignore this.) ***************************** */

static dev_t device_region_start;
static struct class *device_class;
static struct cdev device;

/* Create the device class */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
static inline struct class *checksumz_create_class(void) { return class_create(DEVICE_NAME); }
#else
static inline struct class *checksumz_create_class(void) { return class_create(THIS_MODULE, DEVICE_NAME); }
#endif

/* Make the device file accessible to normal users (rw-rw-rw-) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
static char *device_node(const struct device *dev, umode_t *mode) { if (mode) *mode = 0666; return NULL; }
#else
static char *device_node(struct device *dev, umode_t *mode) { if (mode) *mode = 0666; return NULL; }
#endif

/* Create the device when the module is loaded */
static int __init checksumz_init(void)
{
	int err;

	if ((err = alloc_chrdev_region(&device_region_start, 0, 1, DEVICE_NAME)))
		return err;

	err = -ENODEV;

	if (!(device_class = checksumz_create_class()))
		goto cleanup_region;
	device_class->devnode = device_node;

	if (!device_create(device_class, NULL, device_region_start, NULL, DEVICE_NAME))
		goto cleanup_class;

	cdev_init(&device, &checksumz_fops);
	if ((err = cdev_add(&device, device_region_start, 1)))
		goto cleanup_device;

	return 0;

cleanup_device:
	device_destroy(device_class, device_region_start);
cleanup_class:
	class_destroy(device_class);
cleanup_region:
	unregister_chrdev_region(device_region_start, 1);
	return err;
}

/* Destroy the device on exit */
static void __exit checksumz_exit(void)
{
	cdev_del(&device);
	device_destroy(device_class, device_region_start);
	class_destroy(device_class);
	unregister_chrdev_region(device_region_start, 1);
}

module_init(checksumz_init);
module_exit(checksumz_exit);

/* Metadata that the kernel really wants */
MODULE_DESCRIPTION("/dev/" DEVICE_NAME ": a vulnerable kernel module");
MODULE_AUTHOR("LambdaXCF <hello@lambda.blog>");
MODULE_LICENSE("GPL");
```

</details>

<br>

눈여겨 봐야할 부분은 read, write이다.
read, write함수에서 `buffer->state + buffer->pos`와 복사할 사이즈에 대한 validation check가 미흡해 `checksum_buffer` 구조체 뒤의 맴버 변수의 데이터를 읽어오거나 수정할 수 있다.

read, write에서 문제가 발생하는 부분은 다음과 같다:

<details><summary>Vulnerability Vector</summary>

```c
static ssize_t checksumz_write_iter(struct kiocb *iocb, struct iov_iter *from) {
        struct checksum_buffer* buffer = iocb->ki_filp->private_data;
        size_t bytes = iov_iter_count(from);
 
        if (!buffer)
			return -EBADFD;
        if (!bytes)
			return 0;

		ssize_t copied = copy_from_iter(buffer->state + buffer->pos, min(bytes, 16), from);
        // [...]
}

static ssize_t checksumz_read_iter(struct kiocb *iocb, struct iov_iter *to) {
	struct checksum_buffer* buffer = iocb->ki_filp->private_data;
	size_t bytes = iov_iter_count(to);

	if (!buffer)
		return -EBADFD;
	if (!bytes)
		return 0;
	if (buffer->read >= buffer->size) {
		buffer->read = 0;
		return 0;
	}

	ssize_t copied = copy_to_iter(buffer->state + buffer->pos, min(bytes, 256), to);
    // [...]
}
```

</details>

<br>

`buffer->state` 다음에는 `buffer->name` 값이 존재하는데 해당 데이터를 릭해 slab 주소를 얻을 수 있다.
하지만, `CONFIG_SLAB_FREELIST_RANDOM` 옵션이 enable 되어 있어 힙의 주소를 예측할 수 없어 kbase를 구하기 위해서는 brute force를 진행해 주어야한다.
또, `buffer->size`도 존재하기 때문에 `buffer->pos` 검증을 무효화 시킬 수 있다. 따라서, `AAW`, `AAR` 가능하다.

checksum_buffer 구조체는 다음과 같다:

<details><summary>struct checksum_buffer</summary>

```c
struct checksum_buffer {
	loff_t pos;
	char state[512];
	size_t size;
	size_t read;
	char* name;
	uint32_t s1;
	uint32_t s2;
};
```

</details>

## 0x02 Exploit

AAW, AAR을 통해서 `0xfffffe0000000000`에 고정된 IDT를 읽어 KASLR를 bypass하고 modprobe_path를 overwrite하여 익스를 진행하였다.