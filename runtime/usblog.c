// LD_PRELOAD shim: logs every libusb-0.1 call made by the Validity binaries,
// forwarding to the real libusb-0.1 (libusb-compat). Log file: $VFSLOG (default stderr).
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

typedef struct usb_dev_handle usb_dev_handle;

static FILE *logf;

static void log_open(void)
{
	if (logf)
		return;
	const char *p = getenv("VFSLOG");
	logf = p ? fopen(p, "a") : NULL;
	if (!logf)
		logf = stderr;
	setvbuf(logf, NULL, _IOLBF, 0);
}

static void logmsg(const char *fmt, ...)
{
	struct timeval tv;
	va_list ap;

	log_open();
	gettimeofday(&tv, NULL);
	fprintf(logf, "%ld.%06ld ", (long)tv.tv_sec, (long)tv.tv_usec);
	va_start(ap, fmt);
	vfprintf(logf, fmt, ap);
	va_end(ap);
}

static void loghex(const char *bytes, int len)
{
	log_open();
	for (int i = 0; i < len; i++)
		fprintf(logf, "%02x", (unsigned char)bytes[i]);
	fputc('\n', logf);
}

#define REAL(ret, name, ...)                                        \
	static ret (*real_##name)(__VA_ARGS__);                     \
	if (!real_##name)                                           \
		real_##name = dlsym(RTLD_NEXT, #name);

int usb_bulk_write(usb_dev_handle *dev, int ep, const char *bytes, int size, int timeout)
{
	REAL(int, usb_bulk_write, usb_dev_handle *, int, const char *, int, int)
	int r = real_usb_bulk_write(dev, ep, bytes, size, timeout);
	logmsg("OUT ep=%02x len=%d ret=%d data=", ep, size, r);
	loghex(bytes, size);
	return r;
}

int usb_bulk_read(usb_dev_handle *dev, int ep, char *bytes, int size, int timeout)
{
	REAL(int, usb_bulk_read, usb_dev_handle *, int, char *, int, int)
	int r = real_usb_bulk_read(dev, ep, bytes, size, timeout);
	logmsg("IN  ep=%02x req=%d ret=%d data=", ep, size, r);
	loghex(bytes, r > 0 ? r : 0);
	return r;
}

int usb_reset(usb_dev_handle *dev)
{
	REAL(int, usb_reset, usb_dev_handle *)
	int r = real_usb_reset(dev);
	logmsg("usb_reset ret=%d\n", r);
	return r;
}

int usb_set_configuration(usb_dev_handle *dev, int configuration)
{
	REAL(int, usb_set_configuration, usb_dev_handle *, int)
	int r = real_usb_set_configuration(dev, configuration);
	logmsg("usb_set_configuration %d ret=%d\n", configuration, r);
	return r;
}

int usb_claim_interface(usb_dev_handle *dev, int interface)
{
	REAL(int, usb_claim_interface, usb_dev_handle *, int)
	int r = real_usb_claim_interface(dev, interface);
	logmsg("usb_claim_interface %d ret=%d\n", interface, r);
	return r;
}

int usb_set_altinterface(usb_dev_handle *dev, int alternate)
{
	REAL(int, usb_set_altinterface, usb_dev_handle *, int)
	int r = real_usb_set_altinterface(dev, alternate);
	logmsg("usb_set_altinterface %d ret=%d\n", alternate, r);
	return r;
}
