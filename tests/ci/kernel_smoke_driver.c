/* blook-kdu: minimal kernel-load smoke driver for CI.
 *
 * Deliberately tiny and hang-free: no threads, no timers, no worker, no
 * registry access. DriverEntry creates one device + symbolic link and one
 * buffered IOCTL returns a magic DWORD. CI signs this image with the SPC
 * signer, starts it as a service and asserts STATE 4 RUNNING plus one
 * DeviceIoControl round-trip.
 */
#include <ntddk.h>

#define KDU_CI_SMOKE_DEVICE L"\\Device\\KduCiSmoke"
#define KDU_CI_SMOKE_LINK L"\\DosDevices\\KduCiSmoke"

#define KDU_CI_SMOKE_DEVICE_TYPE 0x8333
#define KDU_CI_SMOKE_IOCTL                                                    \
    CTL_CODE(KDU_CI_SMOKE_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define KDU_CI_SMOKE_MAGIC 0x5355444B /* "KDUS" */

static PDEVICE_OBJECT g_device = NULL;
static UNICODE_STRING g_link;

static NTSTATUS smoke_create(PDEVICE_OBJECT device, PIRP irp) {
    UNREFERENCED_PARAMETER(device);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS smoke_control(PDEVICE_OBJECT device, PIRP irp) {
    UNREFERENCED_PARAMETER(device);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;
    if (stack->Parameters.DeviceIoControl.IoControlCode ==
        KDU_CI_SMOKE_IOCTL) {
        if (stack->Parameters.DeviceIoControl.OutputBufferLength >=
            sizeof(ULONG)) {
            *(ULONG*)irp->AssociatedIrp.SystemBuffer = KDU_CI_SMOKE_MAGIC;
            information = sizeof(ULONG);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
    }
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS smoke_dispatch(PDEVICE_OBJECT device, PIRP irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    switch (stack->MajorFunction) {
        case IRP_MJ_CREATE:
        case IRP_MJ_CLOSE:
            return smoke_create(device, irp);
        case IRP_MJ_DEVICE_CONTROL:
            return smoke_control(device, irp);
        default:
            irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_INVALID_DEVICE_REQUEST;
    }
}

static VOID smoke_unload(PDRIVER_OBJECT driver) {
    UNREFERENCED_PARAMETER(driver);
    if (g_device) {
        IoDeleteDevice(g_device);
        g_device = NULL;
    }
    RtlFreeUnicodeString(&g_link);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry_path) {
    UNREFERENCED_PARAMETER(registry_path);
    UNICODE_STRING device_name;
    RtlInitUnicodeString(&device_name, KDU_CI_SMOKE_DEVICE);
    NTSTATUS status = IoCreateDevice(driver, 0, &device_name,
                                     FILE_DEVICE_UNKNOWN, 0, FALSE, &g_device);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    g_device->Flags |= DO_BUFFERED_IO;
    RtlInitUnicodeString(&g_link, KDU_CI_SMOKE_LINK);
    status = IoCreateSymbolicLink(&g_link, &device_name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_device);
        g_device = NULL;
        return status;
    }
    driver->DriverUnload = smoke_unload;
    for (ULONG index = 0; index <= IRP_MJ_MAXIMUM_FUNCTION; ++index) {
        driver->MajorFunction[index] = smoke_dispatch;
    }
    return STATUS_SUCCESS;
}

