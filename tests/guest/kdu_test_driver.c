// blook-kdu e2e guest test driver.
//
// A deliberately valid but *unsigned* driver. The e2e suite proves that it
// cannot be loaded while DSE is enabled, loads after kdu dse disable, and can no
// longer be loaded once kdu dse restore put the original g_CiOptions back.
#include <ntddk.h>

NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object,
                     PUNICODE_STRING registry_path) {
    UNREFERENCED_PARAMETER(registry_path);
    // No device, no registry, no threads: just enough to prove the loader ran.
    driver_object->DriverUnload = NULL;
    DbgPrint("[kdu-e2e] guest test driver loaded\n");
    return STATUS_SUCCESS;
}
