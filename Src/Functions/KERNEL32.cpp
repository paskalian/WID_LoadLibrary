#include "KERNEL32.h"

ULONG* KernelBaseGlobalData = nullptr;

tBasep8BitStringToDynamicUnicodeString Basep8BitStringToDynamicUnicodeString = nullptr;
tBaseSetLastNTError BaseSetLastNTError = nullptr;

// Signatured
tBasepLoadLibraryAsDataFileInternal BasepLoadLibraryAsDataFileInternal = nullptr;