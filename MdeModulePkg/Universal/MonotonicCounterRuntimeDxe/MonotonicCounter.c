/** @file
  Produce the UEFI boot service GetNextMonotonicCount() and runtime service
  GetNextHighMonotonicCount().

Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>

#include <Protocol/MonotonicCounter.h>
#include <Protocol/VariablePolicy.h>                // MU_CHANGE

#include <Guid/MtcVendor.h>

#include <Library/BaseLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/VariablePolicyHelperLib.h>        // MU_CHANGE

//
// The handle to install Monotonic Counter Architectural Protocol
//
EFI_HANDLE  mMonotonicCounterHandle = NULL;

//
// The current monotonic counter value
//
UINT64  mEfiMtc;

//
// Event to update the monotonic Counter's high part when low part overflows.
//
EFI_EVENT  mEfiMtcEvent;

/**
  Returns a monotonically increasing count for the platform.

  This function returns a 64-bit value that is numerically larger then the last
  time the function was called.
  The platform monotonic counter is comprised of two parts: the high 32 bits
  and the low 32 bits. The low 32-bit value is volatile and is reset to zero on
  every system reset. It is increased by 1 on every call to GetNextMonotonicCount().
  The high 32-bit value is nonvolatile and is increased by one on whenever the
  system resets or the low 32-bit counter overflows.

  @param  Count                  Pointer to returned value.

  @retval EFI_SUCCESS           The next monotonic count was returned.
  @retval EFI_DEVICE_ERROR      The device is not functioning properly.
  @retval EFI_INVALID_PARAMETER Count is NULL.
  @retval EFI_UNSUPPORTED       This function is called at runtime.

**/
EFI_STATUS
EFIAPI
MonotonicCounterDriverGetNextMonotonicCount (
  OUT UINT64  *Count
  )
{
  EFI_TPL  OldTpl;

  //
  // Cannot be called after ExitBootServices()
  //
  if (EfiAtRuntime ()) {
    return EFI_UNSUPPORTED;
  }

  //
  // Check input parameters
  //
  if (Count == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Update the monotonic counter with a lock
  //
  OldTpl = gBS->RaiseTPL (TPL_HIGH_LEVEL);
  *Count = mEfiMtc;
  mEfiMtc++;
  gBS->RestoreTPL (OldTpl);

  //
  // If the low 32-bit counter overflows (MSB bit toggled),
  // then signal that the high part needs update now.
  //
  if ((((UINT32)mEfiMtc) ^ ((UINT32)*Count)) & BIT31) {
    gBS->SignalEvent (mEfiMtcEvent);
  }

  return EFI_SUCCESS;
}

/**
  Returns the next high 32 bits of the platform's monotonic counter.

  The GetNextHighMonotonicCount() function returns the next high 32 bits
  of the platform's monotonic counter. The platform's monotonic counter is
  comprised of two 32 bit quantities:  the high 32 bits and the low 32 bits.
  During boot service time the low 32 bit value is volatile:  it is reset to
  zero on every system reset and is increased by 1 on every call to GetNextMonotonicCount().
  The high 32 bit value is non-volatile and is increased by 1 whenever the system resets,
  whenever GetNextHighMonotonicCount() is called, or whenever the low 32 bit count
  (returned by GetNextMonoticCount()) overflows.
  The GetNextMonotonicCount() function is only available at boot services time.
  If the operating system wishes to extend the platform monotonic counter to runtime,
  it may do so by utilizing GetNextHighMonotonicCount().  To do this, before calling
  ExitBootServices() the operating system would call GetNextMonotonicCount() to obtain
  the current platform monotonic count.  The operating system would then provide an
  interface that returns the next count by:
    Adding 1 to the last count.
    Before the lower 32 bits of the count overflows, call GetNextHighMonotonicCount().
    This will increase the high 32 bits of the platform's non-volatile portion of the monotonic
    count by 1.

  This function may only be called at Runtime.

  @param  HighCount              Pointer to returned value.

  @retval EFI_SUCCESS           The next high monotonic count was returned.
  @retval EFI_INVALID_PARAMETER HighCount is NULL.
  @retval EFI_DEVICE_ERROR      The variable could not be saved due to a hardware failure.
  @retval EFI_OUT_OF_RESOURCES  If variable service reports that not enough storage
                                is available to hold the variable and its data.
  @retval EFI_UNSUPPORTED       This call is not supported by this platform at the time the call is made.
                                The platform should describe this runtime service as unsupported at runtime
                                via an EFI_RT_PROPERTIES_TABLE configuration table.

**/
EFI_STATUS
EFIAPI
MonotonicCounterDriverGetNextHighMonotonicCount (
  OUT UINT32  *HighCount
  )
{
  EFI_TPL  OldTpl;

  //
  // Check input parameters
  //
  if (HighCount == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (!EfiAtRuntime ()) {
    //
    // Use a lock if called before ExitBootServices()
    //
    OldTpl     = gBS->RaiseTPL (TPL_HIGH_LEVEL);
    *HighCount = (UINT32)RShiftU64 (mEfiMtc, 32) + 1;
    mEfiMtc    = LShiftU64 (*HighCount, 32);
    gBS->RestoreTPL (OldTpl);
  } else {
    *HighCount = (UINT32)RShiftU64 (mEfiMtc, 32) + 1;
    mEfiMtc    = LShiftU64 (*HighCount, 32);
  }

  //
  // Update the NV variable to match the new high part
  //
  return EfiSetVariable (
           MTC_VARIABLE_NAME,
           &gMtcVendorGuid,
           EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS,
           sizeof (UINT32),
           HighCount
           );
}

/**
  Monotonic counter event handler.  This handler updates the high part of monotonic counter.

  @param Event           The event to handle.
  @param Context         The event context.

**/
VOID
EFIAPI
EfiMtcEventHandler (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  UINT32  HighCount;

  MonotonicCounterDriverGetNextHighMonotonicCount (&HighCount);
}

//
// MU_CHANGE begin
//

/**
    OnVariablePolicyProtocolNotification

    Sets the AdvancedLogger Locator variable policy.

    @param[in]      Event   - NULL if called from Entry, Event if called from notification
    @param[in]      Context - VariablePolicy if called from Entry, NULL if called from notification

  **/
STATIC
VOID
EFIAPI
OnVariablePolicyProtocolNotification (
  IN  EFI_EVENT  Event,
  IN  VOID       *Context
  )
{
  EDKII_VARIABLE_POLICY_PROTOCOL  *VariablePolicy = NULL;
  EFI_STATUS                      Status;

  DEBUG ((DEBUG_INFO, "%a: Setting policy for MTC variable, Context=%p\n", __FUNCTION__, Context));

  if (Context != NULL) {
    VariablePolicy = (EDKII_VARIABLE_POLICY_PROTOCOL *)Context;
  } else {
    Status = gBS->LocateProtocol (&gEdkiiVariablePolicyProtocolGuid, NULL, (VOID **)&VariablePolicy);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a: - Locating Variable Policy failed - Code=%r\n", __FUNCTION__, Status));
      ASSERT_EFI_ERROR (Status);
      return;
    }
  }

  Status = RegisterBasicVariablePolicy (
             VariablePolicy,
             &gMtcVendorGuid,
             MTC_VARIABLE_NAME,
             sizeof (UINT32),
             sizeof (UINT32),
             EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE,
             (UINT32) ~(EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE),
             VARIABLE_POLICY_TYPE_NO_LOCK
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: - Error setting policy for MTC - Code=%r\n", __FUNCTION__, Status));
    ASSERT_EFI_ERROR (Status);
  }

  return;
}

//
// MU_CHANGE end
//

/**
  Entry point of monotonic counter driver.

  @param  ImageHandle   The image handle of this driver.
  @param  SystemTable   The pointer of EFI_SYSTEM_TABLE.

  @retval EFI_SUCCESS   The initialization is successful.

**/
EFI_STATUS
EFIAPI
MonotonicCounterDriverInitialize (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                      Status;
  UINT32                          HighCount;
  UINTN                           BufferSize;
  EFI_EVENT                       Event;                   // MU_CHANGE
  VOID                            *ProtocolRegistration;   // MU_CHANGE
  EDKII_VARIABLE_POLICY_PROTOCOL  *VariablePolicy = NULL;  // MU_CHANGE

  //
  // Make sure the Monotonic Counter Architectural Protocol has not been installed in the system yet.
  //
  ASSERT_PROTOCOL_ALREADY_INSTALLED (NULL, &gEfiMonotonicCounterArchProtocolGuid);

  //
  // Initialize event to handle low-part overflow
  //
  Status = gBS->CreateEvent (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  EfiMtcEventHandler,
                  NULL,
                  &mEfiMtcEvent
                  );
  ASSERT_EFI_ERROR (Status);

  //
  // Read the last high part
  //
  BufferSize = sizeof (UINT32);
  Status     = EfiGetVariable (
                 MTC_VARIABLE_NAME,
                 &gMtcVendorGuid,
                 NULL,
                 &BufferSize,
                 &HighCount
                 );
  if (EFI_ERROR (Status)) {
    HighCount = 0;
  }

  //
  // Set the current value
  //
  mEfiMtc = LShiftU64 (HighCount, 32);

  //
  // Increment the upper 32 bits for this boot
  // Continue even if it fails.  It will only fail if the variable services are
  // not functional.
  //
  MonotonicCounterDriverGetNextHighMonotonicCount (&HighCount);

  //
  // Fill in the EFI Boot Services and EFI Runtime Services Monotonic Counter Fields
  //
  gBS->GetNextMonotonicCount     = MonotonicCounterDriverGetNextMonotonicCount;
  gRT->GetNextHighMonotonicCount = MonotonicCounterDriverGetNextHighMonotonicCount;

  //
  // Install the Monotonic Counter Architctural Protocol onto a new handle
  //
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &mMonotonicCounterHandle,
                  &gEfiMonotonicCounterArchProtocolGuid,
                  NULL,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  //
  // MU_CHANGE begin
  //
  // There is no dependency for VariablePolicy Protocol in case this code is used
  // in firmware without VariablePolicy.  And, VariablePolicy may or may not be installed
  // before this driver is run.  If the Variable Policy Protocol is not found, register for
  // a notification that may not occur.

  Status = gBS->LocateProtocol (&gEdkiiVariablePolicyProtocolGuid, NULL, (VOID **)&VariablePolicy);
  if (EFI_ERROR (Status)) {
    Status = gBS->CreateEvent (
                    EVT_NOTIFY_SIGNAL,
                    TPL_CALLBACK,
                    OnVariablePolicyProtocolNotification,
                    NULL,
                    &Event
                    );

    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a: failed to create notification callback event (%r)\n", __FUNCTION__, Status));
      ASSERT_EFI_ERROR (Status);
    } else {
      Status = gBS->RegisterProtocolNotify (
                      &gEdkiiVariablePolicyProtocolGuid,
                      Event,
                      &ProtocolRegistration
                      );

      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "%a: failed to register for notification (%r)\n", __FUNCTION__, Status));
        gBS->CloseEvent (Event);
        ASSERT_EFI_ERROR (Status);
      }
    }
  } else {
    OnVariablePolicyProtocolNotification (NULL, VariablePolicy);
  }

  //
  // MU_CHANGE end
  //

  return EFI_SUCCESS;
}
