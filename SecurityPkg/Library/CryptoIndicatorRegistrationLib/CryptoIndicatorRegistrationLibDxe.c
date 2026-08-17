/** @file
  DXE phase hooks for CryptoIndicatorRegistrationLib.

  The queue/flush policy lives in CryptoIndicatorRegistrationCommon.c; this file
  provides only the DXE means to locate the collector and to arm the
  collector-installation notify.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Protocol/CryptoIndicatorRegistration.h>
#include "CryptoIndicatorRegistrationInternal.h"

STATIC EFI_EVENT  mNotifyEvent        = NULL;
STATIC VOID       *mNotifyRegistration = NULL;

/**
  Locate the collector's registration protocol. See
  <CryptoIndicatorRegistrationInternal.h>.
**/
EFI_STATUS
EcitPlatformLocateCollector (
  OUT EFI_CRYPTO_INDICATOR_REGISTRATION_PROTOCOL  **Registration
  )
{
  return gBS->LocateProtocol (
                &gEfiCryptoIndicatorRegistrationProtocolGuid,
                NULL,
                (VOID **)Registration
                );
}

/**
  Protocol-notify callback: the collector arrived; flush the queue.
**/
STATIC
VOID
EFIAPI
OnCollectorInstalled (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS                                  Status;
  EFI_CRYPTO_INDICATOR_REGISTRATION_PROTOCOL  *Registration;

  Status = gBS->LocateProtocol (
                  &gEfiCryptoIndicatorRegistrationProtocolGuid,
                  mNotifyRegistration,
                  (VOID **)&Registration
                  );
  if (EFI_ERROR (Status)) {
    return;
  }

  EcitFlushPending (Registration);

  gBS->CloseEvent (Event);
  mNotifyEvent = NULL;
}

/**
  Idempotently arm the collector-installation notify. See
  <CryptoIndicatorRegistrationInternal.h>.
**/
EFI_STATUS
EcitPlatformArmNotify (
  VOID
  )
{
  EFI_STATUS  Status;

  if (mNotifyEvent != NULL) {
    return EFI_SUCCESS;
  }

  Status = gBS->CreateEvent (EVT_NOTIFY_SIGNAL, TPL_CALLBACK, OnCollectorInstalled, NULL, &mNotifyEvent);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gBS->RegisterProtocolNotify (
                  &gEfiCryptoIndicatorRegistrationProtocolGuid,
                  mNotifyEvent,
                  &mNotifyRegistration
                  );
  if (EFI_ERROR (Status)) {
    gBS->CloseEvent (mNotifyEvent);
    mNotifyEvent = NULL;
  }

  return Status;
}
