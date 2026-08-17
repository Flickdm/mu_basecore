/** @file
  Standalone MM phase hooks for CryptoIndicatorRegistrationLib.

  The queue/flush policy lives in CryptoIndicatorRegistrationCommon.c; this file
  provides only the Standalone MM means to locate the collector and to arm the
  collector-installation notify. The DXE bridge later drains the MM collector
  into the DXE collector that publishes the table.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/MmServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Protocol/CryptoIndicatorRegistration.h>
#include "CryptoIndicatorRegistrationInternal.h"

STATIC VOID  *mNotifyRegistration = NULL;

/**
  Locate the collector's registration protocol. See
  <CryptoIndicatorRegistrationInternal.h>.
**/
EFI_STATUS
EcitPlatformLocateCollector (
  OUT EFI_CRYPTO_INDICATOR_REGISTRATION_PROTOCOL  **Registration
  )
{
  return gMmst->MmLocateProtocol (
                  &gEfiCryptoIndicatorRegistrationProtocolGuid,
                  NULL,
                  (VOID **)Registration
                  );
}

/**
  MM protocol-notify callback: the MM collector arrived; flush the queue.
**/
STATIC
EFI_STATUS
EFIAPI
OnMmCollectorInstalled (
  IN CONST EFI_GUID  *Protocol,
  IN VOID            *Interface,
  IN EFI_HANDLE      Handle
  )
{
  EcitFlushPending ((EFI_CRYPTO_INDICATOR_REGISTRATION_PROTOCOL *)Interface);
  return EFI_SUCCESS;
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
  if (mNotifyRegistration != NULL) {
    return EFI_SUCCESS;
  }

  return gMmst->MmRegisterProtocolNotify (
                  &gEfiCryptoIndicatorRegistrationProtocolGuid,
                  OnMmCollectorInstalled,
                  &mNotifyRegistration
                  );
}
