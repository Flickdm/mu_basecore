/** @file
  Shared queue/flush core for CryptoIndicatorRegistrationLib instances.

  Both the DXE and Standalone MM instances behave identically: submit the record
  to the ECIT collector's registration protocol if it is present, otherwise
  queue it and flush automatically when the collector installs. Only the means
  of locating the collector and arming the installation notify are phase
  specific; those are supplied through CryptoIndicatorRegistrationInternal.h.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/CryptoIndicatorRegistrationLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Protocol/CryptoIndicatorRegistration.h>
#include "CryptoIndicatorRegistrationInternal.h"

typedef struct {
  LIST_ENTRY    Link;
  EFI_GUID      FeatureIdentifier;
  UINTN         DataSize;
  UINT8         *Data;
} ECIT_PENDING_NODE;

STATIC LIST_ENTRY  mPendingList = INITIALIZE_LIST_HEAD_VARIABLE (mPendingList);

/**
  Flush every queued record to the collector, freeing the queue as it goes.
  See <CryptoIndicatorRegistrationInternal.h>.
**/
VOID
EcitFlushPending (
  IN EFI_CRYPTO_INDICATOR_REGISTRATION_PROTOCOL  *Registration
  )
{
  LIST_ENTRY         *Link;
  ECIT_PENDING_NODE  *Node;
  EFI_STATUS         Status;

  if (Registration == NULL) {
    return;
  }

  while (!IsListEmpty (&mPendingList)) {
    Link = GetFirstNode (&mPendingList);
    Node = BASE_CR (Link, ECIT_PENDING_NODE, Link);
    RemoveEntryList (Link);

    Status = Registration->RegisterEntry (
                             Registration,
                             &Node->FeatureIdentifier,
                             Node->Data,
                             Node->DataSize
                             );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_WARN, "ECIT: deferred registration of %g failed - %r\n", &Node->FeatureIdentifier, Status));
    }

    if (Node->Data != NULL) {
      FreePool (Node->Data);
    }

    FreePool (Node);
  }
}

/**
  Copy a record into the pending queue and arm the collector-installation
  notify so it flushes automatically.
**/
STATIC
EFI_STATUS
QueueRecord (
  IN CONST EFI_GUID  *FeatureIdentifier,
  IN CONST VOID      *EntryData,
  IN UINTN           EntryDataSize
  )
{
  ECIT_PENDING_NODE  *Node;

  Node = AllocateZeroPool (sizeof (ECIT_PENDING_NODE));
  if (Node == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  if (EntryDataSize != 0) {
    Node->Data = AllocateCopyPool (EntryDataSize, EntryData);
    if (Node->Data == NULL) {
      FreePool (Node);
      return EFI_OUT_OF_RESOURCES;
    }
  }

  CopyGuid (&Node->FeatureIdentifier, FeatureIdentifier);
  Node->DataSize = EntryDataSize;
  InsertTailList (&mPendingList, &Node->Link);

  //
  // The record is safely queued; arming is idempotent and a failure here only
  // defers the automatic flush, so the queue is retained regardless.
  //
  return EcitPlatformArmNotify ();
}

/**
  Submit an ECIT feature record to the collector. See
  <Library/CryptoIndicatorRegistrationLib.h>.
**/
EFI_STATUS
EFIAPI
EcitRegisterCryptoCapability (
  IN CONST EFI_GUID  *FeatureIdentifier,
  IN CONST VOID      *EntryData        OPTIONAL,
  IN UINTN           EntryDataSize
  )
{
  EFI_STATUS                                  Status;
  EFI_CRYPTO_INDICATOR_REGISTRATION_PROTOCOL  *Registration;

  if (FeatureIdentifier == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if ((EntryData == NULL) && (EntryDataSize != 0)) {
    return EFI_INVALID_PARAMETER;
  }

  Registration = NULL;
  Status       = EcitPlatformLocateCollector (&Registration);
  if (!EFI_ERROR (Status) && (Registration != NULL)) {
    return Registration->RegisterEntry (Registration, FeatureIdentifier, EntryData, EntryDataSize);
  }

  //
  // Collector not present yet: queue and flush when it installs.
  //
  return QueueRecord (FeatureIdentifier, EntryData, EntryDataSize);
}
