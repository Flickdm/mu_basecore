/** @file
  ECIT MM collector (Standalone MM).

  Produces the EFI_CRYPTO_INDICATOR_REGISTRATION_PROTOCOL inside MM so MM-phase
  feature owners can submit their cryptographic-capability records, accumulates
  those records in MM memory, and registers an MMI handler that serializes the
  accumulated records to a caller (the DXE bridge) on request. The MM collector
  never seals or publishes; the DXE bridge drains it into the DXE collector,
  which owns publication. Accumulated records persist after a drain (they are
  not freed), so a repeated drain is harmless - the DXE collector rejects
  already-registered feature GUIDs.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/MmServicesTableLib.h>
#include <Guid/CryptoIndicatorMmBridge.h>
#include <Protocol/CryptoIndicatorRegistration.h>

typedef struct {
  LIST_ENTRY    Link;
  EFI_GUID      FeatureIdentifier;
  UINTN         DataSize;
  UINT8         *Data;
} ECIT_MM_ENTRY_NODE;

STATIC LIST_ENTRY  mEntryList       = INITIALIZE_LIST_HEAD_VARIABLE (mEntryList);
STATIC UINTN       mNumberOfEntries = 0;

/**
  Register one ECIT entry with the MM collector. See
  <Protocol/CryptoIndicatorRegistration.h>.
**/
STATIC
EFI_STATUS
EFIAPI
EcitMmRegisterEntry (
  IN EFI_CRYPTO_INDICATOR_REGISTRATION_PROTOCOL  *This,
  IN CONST EFI_GUID                              *FeatureIdentifier,
  IN CONST VOID                                  *EntryData        OPTIONAL,
  IN UINTN                                       EntryDataSize
  )
{
  LIST_ENTRY          *Link;
  ECIT_MM_ENTRY_NODE  *Node;

  if ((This == NULL) || (FeatureIdentifier == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((EntryData == NULL) && (EntryDataSize != 0)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((sizeof (ECIT_MM_BRIDGE_ENTRY) + EntryDataSize) > MAX_UINT16) {
    return EFI_INVALID_PARAMETER;
  }

  if (mNumberOfEntries >= MAX_UINT8) {
    return EFI_OUT_OF_RESOURCES;
  }

  for (Link = GetFirstNode (&mEntryList); !IsNull (&mEntryList, Link); Link = GetNextNode (&mEntryList, Link)) {
    Node = BASE_CR (Link, ECIT_MM_ENTRY_NODE, Link);
    if (CompareGuid (&Node->FeatureIdentifier, FeatureIdentifier)) {
      return EFI_ALREADY_STARTED;
    }
  }

  Node = AllocateZeroPool (sizeof (ECIT_MM_ENTRY_NODE));
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
  InsertTailList (&mEntryList, &Node->Link);
  mNumberOfEntries++;

  DEBUG ((DEBUG_INFO, "ECIT(MM): registered feature %g (%u byte payload)\n", FeatureIdentifier, (UINT32)EntryDataSize));
  return EFI_SUCCESS;
}

STATIC EFI_CRYPTO_INDICATOR_REGISTRATION_PROTOCOL  mMmRegistration = {
  EFI_CRYPTO_INDICATOR_REGISTRATION_PROTOCOL_REVISION,
  EcitMmRegisterEntry
};

/**
  MMI handler: serialize the accumulated records into the caller comm buffer.

  CommBuffer points at an ECIT_MM_BRIDGE_COMM the DXE bridge supplied; on return
  it carries ReturnStatus, EntryCount, EntriesSize, and EntriesSize bytes of
  packed ECIT_MM_BRIDGE_ENTRY records. If the buffer cannot hold the records the
  handler reports EFI_BUFFER_TOO_SMALL with the required EntriesSize.
**/
STATIC
EFI_STATUS
EFIAPI
EcitMmBridgeHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer       OPTIONAL,
  IN OUT UINTN       *CommBufferSize   OPTIONAL
  )
{
  ECIT_MM_BRIDGE_COMM   *Comm;
  LIST_ENTRY            *Link;
  ECIT_MM_ENTRY_NODE    *Node;
  ECIT_MM_BRIDGE_ENTRY  *EntryHdr;
  UINT8                 *Cursor;
  UINT8                 *BufEnd;
  UINTN                 Required;
  UINT32                Count;

  if ((CommBuffer == NULL) || (CommBufferSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (*CommBufferSize < sizeof (ECIT_MM_BRIDGE_COMM)) {
    return EFI_INVALID_PARAMETER;
  }

  Comm = (ECIT_MM_BRIDGE_COMM *)CommBuffer;
  if ((Comm->Signature != ECIT_MM_BRIDGE_COMM_SIGNATURE) ||
      (Comm->Revision != ECIT_MM_BRIDGE_COMM_REVISION))
  {
    Comm->ReturnStatus = (UINT64)EFI_INVALID_PARAMETER;
    return EFI_SUCCESS;
  }

  //
  // Compute the required space for all records.
  //
  Required = 0;
  for (Link = GetFirstNode (&mEntryList); !IsNull (&mEntryList, Link); Link = GetNextNode (&mEntryList, Link)) {
    Node      = BASE_CR (Link, ECIT_MM_ENTRY_NODE, Link);
    Required += sizeof (ECIT_MM_BRIDGE_ENTRY) + Node->DataSize;
  }

  Comm->EntryCount  = 0;
  Comm->EntriesSize = (UINT32)Required;

  if ((sizeof (ECIT_MM_BRIDGE_COMM) + Required) > *CommBufferSize) {
    Comm->ReturnStatus = (UINT64)EFI_BUFFER_TOO_SMALL;
    return EFI_SUCCESS;
  }

  Cursor = (UINT8 *)(Comm + 1);
  BufEnd = (UINT8 *)CommBuffer + *CommBufferSize;
  Count  = 0;

  for (Link = GetFirstNode (&mEntryList); !IsNull (&mEntryList, Link); Link = GetNextNode (&mEntryList, Link)) {
    Node = BASE_CR (Link, ECIT_MM_ENTRY_NODE, Link);
    if ((Cursor + sizeof (ECIT_MM_BRIDGE_ENTRY) + Node->DataSize) > BufEnd) {
      break;
    }

    EntryHdr = (ECIT_MM_BRIDGE_ENTRY *)Cursor;
    CopyGuid (&EntryHdr->FeatureIdentifier, &Node->FeatureIdentifier);
    EntryHdr->DataSize = (UINT32)Node->DataSize;
    Cursor            += sizeof (ECIT_MM_BRIDGE_ENTRY);

    if (Node->DataSize != 0) {
      CopyMem (Cursor, Node->Data, Node->DataSize);
      Cursor += Node->DataSize;
    }

    Count++;
  }

  Comm->EntryCount   = Count;
  Comm->ReturnStatus = (UINT64)EFI_SUCCESS;
  return EFI_SUCCESS;
}

/**
  Entry point: publish the MM registration protocol and the drain MMI handler.
**/
EFI_STATUS
EFIAPI
CryptoIndicatorCollectorStandaloneMmEntryPoint (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *MmSystemTable
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  Handle;
  EFI_HANDLE  DispatchHandle;

  Handle = NULL;
  Status = gMmst->MmInstallProtocolInterface (
                    &Handle,
                    &gEfiCryptoIndicatorRegistrationProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    &mMmRegistration
                    );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "ECIT(MM): install registration protocol failed - %r\n", Status));
    return Status;
  }

  Status = gMmst->MmiHandlerRegister (
                    EcitMmBridgeHandler,
                    &gEcitMmBridgeHandlerGuid,
                    &DispatchHandle
                    );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "ECIT(MM): register MMI handler failed - %r\n", Status));
    return Status;
  }

  DEBUG ((DEBUG_INFO, "ECIT(MM): collector ready.\n"));
  return EFI_SUCCESS;
}
