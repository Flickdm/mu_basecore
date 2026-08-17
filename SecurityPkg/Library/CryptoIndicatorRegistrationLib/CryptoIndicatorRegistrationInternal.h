/** @file
  Internal contract between the shared CryptoIndicatorRegistrationLib core and
  its phase-specific (DXE / Standalone MM) instances.

  The shared core (CryptoIndicatorRegistrationCommon.c) owns the pending-record
  queue and the submit-or-queue policy; each phase instance provides only the
  means to locate the collector and to arm the collector-installation notify.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef CRYPTO_INDICATOR_REGISTRATION_INTERNAL_H_
#define CRYPTO_INDICATOR_REGISTRATION_INTERNAL_H_

#include <Protocol/CryptoIndicatorRegistration.h>

/**
  Flush the queued records to Registration. Provided by the shared core and
  called by a phase instance's collector-installation notify callback.

  @param[in] Registration  The collector's registration protocol.
**/
VOID
EcitFlushPending (
  IN EFI_CRYPTO_INDICATOR_REGISTRATION_PROTOCOL  *Registration
  );

/**
  Locate the collector's registration protocol for the current phase.

  @param[out] Registration  The located protocol on success.

  @retval EFI_SUCCESS    The protocol was located.
  @retval EFI_NOT_FOUND  The collector is not present yet.
  @retval other          A phase-specific location error.
**/
EFI_STATUS
EcitPlatformLocateCollector (
  OUT EFI_CRYPTO_INDICATOR_REGISTRATION_PROTOCOL  **Registration
  );

/**
  Idempotently arm the collector-installation notify for the current phase. The
  notify callback must flush the queue via EcitFlushPending().

  @retval EFI_SUCCESS  The notify is armed (or was already armed).
  @retval other        Arming failed; the queue will not auto-flush.
**/
EFI_STATUS
EcitPlatformArmNotify (
  VOID
  );

#endif // CRYPTO_INDICATOR_REGISTRATION_INTERNAL_H_
