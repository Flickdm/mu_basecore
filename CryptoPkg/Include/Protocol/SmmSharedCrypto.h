/** @file
  This Protocol provides Crypto services to SMM modules

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef SHARED_SMM_CRYPTO_PROTOCOL_H__
#define SHARED_SMM_CRYPTO_PROTOCOL_H__

#include <Protocol/SharedCryptoProtocol.h>

///
/// EDK II SMM Crypto Protocol is identical to EDK II Crypto Protocol
///
typedef SHARED_CRYPTO_PROTOCOL SHARED_SMM_CRYPTO_PROTOCOL;

extern GUID  gEdkiiSmmCryptoProtocolGuid;

#endif
