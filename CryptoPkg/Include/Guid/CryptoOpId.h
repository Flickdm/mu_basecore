/** @file
  Crypto operation identifiers used by GetCryptoOpCapability().

  Each identifier below returns an unordered, NUL-terminated CSV of
  dotted-decimal algorithm OIDs.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef CRYPTO_OP_ID_H_
#define CRYPTO_OP_ID_H_

/// Signature algorithms accepted by CMS verification.
extern EFI_GUID  gCryptoOpCmsVerifyGuid;

/// Digest algorithms accepted for CMS content digest calculation.
extern EFI_GUID  gCryptoOpCmsContentDigestGuid;

/// Signature algorithms accepted by Authenticode verification.
extern EFI_GUID  gCryptoOpAuthenticodeVerifyGuid;

/// Digest algorithms accepted for Authenticode image hashing.
extern EFI_GUID  gCryptoOpAuthenticodeHashGuid;

#endif // CRYPTO_OP_ID_H_
