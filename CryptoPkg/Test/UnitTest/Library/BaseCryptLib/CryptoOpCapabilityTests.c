/** @file
  GetCryptoOpCapability() unit tests.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "TestBaseCryptLib.h"
#include <Library/BaseLib.h>
#include <Guid/CryptoOpId.h>

#define OID_SHA256  "2.16.840.1.101.3.4.2.1"

/**
  Verifies the CMS content-digest capability descriptor.
**/
STATIC
UNIT_TEST_STATUS
EFIAPI
TestCmsContentDigestReport (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS  Status;
  UINTN       Size;
  CHAR8       *Buffer;

  Size   = 0;
  Buffer = NULL;

  Status = GetCryptoOpCapability (&gCryptoOpCmsContentDigestGuid, NULL, &Size);
  UT_ASSERT_NOT_EFI_ERROR (Status);
  UT_ASSERT_TRUE (Size > 1);

  Buffer = AllocatePool (Size);
  UT_ASSERT_NOT_NULL (Buffer);

  Status = GetCryptoOpCapability (&gCryptoOpCmsContentDigestGuid, Buffer, &Size);
  UT_ASSERT_NOT_EFI_ERROR (Status);
  UT_ASSERT_EQUAL (Buffer[Size - 1], '\0');

  UT_ASSERT_NOT_NULL (AsciiStrStr (Buffer, OID_SHA256));

  FreePool (Buffer);
  return UNIT_TEST_PASSED;
}

/**
  Verifies the buffer-too-small contract.
**/
STATIC
UNIT_TEST_STATUS
EFIAPI
TestCmsContentDigestBufferTooSmall (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS  Status;
  UINTN       Size;
  CHAR8       Tiny[1];

  Size   = sizeof (Tiny);
  Status = GetCryptoOpCapability (&gCryptoOpCmsContentDigestGuid, Tiny, &Size);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_BUFFER_TOO_SMALL);
  UT_ASSERT_TRUE (Size > sizeof (Tiny));

  return UNIT_TEST_PASSED;
}

/**
  Verifies that an unknown operation is rejected.
**/
STATIC
UNIT_TEST_STATUS
EFIAPI
TestGetCryptoOpCapabilityUnknownOp (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS      Status;
  UINTN           Size;
  CONST EFI_GUID  Unknown = {
    0x00000000, 0x1111, 0x2222, { 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa }
  };

  Size   = 0;
  Status = GetCryptoOpCapability (&Unknown, NULL, &Size);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_NOT_FOUND);

  return UNIT_TEST_PASSED;
}

/**
  Verifies that NULL parameters are rejected.
**/
STATIC
UNIT_TEST_STATUS
EFIAPI
TestGetCryptoOpCapabilityInvalidParameters (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS  Status;
  UINTN       Size;

  Size   = 0;
  Status = GetCryptoOpCapability (NULL, NULL, &Size);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_INVALID_PARAMETER);

  Status = GetCryptoOpCapability (&gCryptoOpCmsContentDigestGuid, NULL, NULL);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_INVALID_PARAMETER);

  return UNIT_TEST_PASSED;
}

TEST_DESC  mCryptoOpCapabilityTest[] = {
  //
  // Description                                Class                            Function                             PreReq  CleanUp  Context
  //
  { "CMS content-digest reports SHA-256",       "CryptoPkg.BaseCryptLib.OpCap", TestCmsContentDigestReport,                 NULL, NULL, NULL },
  { "CMS content-digest honours too-small",     "CryptoPkg.BaseCryptLib.OpCap", TestCmsContentDigestBufferTooSmall,         NULL, NULL, NULL },
  { "GetCryptoOpCapability unknown op",         "CryptoPkg.BaseCryptLib.OpCap", TestGetCryptoOpCapabilityUnknownOp,         NULL, NULL, NULL },
  { "GetCryptoOpCapability invalid parameters", "CryptoPkg.BaseCryptLib.OpCap", TestGetCryptoOpCapabilityInvalidParameters, NULL, NULL, NULL },
};

UINTN  mCryptoOpCapabilityTestNum = ARRAY_SIZE (mCryptoOpCapabilityTest);
