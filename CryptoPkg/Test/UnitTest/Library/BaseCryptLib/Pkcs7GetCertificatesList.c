/** @file
  Test for Pkcs7GetSigners

  One implementation of Pkcs7GetSigners may be found here CryptoPkg/Library/BaseCryptLib/Pk/CryptPkcs7VerifyCommon.c

// TODO add Microsoft License
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "TestBaseCryptLib.h"
#include "Pkcs7GetCertificatesList.h"

UNIT_TEST_STATUS
EFIAPI
TestPkcs7GetCertificatesList (
  UNIT_TEST_CONTEXT  Context
  ) 
{
  UNIT_TEST_STATUS Status = UNIT_TEST_ERROR_TEST_FAILED;
  BOOLEAN Result = FALSE;

  UINT8 *SignerCertChainPtr = NULL;
//  UINTN SignerCertChainSize = 0;
  UINT8 *UnchainCertsPtr = NULL;
  UINTN UnchainCertsSize = 0;

  Result = Pkcs7GetCertificatesList(
    m1AdditionalCertificatesMockVar,
    sizeof m1AdditionalCertificatesMockVar,
    NULL,
    NULL,
    &UnchainCertsPtr,
    &UnchainCertsSize
    );

  if (Result == FALSE) {
    goto Exit;
  }

  UT_ASSERT_NOT_NULL(UnchainCertsPtr);
  UT_ASSERT_TRUE (FALSE);

  DUMP_HEX (DEBUG_VERBOSE, 0, UnchainCertsPtr, UnchainCertsSize, "");
  DEBUG ((DEBUG_VERBOSE, "---------------------------------------------------------\n"));
  UT_LOG_ERROR ("TestPkcs7GetCertificatesList() - UnchainCertsSize = %d\n", UnchainCertsSize);
  UT_LOG_ERROR ("UT_LOG_ERROR() message\n");


  Status = UNIT_TEST_PASSED;

Exit:

  if (SignerCertChainPtr != NULL) {
    Pkcs7FreeSigners (SignerCertChainPtr);
  }

  if (UnchainCertsPtr != NULL) {
    Pkcs7FreeSigners (UnchainCertsPtr);
  }

  return Status;
}

TEST_DESC mPkcs7GetCertificatesListTest[] = {
  //
  // -----Description--------------------------------Class--------------------Function----------------Pre---Post--Context
  //
  { "TestPkcs7GetCertificatesList()", "CryptoPkg.BaseCryptLib.TestPkcs7GetCertificatesList", TestPkcs7GetCertificatesList, NULL, NULL, NULL },
};

UINTN  mPkcs7GetCertificatesListTestNum = ARRAY_SIZE (mPkcs7GetCertificatesListTest);
