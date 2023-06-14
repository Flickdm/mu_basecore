/** @file
  Test for Pkcs7GetSigners

  One implementation of Pkcs7GetSigners may be found here CryptoPkg/Library/BaseCryptLib/Pk/CryptPkcs7VerifyCommon.c

// TODO add Microsoft License
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "TestBaseCryptLib.h"
#include "Pkcs7GetCertificatesList.h"
#include <openssl/x509.h>

UNIT_TEST_STATUS
EFIAPI
TestPkcs7GetCertificatesList (
  UINT8 *Signature,
  UINTN SignatureSize,
  CHAR8 *ExpectedCertCommonName,
  INTN CertIndex,
  BOOLEAN CheckIfChainedIsNull,
  BOOLEAN CheckIfUnchainedIsNull
  ) 
{
  BOOLEAN Result = FALSE;
  UINT8 *SignerCertChainPtr;
  UINTN SignerCertChainSize;
  UINT8 *UnchainCertsPtr;
  UINTN UnchainCertsSize;
  CHAR8 CertCommonName[128];
  UINTN CertCommonNameSize;
  UINT8 *TrustedCert;
  UINTN TrustedCertSize;

  SignerCertChainPtr = NULL;
  SignerCertChainSize = 0;
  UnchainCertsPtr = NULL;
  UnchainCertsSize = 0;
  CertCommonNameSize = sizeof (CertCommonName);
  TrustedCert = NULL;
  TrustedCertSize = 0;

  Result = Pkcs7GetCertificatesList(
    Signature,
    SignatureSize,
    &SignerCertChainPtr,
    &SignerCertChainSize,
    &UnchainCertsPtr,
    &UnchainCertsSize
    );

  UT_ASSERT_TRUE(Result);

  // If there are no certficates chained to the signer, then SignerCertChainPtr should be NULL
  if (!CheckIfChainedIsNull) {
    UT_ASSERT_NOT_NULL(SignerCertChainPtr);
    UT_ASSERT_NOT_EQUAL(SignerCertChainSize, 0);
  }

  // If there are no addtional certificates chained, then UnchainCertsPtr should be NULL
  if (!CheckIfUnchainedIsNull) {
    UT_ASSERT_NOT_NULL(UnchainCertsPtr);
    UT_ASSERT_NOT_EQUAL(UnchainCertsSize, 0);
  }

  Result = Pkcs7GetCertificateByIndex(
    SignerCertChainPtr,
    SignerCertChainSize,
    CertIndex,
    &TrustedCert,
    &TrustedCertSize
    );

  UT_ASSERT_TRUE(Result);
  UT_ASSERT_NOT_NULL(TrustedCert);

  //
  // Get SignerCert CommonName
  //
  RETURN_STATUS Status2 = X509GetCommonName (TrustedCert, TrustedCertSize, CertCommonName, &CertCommonNameSize);
  UT_ASSERT_EQUAL (Status2, RETURN_SUCCESS);

  DEBUG((DEBUG_INFO, "CertCommonName: %a\n", CertCommonName));
  // Compare CertCommonName to expected value
  UT_ASSERT_MEM_EQUAL (CertCommonName, ExpectedCertCommonName, CertCommonNameSize);

  if (SignerCertChainPtr != NULL) {
    Pkcs7FreeSigners (SignerCertChainPtr);
  }

  if (UnchainCertsPtr != NULL) {
    Pkcs7FreeSigners (UnchainCertsPtr);
  }

  return UNIT_TEST_PASSED;
}

UNIT_TEST_STATUS
EFIAPI
TestPkcs7GetCertificatesListWith1AddtionalCertificatedChained(
  IN UNIT_TEST_CONTEXT           Context
  )
{
  UNIT_TEST_STATUS Status = UNIT_TEST_ERROR_TEST_FAILED;

  Status = TestPkcs7GetCertificatesList(m1AdditionalCertificatesMockVar, sizeof m1AdditionalCertificatesMockVar, mIntermediate0, 0, FALSE, TRUE);
  UT_ASSERT_EQUAL(Status, UNIT_TEST_PASSED);

  return Status;
}

UNIT_TEST_STATUS
EFIAPI
TestPkcs7GetCertificatesListWith2AddtionalCertificatedChained(
  IN UNIT_TEST_CONTEXT           Context
  )
{
  UNIT_TEST_STATUS Status = UNIT_TEST_ERROR_TEST_FAILED;

  Status = TestPkcs7GetCertificatesList(m2AdditionalCertificatesMockVar, sizeof m2AdditionalCertificatesMockVar, mIntermediate0, 0, FALSE, TRUE);
  UT_ASSERT_EQUAL(Status, UNIT_TEST_PASSED);

  Status = TestPkcs7GetCertificatesList(m2AdditionalCertificatesMockVar, sizeof m2AdditionalCertificatesMockVar, mIntermediate1, 1, FALSE, TRUE);
  UT_ASSERT_EQUAL(Status, UNIT_TEST_PASSED);

  return Status;
}

UNIT_TEST_STATUS
EFIAPI
TestPkcs7GetCertificatesListWith3AddtionalCertificatedChained(
  IN UNIT_TEST_CONTEXT           Context
  )
{
  UNIT_TEST_STATUS Status = UNIT_TEST_ERROR_TEST_FAILED;

  Status = TestPkcs7GetCertificatesList(m3AdditionalCertificatesMockVar, sizeof m3AdditionalCertificatesMockVar, mIntermediate0, 0, FALSE, TRUE);
  UT_ASSERT_EQUAL(Status, UNIT_TEST_PASSED);

  Status = TestPkcs7GetCertificatesList(m3AdditionalCertificatesMockVar, sizeof m3AdditionalCertificatesMockVar, mIntermediate1, 1, FALSE, TRUE);
  UT_ASSERT_EQUAL(Status, UNIT_TEST_PASSED);

  Status = TestPkcs7GetCertificatesList(m3AdditionalCertificatesMockVar, sizeof m3AdditionalCertificatesMockVar, mIntermediate2, 2, FALSE, TRUE);
  UT_ASSERT_EQUAL(Status, UNIT_TEST_PASSED);

  return Status;
}

UNIT_TEST_STATUS
EFIAPI
TestPkcs7GetCertificatesListNegativeIndex(
  IN UNIT_TEST_CONTEXT           Context
  )
{
  UNIT_TEST_STATUS Status = UNIT_TEST_ERROR_TEST_FAILED;

  // the leaf certificate is always at the highest index
  Status = TestPkcs7GetCertificatesList(m3AdditionalCertificatesMockVar, sizeof m3AdditionalCertificatesMockVar, mSigner, -1, FALSE, TRUE);
  UT_ASSERT_EQUAL(Status, UNIT_TEST_PASSED);

  return Status;
}


TEST_DESC mPkcs7GetCertificatesListTest[] = {
  //
  // -----Description--------------------------------Class--------------------Function----------------Pre---Post--Context
  //
  { "TestPkcs7GetCertificatesListWith1AddtionalCertificatedChained()", "CryptoPkg.BaseCryptLib.TestPkcs7GetCertificatesList", TestPkcs7GetCertificatesListWith1AddtionalCertificatedChained, NULL, NULL, NULL },
  { "TestPkcs7GetCertificatesListWith2AddtionalCertificatedChained()", "CryptoPkg.BaseCryptLib.TestPkcs7GetCertificatesList", TestPkcs7GetCertificatesListWith2AddtionalCertificatedChained, NULL, NULL, NULL },
  { "TestPkcs7GetCertificatesListWith3AddtionalCertificatedChained()", "CryptoPkg.BaseCryptLib.TestPkcs7GetCertificatesList", TestPkcs7GetCertificatesListWith3AddtionalCertificatedChained, NULL, NULL, NULL },
  { "TestPkcs7GetCertificatesListNegativeIndex()", "CryptoPkg.BaseCryptLib.TestPkcs7GetCertificatesList", TestPkcs7GetCertificatesListNegativeIndex, NULL, NULL, NULL },
};

UINTN  mPkcs7GetCertificatesListTestNum = ARRAY_SIZE (mPkcs7GetCertificatesListTest);
