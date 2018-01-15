#include "keytar.h"

#define UNICODE

#include <windows.h>
#include <wincred.h>
#include <memory>
#include <utility>

#include "credentials.h"

namespace keytar {

std::unique_ptr<wchar_t[]> utf8ToWideChar(const std::string& utf8) {
  int size = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), NULL, 0);
  if (size == 0)
    return nullptr;

  std::unique_ptr<wchar_t[]> ret(new wchar_t[size + 1]);
  if (MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), ret.get(), size) == 0)
    return nullptr;

  ret[size] = '\0';
  return ret;
}

std::string wideCharToAnsi(LPWSTR wide_char) {
  if (wide_char == nullptr)
    return nullptr;

  int size = WideCharToMultiByte(CP_ACP, 0, wide_char, -1, NULL, 0, NULL, NULL);
  if (size == 0)
    return nullptr;

  std::unique_ptr<char[]> ret(new char[size + 1]);
  if (WideCharToMultiByte(CP_ACP, 0, wide_char, -1, ret.get(), size, NULL, NULL) == 0)
    return nullptr;

  ret[size] = '\0';
  return ret.get();
}

std::string getErrorMessage(DWORD errorCode) {
  LPWSTR errBuffer;
  DWORD ret = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                  NULL, errorCode, 0, (LPWSTR) &errBuffer, 0, NULL);
  if (ret) {
    std::string errMsg = wideCharToAnsi(errBuffer);
    LocalFree(errBuffer);
    return errMsg;
  }
  return "Unknown error";
}

KEYTAR_OP_RESULT SetPassword(const std::string& service,
                             const std::string& account,
                             const std::string& password,
                             std::string* errStr) {
  std::unique_ptr<wchar_t[]> target_uni = utf8ToWideChar(service + '/' + account);
  if (target_uni == nullptr) {
    errStr = "Could not decode parameter: service or/and account";
    return FAIL_ERROR;
  }

  std::unique_ptr<wchar_t[]> account_uni = utf8ToWideChar(account);
  if (target_uni == nullptr) {
    errStr = "Could not decode parameter: account";
    return FAIL_ERROR;
  }

  CREDENTIAL cred = { 0 };
  cred.Type = CRED_TYPE_GENERIC;
  cred.TargetName = target_uni.get();
  cred.UserName = account_uni.get();
  cred.CredentialBlobSize = password.size();
  cred.CredentialBlob = (LPBYTE)(password.data());
  cred.Persist = CRED_PERSIST_LOCAL_MACHINE;

  bool result = ::CredWrite(&cred, 0);
  if (!result) {
    *errStr = getErrorMessage(::GetLastError());
    return FAIL_ERROR;
  }
  return SUCCESS;
}

KEYTAR_OP_RESULT GetPassword(const std::string& service,
                             const std::string& account,
                             std::string* password,
                             std::string* errStr) {
  std::unique_ptr<wchar_t[]> target_uni = utf8ToWideChar(service + '/' + account);
  if (target_uni == nullptr) {
    return FAIL_ERROR;
  }

  CREDENTIAL* cred;
  bool result = ::CredRead(target_uni.get(), CRED_TYPE_GENERIC, 0, &cred);
  if (!result) {
    DWORD code = ::GetLastError();
    if (code == ERROR_NOT_FOUND) {
      return FAIL_NONFATAL;
    }
    else {
      *errStr = getErrorMessage(code);
      return FAIL_ERROR;
    }
  }

  *password = std::string(reinterpret_cast<char*>(cred->CredentialBlob), cred->CredentialBlobSize);
  ::CredFree(cred);
  return SUCCESS;
}

KEYTAR_OP_RESULT DeletePassword(const std::string& service,
                                const std::string& account,
                                std::string* errStr) {
  std::unique_ptr<wchar_t[]> target_uni = utf8ToWideChar(service + '/' + account);
  if (target_uni == nullptr) {
    errStr = "Could not decode parameter: service and/or account";
    return FAIL_ERROR;
  }

  bool result = ::CredDelete(target_uni.get(), CRED_TYPE_GENERIC, 0);
  if (!result) {
    DWORD code = ::GetLastError();
    if (code == ERROR_NOT_FOUND) {
      return FAIL_NONFATAL;
    }
    else {
      *errStr = getErrorMessage(code);
      return FAIL_ERROR;
    }
  }

  return SUCCESS;
}

KEYTAR_OP_RESULT FindPassword(const std::string& service,
                              std::string* password,
                              std::string* errStr) {
  std::unique_ptr<wchar_t[]> filter_uni = utf8ToWideChar(service + "*");
  if (filter_uni == nullptr) {
    errStr = "Could not decode parameter: service";
    return FAIL_ERROR;
  }

  DWORD count;
  CREDENTIAL** creds;
  bool result = ::CredEnumerate(filter_uni.get(), 0, &count, &creds);
  if (!result) {
    DWORD code = ::GetLastError();
    if (code == ERROR_NOT_FOUND) {
      return FAIL_NONFATAL;
    }
    else {
      *errStr = getErrorMessage(code);
      return FAIL_ERROR;
    }
  }

  *password = std::string(reinterpret_cast<char*>(creds[0]->CredentialBlob), creds[0]->CredentialBlobSize);
  ::CredFree(creds);
  return SUCCESS;
}

KEYTAR_OP_RESULT FindCredentials(const std::string& service,
                                 std::vector<Credentials>* credentials,
                                 std::string* errStr) {
  std::unique_ptr<wchar_t[]> filter_uni = utf8ToWideChar(service + "*");
  if (filter_uni == nullptr) {
    errStr = "Could not decode parameter: service";
    return FAIL_ERROR;
  }

  DWORD count;
  CREDENTIAL **creds;
  bool result = ::CredEnumerate(filter_uni.get(), 0, &count, &creds);
  if (!result) {
    DWORD code = ::GetLastError();
    if (code == ERROR_NOT_FOUND) {
      return FAIL_NONFATAL;
    }
    else {
      *errStr = getErrorMessage(code);
      return FAIL_ERROR;
    }
  }

  for (unsigned int i = 0; i < count; ++i) {
    CREDENTIAL* cred = creds[i];
    if (cred->UserName == NULL || cred->CredentialBlob == NULL) {
      continue;
    }

    std::string login = wideCharToAnsi(cred->UserName);
    std::string password(reinterpret_cast<char*>(cred->CredentialBlob), cred->CredentialBlobSize);
    credentials->push_back(std::make_pair(login, password));
  }

  CredFree(creds);
  return SUCCESS;
}

}  // namespace keytar
