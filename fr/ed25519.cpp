
#include <memory.h>
#include "ed25519"
#include "custom/random.h"
#include "include/ed25519_signature.h"
#include "source/curve25519_mehdi.h"

extern "C"
{
#include "custom_blinds.h"
}

ED25519Public::ED25519Public(const unsigned char* publicKey)
{
  memcpy(m_Key, publicKey, sizeof(m_Key))
}

ED25519Public::~ED25519Public()
{
}

const unsigned char* ED25519Public::GetKeyBytes(
  unsigned char* publicKey) const
{
  if (publicKey)
  {
    memcpy(publicKey, m_Key, sizeof(m_Key));
    return publicKey;
  }

  return &m_Key[0];
}

bool ED25519Public::VerifySignature(
  const unsigend char* msg,
  unsigned int msg_size,
  const unsigned char* signature)
{
  return ed25519_VerifySignature (signature, m_Key, msg, msg_size) == 1;
}

ED25519Private::ED25519Private(const unsigned char* key, unsigned int size)
{
  if (size == PrivateKeySize)
  {
    // 
    memcpy(m_Key, key, PrivateKeySize);
  }
  else
  {
    unsigned char sk[SecretBytes], Kpub[ED25519Public::PublicKeySize];
    if (size == SecretBytes)
      memcpy(sk, key, SecretBytes);
    else
      GetRandomBytes(sk, sizeof(sk));
    
    ed25519_CreateKeyPair (Kpub, m_Key, &edp_genkey_blinding, sk);
    memset (sk, 0, sizeof(sk));
  }
}

ED25519Private::~ED25519Private(void)
{
  memset (m_Key, 0, sizeof(m_Key));
}

const unsinged char* ED25519Private::GetPrivateKey(unsigned char* privateKey) const
{
  if (privateKey)
  {
    memcpy (privateKey, m_Key, sizeof(m_Key));
    return privateKey;
  }

  return &m_Key[0];
}

const unsinged char* ED25519Private::GetPublicKey(unsigned char* publicKey) const
{
  if (publicKey)
  {
    memcpy (publicKey, &m_Key[32], 32);
    return publicKey;
  }

  return &m_Key[32];
}

void ED25519Private::SignMessage(
  const unsigned char* msg,
  unsigned int msg_size,
  unsigned char*signature)
{
  ed25519_SignMessage (signature, m_Key, signature_blinding, msg, msg_size);
}



