#ifndef __aes_base_h__
#define __aes_base_h__

#include <stdio.h>
#include <cassert>
#include <string> 
#include <vector> 


#include "common_defines.h" 
#include "openssl/evp.h" 

#define AES_BLOCK_SIZE          256 /* guarantees that data of cryption isn't exceeds the allocated memory */
#define SPARE_FOR_ENCRYPTION    32  /* spare bytes of cryption that can be greater original size when we use 256-byte block  */
#define AES_PASSWORD_LEN        16  /* some technical solving to control the length of the differ passwords 
                                       (let it be the half of AES256 key) */
#define AES_KEY_LEN             32  /* 256-bit length */
#define AES_KEY_IV_LEN          16  /* half from key length */
#define AES_SALT_NUMBERS        2   /* two numbers */
#define AES_SALT_NUMERIC_AMOUNT 5   /* five-placed */
#define AES_SHA1_KEYGEN_ROUNDS  10  /* the number of SH1 passes for key generation */

/***************************************************/
/* The AES256 key container 
   @note We can store this fields in the database during session is live
   in case of possible package restoration 
*/
typedef struct AES_KeyStore
{
    u8  AES_Key[AES_KEY_LEN];             /* the AES256 key */

    u8  AES_IV[AES_KEY_IV_LEN];           /* the key 128-bit association that returns by AES key generator 
                                             (may use for restoration) */
    u8  AES_Password[AES_PASSWORD_LEN+1]; /* passphrase to generate the AES256 key (used to create key by 
                                             AES key generator) */
    u32 AES_Salt[AES_SALT_NUMBERS];       /* 64-bit random number that overlaps the key processing 
                                             (overlapping by 'xor') */
} AES_KeyStore;

/****************************************************/
/* Initializes encryptor OpenSSL contexts that uses AES-256 key 
   @note We stores created context while the current key is valid 
   even if the socket session is disconnected because session have to be reconnect
   @note The context stands invalid in case when session's livetime is finished really
*/
s32 AES_InitEncryptCtx( const u8*       key,
                        const u8*       key_iv,
                        EVP_CIPHER_CTX* en_ctx );

/****************************************************/
/* Initializes decryptor OpenSSL contexts that uses AES-256 key 
   @note We stores created context while the current key is valid 
   even if the socket session is disconnected because session have to be reconnect
   @note The context stands invalid in case when session's livetime is finished really
*/
s32 AES_InitDecryptCtx( const u8*       key,
                        const u8*       key_iv,
                        EVP_CIPHER_CTX* de_ctx );

/****************************************************/
/* Encryptor */
u8* AES_Encrypt( EVP_CIPHER_CTX* en_ctx, 
                 u8*             msg, 
                 i32*            msg_len );

/****************************************************/
/* Decryptor */
u8* AES_Decrypt( EVP_CIPHER_CTX* de_ctx,
                 u8*            crypted, 
                 i32*       crypted_len );

/****************************************************/
/* Creates "salt" that represented as random 64-bit number
   @note We use pair of five-numeric decimal numbers 
*/
void AES_SaltRandomizer( u32 salt[2] );

/****************************************************/
/*  Creates the user's password that will be used on key creation for SHA1 auth
    @param licensePassword only for first AES key in session 
    set to NULL for random passwords creation
    @note Let it be the length the half of AES256 key 16 characters from ASCII 48 to ASCII 122 : 
    numbers and case-sensitive latin alphabet excluding special symbols 
    (simple mobile keyboard)
*/
void AES_PasswordRandomizer( u8* password, const s8* licensePassword );

/****************************************************/
/* AES256 key creator */
void AES_KeyGenerator( AES_KeyStore* key );

/****************************************************/


/**/
#endif /* __aes_base_h__ */
