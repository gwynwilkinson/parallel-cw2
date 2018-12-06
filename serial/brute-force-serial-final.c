/*######################################################################################
########################################################################################
##                                                                                    ##
##  Brute Force Encryption Breaker - Serial Version 1.0 by Gwyn Wilkinson 01/12/2018  ##
##                                                                                    ##
##    Functions handleErrors() and encrypt() both Copyright OpenSSL 2017              ##
##    Contents licensed under the terms of the OpenSSL license                        ##
##    See https://www.openssl.org/source/license.html for details                     ##
##                                                                                    ##
##                                                                                    ##
########################################################################################
#######################################################################################*/

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <omp.h>

/*This alphabet sets the complexity of the task.
  We can extend or shorten it depending on what
  we want to do */
static unsigned char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static int alphabetLen = 52;

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int main (int argc, char* argv[])
{
  int numkeys = 0;

  double Start, End;

  /*This flag is used to guard all the operations in
    our encryption logic below, when it is true we
    cease all operations */
  bool success = false;

  /*These variables are needed for AES CBC - we encrypt
    the plaintext using the key & IV to produce a
    ciphertext.*/

  unsigned char plaintext[16] = "UWE";
  unsigned char keyA[16] = "AAAAA";
  unsigned char iv[16] = "0123456789012345";
  unsigned char ciphertextA[128];

  /*These variables are used to test different keys
    until we produce a ciphertext that matches. */

  unsigned char keyB[16];
  unsigned char ciphertextB[128];


  int keylen = strlen(keyA);

  /*Pads the remaining characters with '#' so
    we have a 128-bit key to encrypt with */
  for (int j = keylen; j<16;j++){
    keyA[j] = 0x23;
    keyB[j] = 0x23;
  }

  /*Encrypt function*/
  encrypt (plaintext, 16, keyA, iv, ciphertextA);

  /*Start our performance clock.
    We use the OpenMP Wtime() function
    because it's more reliable than time.h */
  Start = omp_get_wtime();

  /*This nested for-loop builds our key, which
    is then used to encrypt in the middle */
  for (int i = 0; i < alphabetLen; i++){
    if(!success){
    keyB[0] = alphabet[i];
    for (int j = 0; j < alphabetLen; j++){
      if(!success){
      keyB[1] = alphabet[j];
      for (int k = 0; k < alphabetLen; k++){
        if(!success){
        keyB[2] = alphabet[k];
        for (int l = 0; l < alphabetLen; l++){
          if(!success){
          keyB[3] = alphabet[l];
          for (int m = 0; m < alphabetLen; m++){
            if(!success){
            keyB[4] = alphabet[m];
            /*encrypt the plaintext using the new key */
            encrypt (plaintext, 16, keyB, iv, ciphertextB);
            numkeys++;
            /*Compare the two ciphertexts together -
              if they match, we have broken the
              encryption and can exit. */
            if(strncmp(ciphertextA,ciphertextB,16)==0){
              printf("Success!\n");
              printf("Key is : ");
              for(int k = 0;k<16;k++){
                printf("%c",keyB[k]);
              }
              printf("\n");
              printf("Ciphertext is:\n");
              BIO_dump_fp (stdout, (const char *)ciphertextA, 16);
              BIO_dump_fp (stdout, (const char *)ciphertextB, 16);
              success = true;


              }

            }
          }
          }
      }
      }
    }
    }
  }
  }
}
End = omp_get_wtime() - Start;
/*Print out our performance data*/
printf( "Number of seconds to crack:   %f\n", End);
printf( "Number of passwords tried:    %d\n", numkeys);
printf( "Passwords tried per second:   %d\n", (int)(numkeys/End));
return 0;
}
