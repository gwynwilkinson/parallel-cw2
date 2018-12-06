/*######################################################################################
########################################################################################
##                                                                                    ##
##  Brute Force Encryption Breaker - MPI Version 1.0 by Gwyn Wilkinson 01/12/2018     ##
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
#include <mpi.h>

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
  int allnumkeys = 0;

  double Start = 0;
  double End = 0;

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

  /*This flag is used to guard all the operations in
    our encryption logic below, when it is true we
    cease all operations */
  bool success = false;

  /*Start our performance clock. */
  Start = MPI_Wtime();

  int rank,size,flag=0;
  int chunkstart,chunksize,rem;

  MPI_Status status;
  MPI_Request request,request2;

  MPI_Init(&argc, &argv);
  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  MPI_Comm_size(MPI_COMM_WORLD, &size);

  /*Divide the workload between each process
    as evenly as possible */
  rem = (alphabetLen % size);
  chunksize = (alphabetLen/size); //size of share per thread
  chunkstart = (chunksize*rank); //starting index of share

  if(rank<rem){
      chunkstart += rank;	//spread remainder evenly between threads
      chunksize++;
    }else{
      chunkstart += rem;
    }

  /*This nested for-loop builds our key, which
    is then used to encrypt in the middle */
  for (int i = chunkstart; i < (chunkstart+chunksize); i++){
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
                        /*If we aren't in more than one process we can skip this */
                        if(size>1){
                          /*Sends success state to root process */
                          MPI_Isend(&success,1,MPI_C_BOOL,0,100,MPI_COMM_WORLD,&request);
                        }
                      }
                    }
                  }
                  /*If we are running more than one process,
                    we need to synchronise the success flag
                    across all processes */
                  if(size>1){
                    /*root process checks for a success flag from any process*/
                    if(rank==0){
                      MPI_Irecv(&success, 1, MPI_C_BOOL, MPI_ANY_SOURCE, 100, MPI_COMM_WORLD, &request);
                      MPI_Test(&request, &flag, &status);
                      /*send current success value to all other threads */
                      for(i=1;i<size;i++){
                        MPI_Isend(&success, 1, MPI_C_BOOL, i, 100, MPI_COMM_WORLD, &request2);
                      }
                    /*non-root processes check for a success flag from root */
                    }else{
                      MPI_Irecv(&success, 1, MPI_C_BOOL, 0, 100, MPI_COMM_WORLD, &request2);
                      MPI_Test(&request2, &flag, &status);
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
  /*Add together the number of keys tested
    across all processes */
MPI_Reduce(&numkeys,&allnumkeys,1,MPI_INT,MPI_SUM,0,MPI_COMM_WORLD);
/*Root thread prints out our performance data */
if(rank==0){
  End = MPI_Wtime() - Start;
  printf( "Number of seconds to crack:   %f\n", End);
  printf( "Number of passwords tried:    %d\n", allnumkeys);
  printf( "Passwords tried per second:   %d\n", (int)(allnumkeys/End));
}


MPI_Finalize();

return 0;
}
