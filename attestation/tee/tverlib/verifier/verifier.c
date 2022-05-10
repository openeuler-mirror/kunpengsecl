#include "verifier.h"

#define MAXSIZE 1000
#define VERSION 5
#define TIMESTAMP 9
#define NONCE 33
#define UUID 65
#define ALG 3
#define IMAGE_HASH 33
#define HASH 33
#define RESERVE 33
#define SIGNATURE 513
#define CERT 513
#define PRIVATEKEY "./private_key.pem"
#define PUBLICKEY "./public_key.pem"
TAreport *Convert(buffer_data *data);
bool VerifyProcess(TAreport *report, int type, char *filename);
BaseValue *loadbasevalue(char *uuid, char *filename);
bool compare(int type, TAreport *report, BaseValue *basevalue);

//interface 
bool VerifySignature(buffer_data *report);

bool verifysig(uint8_t *data,uint8_t *sig,uint8_t *cert);
bool translateBuf(buffer_data report,TAreport *tareport);

//testSignature will generate a signature by the private_key.pem file
void testSignature(char *digest,char *sig)
{  
   char buf[256]={0};
   //get private key from file
	FILE *fp = fopen(PRIVATEKEY,"r");
	if(fp==NULL){
		printf("read file failed\n");
	}
	RSA *privKey = PEM_read_RSAPrivateKey(fp,NULL,NULL,NULL);
	if(privKey==NULL){
		printf("failed get private key\n");
	}
	fclose(fp);
   int nOutLen = strlen(sig);
	int rt = 0;
	rt = RSA_sign(NID_sha256,digest,SHA256_DIGEST_LENGTH,sig,&nOutLen,privKey);
	if(rt!=1){
		printf("sig failed\n");
	}
   
}
   /* 
	verifysig will to verify the signature which in report by RSA_verify
	buf: input data and is a byte array 
	sig: the signature block by RSA_sign generated and is a byte array
	cert:input cert: byte array of the DER representation 
	*/
bool verifysig(uint8_t *data,uint8_t *sig,uint8_t *cert){
	int status = EXIT_SUCCESS;
	int rc = 1; //OpenSSL return code
	int data_len = sizeof(data);
	int sig_len = strlen(sig);
   int cert_len = strlen(cert);
	if (data_len<=0||sig_len<=0||cert_len<=0){
		status = EXIT_FAILURE;
		return false;
	}

	/* step 1:  hash the data store in digest 
	*/
	uint8_t digest[SHA256_DIGEST_LENGTH];
	SHA256(data,strlen(data),digest);
   int nOutLen = strlen(sig);
   testSignature(digest,sig);
    /* step 2: extract the RSA public key from the x509 certificate
	*/
   //get public key from file
	FILE* fp = fopen(PUBLICKEY,"r");
	if(fp==NULL){
		printf("read file failed\n");
	}
	RSA *pubKey = PEM_read_RSA_PUBKEY(fp,NULL,NULL,NULL);
	if(pubKey==NULL){ 
		printf("failed get public key\n");
	}
	fclose(fp);
   
   //step 3: using the RSA_verify to verify the signature is validate
	/*
	verifies that the signature sigbuf of size 
	siglen matches a given message digest m of size m_len. 
	type denotes the message digest algorithm that was used to 
	generate the signature. rsa is the signer's public key.
	*/
	rc = RSA_verify(NID_sha256,digest,SHA256_DIGEST_LENGTH,sig,256,pubKey);
	if (rc != 1){
		status = EXIT_FAILURE;
		return false;
	}
	return true;
}

//translateBuf will translate the buffer_date to TAreport
bool translateBuf(buffer_data report,TAreport *tareport){
	memcpy(tareport,report.buf,report.size);
	return true;

}
bool VerifySignature(buffer_data *report) {
	//get the report from buffer
	TAreport tareport;
	int rt = translateBuf(*report,&tareport);
	if(rt!=1){
		printf("translate is failed!\n");
      return false;
	}
	//1. verify the signature by the public key from the cert and digest(is a quoted)

	char *data = "testdata";
   char sig[] = "ac90984b642d241161e90b6795c481f1ed0b065dbe713a7f4c562ba99ed91996b2b5fa0bf9319dfead8c98d0e58e10c890b4f628cd8d030b637ff4cf1a12642f4a27aafe794130057b94672c35af27727ad057fc83c8a22e499ab77e3cabe8ee1a0643edc0381e9d837f93ac6de4e0d7657a07e0ad0125ba79ba357a1682d4a7070bd1fe80d900105fdc5b32ec72211cd50e535775e604b880536d94e1e4cfc04710182ca9924decf215071ef50c5af87e178e125a2d5554f0ec07604daf6098dc1dd1b6b69dc813c89fdb2ad5849c125306fd058bf6447bb15251d67ebb4207fb4defde05b2609e029c009ecb18ad5ebbfa67e974057e48376501cc6190ee83";
   rt = verifysig(data,sig,tareport.cert);
	if(rt != 1){
		return false;	
	}
    printf("Verify success!\n");
    return true;
}
// int main(){
// 	TAreport report = {
// 		"1.0",   //version
// 		"20220504",		//timestamp
// 		"1001",		//nonce
// 		"",			//uuid
// 		"",			//alg
// 		"",			//
// 		"",			//hash
// 		"",
// 		"ac90984b642d241161e90b6795c481f1ed0b065dbe713a7f4c562ba99ed91996b2b5fa0bf9319dfead8c98d0e58e10c890b4f628cd8d030b637ff4cf1a12642f4a27aafe794130057b94672c35af27727ad057fc83c8a22e499ab77e3cabe8ee1a0643edc0381e9d837f93ac6de4e0d7657a07e0ad0125ba79ba357a1682d4a7070bd1fe80d900105fdc5b32ec72211cd50e535775e604b880536d94e1e4cfc04710182ca9924decf215071ef50c5af87e178e125a2d5554f0ec07604daf6098dc1dd1b6b69dc813c89fdb2ad5849c125306fd058bf6447bb15251d67ebb4207fb4defde05b2609e029c009ecb18ad5ebbfa67e974057e48376501cc6190ee83",
// 		"testcert",
// 	};
// 	int size = 0;
// 	for(int i=0;i<10;i++)
// 		size += len[i];
// 	buffer_data r = {
// 		size,
// 		&report
// 	};
// 	int rt = VerifySignature(&r);
// 	if(rt!=1){
// 		printf("verify is failed!");
// 	}
//    return 0;
// }
// bool Validate(buffer_data *manifest, BaseValue *basevalue) {
//     printf("Validate success!\n");
//     return true;
// }
bool VerifyManifest(buffer_data *data, int type, char *filename)
{
   bool result = false;
   TAreport *report = Convert(data);
   printf("report-version:%s\n", report->version);
   printf("report-timestamp:%s\n", report->timestamp);
   printf("report-uuid:%s\n", report->uuid);
   printf("report-image-hash:%s\n", report->image_hash);
   printf("report-hash:%s\n", report->hash);
   result = VerifyProcess(report, type, filename);
   if (result == true)
   {
      printf("%s\n", "Verification succeeded");
   }
   else
   {
      printf("%s\n", "Verification failed");
   }
   return result;
}

//Read data stream from buffer and convert to structure
TAreport *Convert(buffer_data *data)
{
   TAreport *report;
   if (data == NULL)
   {
      printf("%s\n", "illegal pointer,the buffer data is null");
      return NULL;
   }
   int bufsize = data->size;
   report = (TAreport *)malloc(sizeof(TAreport));
   char *init="0";
   strcpy(report->version,init);
   strcpy(report->timestamp,init);
   strcpy(report->nonce,init);
   strcpy(report->uuid,init);
   strcpy(report->alg,init);
   strcpy(report->image_hash,init);
   strcpy(report->hash,init);
   strcpy(report->reserve,init);
   strcpy(report->signature,init);
   strcpy(report->cert,init);
   if(strlen(data->buf)!=bufsize){
      printf("%s\n","bufsize error");
      return report;
   }
   int j = 0;
   for (int i = 0; i < VERSION ; i++, j++)
   {
      if (data->buf[j] != ' ' && j < bufsize - 1)
      {
         report->version[i] = data->buf[j];
      }
      else
      {
         if (data->buf[j] == ' ')
         {
            printf("%s\n","version convert complete");
            j++;
            break;
         }
         else
         {
            printf("%s\n","bufdata is over");
            return report;
         }
      }
   }
   for (int i = 0; i < TIMESTAMP ; i++, j++)
   {
      if (data->buf[j] != ' ' && j < bufsize - 1)
      {
         report->timestamp[i] = data->buf[j];
      }
      else
      {
         if (data->buf[j] == ' ')
         {
            printf("%s\n","timestamp convert complete");
            j++;
            break;
         }
         else
         {
            printf("%s\n","bufdata is over");
            return report;
         }
      }
   }
   for (int i = 0; i < NONCE ; i++, j++)
   {
      if (data->buf[j] != ' ' && j < bufsize - 1)
      {
         report->nonce[i] = data->buf[j];
      }
      else
      {
         if (data->buf[j] == ' ')
         {
            printf("%s\n","nonce convert complete");
            j++;
            break;
         }
         else
         {
            printf("%s\n","bufdata is over");
            return report;
         }
      }
   }
   for (int i = 0; i < UUID ; i++, j++)
   {
      if (data->buf[j] != ' ' && j < bufsize - 1)
      {
         report->uuid[i] = data->buf[j];
      }
      else
      {
         if (data->buf[j] == ' ')
         {
            printf("%s\n","uuid convert complete");
            j++;
            break;
         }
         else
         {
            printf("%s\n","bufdata is over");
            return report;
         }
      }
   }
   for (int i = 0; i < ALG ; i++, j++)
   {
      if (data->buf[j] != ' ' && j < bufsize - 1)
      {
         report->alg[i] = data->buf[j];
      }
      else
      {
         if (data->buf[j] == ' ')
         {
            printf("%s\n","alg convert complete");
            j++;
            break;
         }
         else
         {
            printf("%s\n","bufdata is over");
            return report;
         }
      }
   }
   for (int i = 0; i < IMAGE_HASH ; i++, j++)
   {
      if (data->buf[j] != ' ' && j < bufsize - 1)
      {
         report->image_hash[i] = data->buf[j];
      }
      else
      {
         if (data->buf[j] == ' ')
         {
            printf("%s\n","imagehash convert complete");
            j++;
            break;
         }
         else
         {
            printf("%s\n","bufdata is over");
            return report;
         }
      }
   }
   for (int i = 0; i < HASH ; i++, j++)
   {
      if (data->buf[j] != ' ' && j < bufsize - 1)
      {
         report->hash[i] = data->buf[j];
      }
      else
      {
         if (data->buf[j] == ' ')
         {
            printf("%s\n","hash convert complete");
            j++;
            break;
         }
         else
         {
            printf("%s\n","bufdata is over");
            return report;
         }
      }
   }
   for (int i = 0; i < RESERVE ; i++, j++)
   {
      if (data->buf[j] != ' ' && j < bufsize - 1)
      {
         report->reserve[i] = data->buf[j];
      }
      else
      {
         if (data->buf[j] == ' ')
         {
            printf("%s\n","reverse convert complete");
            j++;
            break;
         }
         else
         {
            printf("%s\n","bufdata is over");
            return report;
         }
      }
   }
   for (int i = 0; i < SIGNATURE ; i++, j++)
   {
      if (data->buf[j] != ' ' && j < bufsize - 1)
      {
         report->signature[i] = data->buf[j];
      }
      else
      {
         if (data->buf[j] == ' ')
         {
            printf("%s\n","signature convert complete");
            j++;
            break;
         }
         else
         {
            printf("%s\n","bufdata is over");
            return report;
         }
      }
   }
   for (int i = 0; i < CERT ; i++, j++)
   {
      if (data->buf[j] != ' ' && j < bufsize - 1)
      {
         report->cert[i] = data->buf[j];
      }
      else
      {
         if (data->buf[j] == ' ')
         {
            printf("%s\n","cert convert complete");
            j++;
            break;
         }
         else
         {
            printf("%s\n","bufdata is over");
            return report;
         }
      }
   }

   return report;
}

//verify the measurement value
bool VerifyProcess(TAreport *report, int type, char *filename)
{
   bool verified = false;
   char *init="0";
   if (type != 1 && type != 2)
   {
      printf("%s\n", "the type-value is incorrect");
      return verified;
   }
   if (report == NULL)
   {
      printf("%s\n", "the report is null");
      return verified;
   }
   if (filename == NULL)
   {
      printf("%s\n", "the filename is null");
      return verified;
   }
   if (strcmp(report->uuid,init) == 0){
      printf("%s\n", "the report is empty");
      return verified;
   }
   BaseValue *basevalue = loadbasevalue(report->uuid, filename); //use uuid to select which basevalue we need
   verified = compare(type, report, basevalue);                  //compare the report with the basevalue
   free(report);
   return verified;
}

BaseValue *loadbasevalue(char *uuid, char *filename)
{
   BaseValue *basevalue;
   if (uuid == NULL)
   {
      printf("%s\n", "the uuid is null");
      return NULL;
   }
   if (filename == NULL)
   {
      printf("%s\n", "the filename is null");
      return NULL;
   }
   basevalue = (BaseValue *)malloc(sizeof(BaseValue));
   char *init="0";
   strcpy(basevalue->uuid,init);
   strcpy(basevalue->valueinfo[0],init);
   strcpy(basevalue->valueinfo[1],init);
   //open the file which stores the basevalue
   FILE *fp;
   if ((fp = fopen(filename, "r")) == NULL)
   { // namefile=file path
      printf("%s\n", "Fail to open file!");
      exit(0); //fail to open and exit the function
   }
   else
   { //use uuid to select which basevalue we need
      char buf[MAXSIZE], save[MAXSIZE];
      while ((fgets(buf, MAXSIZE, fp)) != NULL)
      {
         strcpy(save, buf);
         char *p = strtok(buf, " ");
         if (strcmp(p, uuid) == 0)
         {
            sscanf(save, "%64s %32s %32s", basevalue->uuid, basevalue->valueinfo[0], basevalue->valueinfo[1]);
            break;
         }
      }
      if (strcmp(basevalue->uuid,init) == 0)
      {
         printf("%s\n", "can't search the corresponding basevalue");
      }
      else
      {
         printf("basevalue-uuid:%s\n", basevalue->uuid);
         printf("basevalue-image-measurement:%s\n", basevalue->valueinfo[0]);
         printf("basevalue-hash-measurement:%s\n", basevalue->valueinfo[1]);
      }
   }
   fclose(fp);
   return basevalue;
}

bool compare(int type, TAreport *report, BaseValue *basevalue)
{
   bool compared = false;
   if (type != 1 && type != 2)
   {
      printf("%s\n", "type is incorrect,can't do compatation");
      return compared;
   }
   if (report == NULL)
   {
      printf("%s\n", "TAreport is null,can't do compatation");
      return compared;
   }
   if (basevalue == NULL)
   {
      printf("%s\n", "basevalue is null,can't do compatation");
      return compared;
   }
   if (strcmp(basevalue->uuid,"0") == 0)
   {
      printf("%s\n", "basevalue is not be found,can't do compatation");
      return compared;
   }
   if (type == 1)
   {
      if (strcmp(report->image_hash, basevalue->valueinfo[0]) == 0)
      {
         compared = true;
         printf("%s\n", "the image-measurement is true");
      }
      else
      {
         printf("%s\n", "the image-measurement is false");
      }
   }
   else if (type == 2)
   {
      if (strcmp(report->hash, basevalue->valueinfo[1]) == 0)
      {
         compared = true;
         printf("%s\n", "the hash-measurement is true");
      }
      else
      {
         printf("%s\n", "the hash-measurement is false");
      }
   }
   free(basevalue); //free basevalue
   printf("finish comparation\n");
   return compared;
};

/*
Verify(report,1)------------Verification succeeded
Verify(report,2)------------Verification failed
*/
// void main()
// {
//    buffer_data report;
//    report.size = 121;
//    report.buf = "1.2 20220504 100 10EF6654-6A6F-C304-10AC-D48A0348A303 0 fc6aa6a655ec4b2fe5bff8d4670754ab 3fb951c89b84987a3dccb5400f821bga";
//    VerifyManifest(&report, 1, "basevalue.txt");
// }
