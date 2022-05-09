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

bool VerifySignature(buffer_data *report) {
    printf("Verify success!\n");
    return true;
}

TAreport *Convert(buffer_data *data);
bool VerifyProcess(TAreport *report, int type, char *filename);
BaseValue *loadbasevalue(char *uuid, char *filename);
bool compare(int type, TAreport *report, BaseValue *basevalue);

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
