#include <errno.h>
#include <stdlib.h>
#include <stdio.h> 
#include <assert.h>
#include <string.h> 
#include "base64.h"
#include "serialization.h"

/*
 * SimpleSecureChat Serialization Library. Made with Security in mind.
*/
/*
void debug_sscso(sscso* obj){
	puts("Printing debug info on SSCS_struct");
	printf("Pointer to buffer is 0x%x\n",(unsigned int)(obj->buf_ptr));
	printf("buffer size is %d\n",(unsigned int)(obj->allocated));
	if(obj->buf_ptr != NULL){
		puts("Printing Buffer");
		int i = 0;
		while(i <= obj->allocated){
			char* nextchar = obj->buf_ptr + i;
			//printf("%c(0x%x)|",*nextchar,*nextchar);
			printf("%c",*nextchar);
			i++;
		}
		printf("\n End\n\n");
	}
	return ;	
}
*/
void *SSCS_object(){
	sscso* obj = malloc(sizeof(struct SSCS_struct));		
	obj->buf_ptr = NULL; obj->allocated = 0;
	return obj;
}

int SSCS_object_add_data(sscso* obj,char* label,byte* data,size_t size){
	if(size <= 0)return 1; //Size has to be bigger than 0
	void *old_buf_ptr = obj->buf_ptr;
	size_t old_buf_size = obj->allocated;	
	size_t encoded_size;
	byte* b64data = base64_encode(data,size,&encoded_size);
	int b64datalen = encoded_size;
	int label_len = strlen((const char*)label);
	size_t final_intermediate_len = b64datalen+label_len+4;
	byte* intermediatebuf = malloc(final_intermediate_len);
	memset(intermediatebuf,0,final_intermediate_len);
	byte* ibufwloc = intermediatebuf; //ibufwloc is a pointer to the next area to write to
	int i = 0;
	while(i < label_len){
		*ibufwloc = label[i];
		ibufwloc++;
		i++;
	}
	*ibufwloc = ':';
	ibufwloc++;
	*ibufwloc = '"';
	ibufwloc++;
	memcpy(ibufwloc,b64data,encoded_size); //Add B64 encoded data 
	ibufwloc += b64datalen;
	*(ibufwloc) = '"';
	ibufwloc++;
	*ibufwloc = ';';
	ibufwloc++;
	free(b64data);	
	size_t new_buf_size = (old_buf_size + final_intermediate_len);
	void *new_buf_ptr = malloc(new_buf_size);
	memset(new_buf_ptr,0,new_buf_size);
	if(old_buf_ptr != NULL)memcpy(new_buf_ptr,old_buf_ptr,old_buf_size);
	free(old_buf_ptr);
	old_buf_ptr = NULL;
	i = 0;
	byte* base_ptr = new_buf_ptr + old_buf_size ;	
	while(i < (int)final_intermediate_len){
		*base_ptr = intermediatebuf[i];	
		base_ptr++;
		i++;
	}
	obj->allocated = new_buf_size;
	obj->buf_ptr = new_buf_ptr;
	free(intermediatebuf);
	return 0;
}
sscsd* SSCS_object_data(sscso* obj,char* label){
	byte* buf_ptr = obj->buf_ptr;
	size_t allocated = obj->allocated;
	byte* readpointer = (byte*)strstr((const char*)buf_ptr,label);
	if(readpointer == NULL){
		puts("Label Not Found");
		return NULL;
	}
	readpointer = (byte*)strstr((const char*)readpointer,":\"");	
	if(readpointer == NULL){
		puts("Invalid SSCS object");
		return NULL;
	}
	readpointer+=2;
	//Readpointer is now at the beginning of the base64 encoded data
	int i = 0;
	while(readpointer[i] != '"' && readpointer[i+1] != ';'){ //Run once to get length of string 
		if(!((readpointer+i)-buf_ptr < (signed)allocated)){
			puts("Outsize of memory bounds");
			return NULL;
		}
		i++;	
	}
	double b64encoded_len = i; 
	byte* b64buffer = malloc(b64encoded_len); 
	i = 0;
	/* Run loop again to read encoded string */
	while(readpointer[i] != '"' && readpointer[i+1] != ';'){ //Get base64encoded data 
		if(!((size_t)((readpointer+i) - buf_ptr) < allocated) || b64encoded_len < i){
			puts("Outsize of memory bounds");
			free(b64buffer);
			return NULL;
		}
		*(b64buffer+i) = *(readpointer+i);	
		i++;
	}
	size_t len; 
	sscsd* final = malloc(sizeof(sscsd));
	final->data = base64_decode((const unsigned char*)b64buffer,b64encoded_len,&len);
	final->len = len;
	free(b64buffer);
	return final;
}

char* SSCS_object_encoded(sscso* obj){ //Get string to send over socket
	return obj->buf_ptr;
}

size_t SSCS_object_encoded_size(sscso* obj){ //Get size of string(often needs to be specified when sending over socket)
	return obj->allocated;	
} 
byte* SSCS_data_get_data(sscsd* data){
	return data->data;
}
size_t SSCS_data_get_size(sscsd* data){
	return data->len;
}
void SSCS_free(sscso* obj){ //Frees current buffer associated with sscso obj (Object Can be Reused)
	free(obj->buf_ptr);
	obj->buf_ptr = NULL;
	obj->allocated = 0;
}

void SSCS_release(sscso** obj){ //Frees the current buffer AND the structure holding the address to the buffer; (Object Cant be Reused)
	free(((*obj)->buf_ptr));
	free(*obj);
	*obj = NULL;
}
void SSCS_data_release(sscsd** data){ //Frees the data buffer AND the structure holding the address and the length
	if(*data == NULL)return;
	free(((*data)->data));
	free(*data);
	*data = NULL;	
}

/*
int main(void){
	sscso* obj = SSCS_object();
	SSCS_object_add_data(obj,"label1",(byte*)"test",4);
	sscsd* message = SSCS_object_data(obj,"label1");
	if(message != NULL)fprintf(stdout,message->data,message->len);
	SSCS_data_release(&message);
	SSCS_release(&obj);
	return 0;
} 
*/