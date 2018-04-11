# SimpleSecureSerialization
Simple Secure Serialization library.

Written in c.


struct SSCS_data{ //Object returned by SSCS_object_data

   void* data; //Data related to label

size_t len; //Length of data

}sscsd;

void *SSCS_object(void); //Create SSCS object

int SSCS_object_add_data(sscso* obj,char* label,byte* data,size_t size); //Add data (binary or other) to SSCS object

sscsd* SSCS_object_data(sscso* obj,char* label); //Get SSCS_data structure from SSCS_object via label

char* SSCS_object_encoded(sscso* obj); //Get serialized string to send

size_t SSCS_object_encoded_size(sscso* obj); // Get serialized string length 

byte* SSCS_data_get_data(sscsd* data); //Get data from SSCS_data structure

size_t SSCS_data_get_size(sscsd* data); //Get data length from SSCS_data structure

void SSCS_free(sscso* obj); //Free Buffer

void SSCS_release(sscso** obj); //Free SSCS_data obj + SSCS_data struct

void SSCS_data_release(sscsd** data); //Free Buffer + SSCS_object struct

