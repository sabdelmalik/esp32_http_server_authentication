/*
 Copyright (c) 2022 Sami Onsy Abdel Malik

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @brief base64_encoding.c
 * 
 * contains routins to encode an array of bytes according to https://www.rfc-editor.org/rfc/rfc4648#section
 * The following description is copied from the refrenced RFC.
 * The Base 64 encoding is designed to represent arbitrary sequences of octets in a form that allows 
 * the use of both upper and lowercase letters but that need not be human readable.
 * 
 * A 65 character subset of US - ASCII is used, enabling 6-bits to be represented per printable character.
 * (The extra 65th character, "=", is used to signify a special processing function.)
 * The encoding process represents 24-bit groups of input bits as output strings of 4 encoded characters.
 * Proceeding from left to right, a 24-bit input group is formed by concatenating 3 8-bit input groups.
 * These 24-bits are then treated as 4 concatenated 6-bit groups, each of which is translated into a 
 * single character in the base 64 alphabet. Each 6-bit group is used as an index into an array of 64 
 * printable characters.The character referenced by the index is placed in the output string.
 */
#include <stdlib.h>
#include <string.h>

#include <esp_log.h>
#include <stddef.h>
#include "esp_http_server.h"

/**
 * @brief array of base64 alphabet as defined in rfc4648. 6 bit code is used to index into into it.
 */
static char base64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * @brief given the size of the source string to be encoded, returns the size to be allocated for
 * 
 * @param data_to_encode_size 
 * @return size_t the size to be allocated for the buffer that receives the base64 encoded string.
 * 
 * the number of 6 bits in the data. Each 3 bytes (24 bit group), translate to 4 characters
 * if fewer than 24 bits are available at the end of the data being encoded, bits with value
 * zero are added (on the right) to form an integral number of 6 - bit groups.
 * To cater for this, since we deal with integers, we add 2 to the passed length.
 * One is added to the the result for a string terminating null.
 */
size_t base64_encoded_size(size_t data_to_encode_size)
{
  return (((data_to_encode_size + 2) / 3) * 4) + 1;
}

/**
 * @brief base64_encode: encodes an array of bytes according to rfc4648
 * 
 * @param data_to_encode an array of bytes to encode
 * @param data_to_encode_size size of the array of bytes 
 * @param encoded_data a buffer that receives the base64 encoded string. must be allocated  with
 *                     size obtained from base64_encoded_size function.
 * @return esp_err_t currently, it always returns ESP_OK
 */
esp_err_t base64_encode(uint8_t *data_to_encode, size_t data_to_encode_size, char *encoded_data)
{
  // Data is encoded 24-bit (3 byte group). Because special processing is performed if fewer than 24
  // bits are available at the end of the data being encoded, we first encode the first 3n bytes, then
  // treat the remaing bits seperatly
  int first_part = data_to_encode_size - (data_to_encode_size % 3);

  // index for the output buffer
  int j = 0;

  // loop through the first part
  for (int i = 0; i < first_part; i += 3)
  {
    // concatenate 3 bytes into 24 bits of a 32 bit word
    unsigned int data = (data_to_encode[i] << 16) + (data_to_encode[i + 1] << 8) + data_to_encode[i + 2];

    // use each 6 bits to index into the base64_alphabet
    encoded_data[j++] = base64_alphabet[(data >> 18) & 0x3F];
    encoded_data[j++] = base64_alphabet[(data >> 12) & 0x3F];
    encoded_data[j++] = base64_alphabet[(data >> 6) & 0x3F];
    encoded_data[j++] = base64_alphabet[(data)&0x3F];
  }

  // do we have any remaining bytes?
  int remain = data_to_encode_size - first_part;
  if (remain > 0)
  {
    // yes, special encoding ...
    unsigned int data = 0;
    // at least one byte
    data += data_to_encode[first_part] << 16;
    if (remain == 1)
    {
      // only one byte remaining,  we encode the 8 bits as xxxxx xx0000
      encoded_data[j++] = base64_alphabet[(data >> 18) & 0x3F];
      encoded_data[j++] = base64_alphabet[(data >> 12) & 0x3F];
      // then add '='
      encoded_data[j++] = '=';
    }
    else
    {
      // two bytes remaining,  we encode the 16 bits as xxxxx xxxxxx xxxx00
      data += data_to_encode[first_part + 1] << 8;
      encoded_data[j++] = base64_alphabet[(data >> 18) & 0x3F];
      encoded_data[j++] = base64_alphabet[(data >> 12) & 0x3F];
      encoded_data[j++] = base64_alphabet[(data >> 6) & 0x3F];
    }
    // add a final '='
    encoded_data[j++] = '=';
  }

  return ESP_OK;
}
