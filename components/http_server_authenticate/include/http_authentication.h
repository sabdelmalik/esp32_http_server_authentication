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

#define HDR_BUFFER_LENGTH 1024

#if CONFIG_HTTP_AUTH_BASIC
extern char hdr_buffer[HDR_BUFFER_LENGTH];

esp_err_t check_authorisation(httpd_req_t *req, char *user_id, char *password);
esp_err_t send_basic_authorisation_request(httpd_req_t *req);
esp_err_t validate_basic_response(char *hdr_buffer, char *user_id, char *password);
#endif

#if CONFIG_HTTP_AUTH_DIGEST
extern char hdr_buffer[HDR_BUFFER_LENGTH];

esp_err_t check_authorisation(httpd_req_t *req, char *user_id, char *password);
esp_err_t send_digest_authorisation_request(httpd_req_t *req);
esp_err_t validate_digest_response(char *hdr_buffer, char *user_id, char *password);
#endif

esp_err_t get_header(httpd_req_t *req, const char *header_name, char *buf, size_t buf_len);
esp_err_t getMD5(uint8_t *data, uint16_t len, char *output);

size_t base64_encoded_size(size_t data_to_encode_size);
esp_err_t base64_encode(uint8_t *data_to_encode, size_t data_to_encode_size, char *encoded_data);