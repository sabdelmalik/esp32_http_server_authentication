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

#include <stdlib.h>
#include <string.h>

#include <esp_log.h>
#include "esp_http_server.h"
#include "mbedtls/md5.h"

#include "http_authentication.h"

#if CONFIG_HTTP_AUTH_BASIC

static const char *TAG = "basic authentication";

/**
 * @brief 
 * 
 * @param req 
 * @return esp_err_t 
 */
esp_err_t send_basic_authorisation_request(httpd_req_t *req)
{
  char hdr_buffer[128];
  sprintf(hdr_buffer, "Basic realm=\"%s\"", CONFIG_DIGEST_REALM);

  ESP_LOGW(TAG, "WWW-Authenticate: %s", hdr_buffer);

  httpd_resp_set_status(req, "401 Unauthorized");
  httpd_resp_set_hdr(req, "WWW-Authenticate", hdr_buffer);
  httpd_resp_set_type(req, "text/html");
  httpd_resp_sendstr(req, "Authentication required");

  return ESP_ERR_NOT_FOUND;
}

/**
 * @brief 
 * 
 * @param hdr_buffer 
 * @param user_id 
 * @param password 
 * @return esp_err_t 
 */
esp_err_t validate_basic_response(char *hdr_buffer, char *user_id, char *password)
{
  // TODO check that hdr_buffer starts with "Basic "

  char data_to_encode[128];
  sprintf(data_to_encode, "%s:%s", user_id, password);

  size_t encoded_data_size = base64_encoded_size(strlen(data_to_encode));
  char *encoded_creds = (char *)calloc(encoded_data_size, 1);

  base64_encode((uint8_t *)data_to_encode, strlen(data_to_encode), encoded_creds);

  if (strcmp(hdr_buffer + strlen("Basic "), encoded_creds) == 0)
  {
    return ESP_OK;
  }

  return ESP_FAIL;
}

#endif
