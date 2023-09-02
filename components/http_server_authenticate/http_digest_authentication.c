#include <stdlib.h>
#include <string.h>

#include <esp_log.h>
#include "esp_http_server.h"

#include "http_authentication.h"

#if CONFIG_HTTP_AUTH_DIGEST

static const char *TAG = "digest authentication";

static char nonce[33];
static char opaque[33];

esp_err_t send_digest_authorisation_request(httpd_req_t *req)
{
  uint32_t random = rand();
  getMD5((uint8_t *)(&random), 4, nonce);
  random = rand();
  getMD5((uint8_t *)(&random), 4, opaque);

  char hdr_buffer[128];
  sprintf(hdr_buffer, "Digest realm=\"%s\", qop=\"auth\", nonce=\"%s\", opaque=\"%s\"",
          CONFIG_DIGEST_REALM, nonce, opaque);

  ESP_LOGW(TAG, "WWW-Authenticate: %s", hdr_buffer);

  httpd_resp_set_status(req, "401 Unauthorized");
  httpd_resp_set_hdr(req, "WWW-Authenticate", hdr_buffer);
  httpd_resp_set_type(req, "text/html");
  httpd_resp_sendstr(req, "Authentication required");

  return ESP_ERR_NOT_FOUND;
}

esp_err_t parse_token(char *token_buffer, char *param, char *value)
{
  char *saveptr, *tmp;

  char *token = strtok_r(token_buffer, "=", &saveptr);
  if (token == NULL)
    return ESP_FAIL;

  tmp = param;
  while (*token != '\0')
  {
    if (*token != ' ')
      *tmp++ = *token;
    token++;
  }
  *tmp = '\0';

  token = strtok_r(NULL, "=", &saveptr);
  if (token == NULL)
    return ESP_FAIL;

  tmp = value;
  while (*token != '\0')
  {
    if (*token != '"')
      *tmp++ = *token;
    token++;
  }
  *tmp = '\0';

  printf("%s = %s\n", param, value);

  return ESP_OK;
}
/**
 * @brief 
 * 
 * @param hdr_buffer 
 * @param method 
 * @param user_id 
 * @param password 
 * @return esp_err_t 
 */
esp_err_t validate_digest_response(const char *hdr_buffer, const char *method, const char *user_id, const char *password)
{
  // TODO check that hdr_buffer starts with "Digest "

  char *saveptr;

  char param[16];
  char value[33];

  char rcvd_username[33];
  char rcvd_realm[33];
  char rcvd_nonce[33];
  char rcvd_uri[33];
  char rcvd_response[33];
  char rcvd_qop[33];
  char rcvd_nc[33];
  char rcvd_cnonce[33];

  char *token = strtok_r(hdr_buffer + strlen("Digest "), ",", &saveptr);
  parse_token(token, param, value);

  while (token != NULL)
  {

    if (strcmp(param, "username") == 0)
      strlcpy(rcvd_username, value, 33);
    else if (strcmp(param, "realm") == 0)
      strlcpy(rcvd_realm, value, 33);
    else if (strcmp(param, "nonce") == 0)
      strlcpy(rcvd_nonce, value, 33);
    else if (strcmp(param, "uri") == 0)
      strlcpy(rcvd_uri, value, 33);
    else if (strcmp(param, "response") == 0)
      strlcpy(rcvd_response, value, 33);
    else if (strcmp(param, "qop") == 0)
      strlcpy(rcvd_qop, value, 33);
    else if (strcmp(param, "nc") == 0)
      strlcpy(rcvd_nc, value, 33);
    else if (strcmp(param, "cnonce") == 0)
      strlcpy(rcvd_cnonce, value, 33);

    token = strtok_r(NULL, ",", &saveptr);
    parse_token(token, param, value);
  }

  // https://www.rfc-editor.org/rfc/rfc7616.html
  // section 3.4.2. A1
  // A1       = unq(username) ":" unq(realm) ":" passwd
  // A2       = Method ":" request-uri
  //  response = <"> < KD ( H(A1), unq(nonce)
  //                                    ":" nc
  //                                    ":" unq(cnonce)
  //                                    ":" unq(qop)
  //                                    ":" H(A2)
  //                           ) <">
  char work_buffer[256];
  char A1_hash[33];
  sprintf(work_buffer, "%s:%s:%s", user_id, CONFIG_DIGEST_REALM, password);
  getMD5((uint8_t *)work_buffer, strlen(work_buffer), A1_hash);
  ESP_LOGW(TAG, "A1: %s, A1_hash: %s", work_buffer, A1_hash);

  char A2_hash[33];
  sprintf(work_buffer, "%s:%s", method, rcvd_uri);
  getMD5((uint8_t *)work_buffer, strlen(work_buffer), A2_hash);
  ESP_LOGW(TAG, "A2: %s, A2_hash: %s", work_buffer, A2_hash);

  char resp_hash[33];
  sprintf(work_buffer, "%s:%s:%s:%s:%s:%s", A1_hash, nonce, rcvd_nc, rcvd_cnonce, rcvd_qop, A2_hash);
  getMD5((uint8_t *)work_buffer, strlen(work_buffer), resp_hash);
  ESP_LOGW(TAG, "resp: %s, resp_hash: %s", work_buffer, resp_hash);

  memset(nonce, '\0', sizeof(nonce));

  if (strcmp(rcvd_response, resp_hash) == 0)
  {
    return ESP_OK;
  }

  return ESP_FAIL;
}

#endif