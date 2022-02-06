#include <esp_log.h>
#include "esp_http_server.h"
#include "mbedtls/md5.h"

#include "http_authentication.h"

char hdr_buffer[HDR_BUFFER_LENGTH];

static const char *TAG = "http authentication common";

#if !CONFIG_HTTP_AUTH_NONE

esp_err_t check_authorisation(httpd_req_t *req, char *user_id, char *password)
{

  esp_err_t ret = get_header(req, "Authorization", hdr_buffer, sizeof(hdr_buffer));

  if (ret == ESP_ERR_NOT_FOUND)
  {
#if CONFIG_HTTP_AUTH_DIGEST
    return send_digest_authorisation_request(req);
#elif CONFIG_HTTP_AUTH_BASIC
    return send_basic_authorisation_request(req);
#endif
  }

  if (ret == ESP_ERR_INVALID_SIZE)
  {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Memory allocation failed");
    return ESP_FAIL;
  }
  if (ret != ESP_OK)
  {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Error in getting value of header");
    return ESP_FAIL;
  }

  ESP_LOGW(TAG, "Authorization: %s", hdr_buffer);

#if CONFIG_HTTP_AUTH_DIGEST
  if (validate_digest_response(hdr_buffer, get_method_string(req->method), user_id, password) != ESP_OK)
    return send_digest_authorisation_request(req);
#elif CONFIG_HTTP_AUTH_BASIC
  if (validate_basic_response(hdr_buffer, user_id, password) != ESP_OK)
    return send_basic_authorisation_request(req);
#endif
  else
    return ESP_OK;
}
#endif

esp_err_t get_header(httpd_req_t *req, const char *header_name, char *buf, size_t buf_len)
{
  ESP_LOGD(TAG, "get_header: header_name = %s", header_name);
  int hdr_len = httpd_req_get_hdr_value_len(req, header_name);

  if (hdr_len > 0)
  {
    if ((hdr_len + 1) > buf_len)
    {
      ESP_LOGE(TAG, "passed buffer size (%d) too small. Heder length = %d", buf_len, hdr_len + 1);
      //httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Memory allocation failed");
      return ESP_ERR_INVALID_SIZE;
    }
    /* Copy null terminated value string into buffer */
    if (httpd_req_get_hdr_value_str(req, header_name, buf, hdr_len + 1) != ESP_OK)
    {
      ESP_LOGE(TAG, "Error getting value of '%s' header", header_name);
      return ESP_FAIL;
    }
  }
  else
  {
    ESP_LOGE(TAG, "Header '%s' not found", header_name);
    return ESP_ERR_NOT_FOUND;
  }
  return ESP_OK;
}

esp_err_t getMD5(uint8_t *data, uint16_t len, char *output)
{ //33 bytes or more
  mbedtls_md5_context _ctx;
  uint8_t i;
  uint8_t *buf = (uint8_t *)malloc(16);
  if (buf == NULL)
    return ESP_FAIL;
  memset(buf, 0x00, 16);

  mbedtls_md5_init(&_ctx);
  mbedtls_md5_starts_ret(&_ctx);
  mbedtls_md5_update(&_ctx, data, len);
  mbedtls_md5_finish(&_ctx, buf);
  for (i = 0; i < 16; i++)
  {
    sprintf(output + (i * 2), "%02x", buf[i]);
  }
  free(buf);
  output[strlen(output)] = 0;
  return ESP_OK;
}

char *get_method_string(httpd_method_t method)
{
  switch (method)
  {
  case HTTP_GET:
    return "GET";
  case HTTP_POST:
    return "POST";
  case HTTP_DELETE:
    return "DELETE";
  case HTTP_PUT:
    return "PUT";
  default:
    return "UNKNOWN";
  }
}