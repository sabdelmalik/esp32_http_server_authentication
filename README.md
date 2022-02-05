HHTTP Server Authentication

This project uses ESP IDF example: esp-idf\examples\protocols\http_server\simple

Call for authentication is inserted into the hello_get_handler() function.
Therefore if this code is invoked from a browser (e.g. http://192.168.2.229/hello),
Hello World! will only display after authentication takes place.

The code was tested in VS Code.

Two configuration parameters are available through menuconfig under "HTTP Server Authentication":
"HTTP authentication Scheme":

- HTTP_AUTH_NONE: No authentication - Hello World! just displays
- HTTP_AUTH_BASIC: Basic authentication according to https://www.rfc-editor.org/rfc/rfc7617.html
- HTTP_AUTH_DIGEST: Digest authentication according to https://www.rfc-editor.org/rfc/rfc7616.html

For both HTTP_AUTH_BASIC and HTTP_AUTH_DIGEST, Hello World! is displayed only after the correct credentials are entered. For this code credentials are hard coded as username: joe and password: Password1

"Digest scheme realm":
Only requires for Basic and Digest schemes. According to the RFCs, it is a string to be displayed to users so they know which username and password to use.
