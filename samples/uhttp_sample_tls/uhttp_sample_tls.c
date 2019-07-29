// Copyright (c) Microsoft. All rights reserved.
// Copyright (c) Twilio Inc. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include "azure_c_shared_utility/threadapi.h"
#include "azure_c_shared_utility/tickcounter.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/platform.h"
#include "azure_c_shared_utility/socketio.h"
#include "azure_c_shared_utility/tlsio.h"
#include "azure_c_shared_utility/shared_util_options.h"
#include "azure_uhttp_c/uhttp.h"

#define HTTP_PORT_NUM       80
#define HTTPS_PORT_NUM      11111

const char* client_cert = "-----BEGIN CERTIFICATE-----\n\
MIIEfzCCAmcCCQDUuQBXuzl2njANBgkqhkiG9w0BAQsFADCBhTELMAkGA1UEBhMC\n\
SVMxEDAOBgNVBAgMB0ljZWxhbmQxEjAQBgNVBAcMCVJleWtqYXZpazESMBAGA1UE\n\
CgwJTUlBUyBUZXN0MScwJQYDVQQLDB5DZXJ0aWZpY2F0ZSBpc3N1aW5nIGRlcGFy\n\
dG1lbnQxEzARBgNVBAMMCmV4YW1wbGUuaXMwHhcNMTkwNTA4MTMzMzQ5WhcNMjQw\n\
NTA2MTMzMzQ5WjB9MQswCQYDVQQGEwJJUzEQMA4GA1UECAwHSWNlbGFuZDESMBAG\n\
A1UEBwwJUmV5a2phdmlrMRIwEAYDVQQKDAlNSUFTIFRlc3QxFjAUBgNVBAsMDVFB\n\
IERlcGFydG1lbnQxHDAaBgNVBAMME1plcGh5ciBRdWVjdGVsIEJHOTYwggEiMA0G\n\
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCjJ8AclFX+hA6QCy/gGxUYCgvwUmio\n\
Fy3XgHd6wBnX15kqEo0QFf+zQ2Zaql/GVwhJ2rL5/Z2lVUzdnd+CjanDXNnYmlMd\n\
qRduqV09PbJq4VGmr0iSlp1c6y6I/lbLU3qkPthUWzDBGPPMRlEHHoO48hH+4cZy\n\
oUKctfvkigPKDYTblRJW2+gN9Ptua+urMvNkxxsFfdZpwe9s4/8DI6ouBAlpvgfY\n\
86S1f3f2++eL0nmhanJOAkbaVDs2DcGWDKFUdUP1c832dRpkh9ny4yK2F3s2RRRa\n\
nhNQEQp+H/WDGMXIKZcLvrGeDXAwbz5C8Xh2xvSb0VGznIHXQSqf4KlbAgMBAAEw\n\
DQYJKoZIhvcNAQELBQADggIBANFn6su7SZBxDa+mMrN3tytQBJRVEwuBbs1Ri5g9\n\
UBcMxi1VZX3ievvg3KMb+Isfu+mIVkR9Iig2mNAByjztR7ejF0MpkDOYYPHUx1lK\n\
T29XpcP5FrN3J+0IPidtD5kjR7Wf0vVeuYOFrDNA/bT7ltA4YAQS5lvrb7V7pDjQ\n\
XX1KNg39olShTxvZX7/+hUavV4ExGLuYq7brVJktQ7u8k5Nao5FZhoeDr0PsLoPF\n\
n4sbh96oSAcmcAXtpx5ZB33xGJvhHREDZPL9I1FeB6MgoPhivExP9J7Ft8IT+jJu\n\
jsZDywOwOB6zsKtfQFMlChrYICyO91uk+f63toZzi5FtTN7XcUNDb859cC2AilBH\n\
ZsZQacHPDV1ZgnGjt3p/Zz5djG3XlO5QjHYHzxZ4u9O/0f1QwR+658VXjqTltv9h\n\
AGWiuXcWC3V2JuTFyDuMMbFRFUYYyPODdDMUC2nFDay5fH12A+TxqDYNW+N2VMZM\n\
kquIl2Nn7ZzKvq8VlD7KMICL3o+U9rJT4D8qjIGIFlCNn0ni3EKOS5rIwixPPbv4\n\
cRI1zELUMD4VKs3E/wI90eN1o/E8PHSdRbOfNyHP6SGxJY+1KPvlU+k6d6zNZ/tM\n\
8G9F7eD7B8spskplmwtaTd6a4EmV3wj+eh9wVL9W0koSoAahTYlmdBUYffX8QX2D\n\
KbFK\n\
-----END CERTIFICATE-----";

const char* client_key = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEowIBAAKCAQEAoyfAHJRV/oQOkAsv4BsVGAoL8FJoqBct14B3esAZ19eZKhKN\n\
EBX/s0NmWqpfxlcISdqy+f2dpVVM3Z3fgo2pw1zZ2JpTHakXbqldPT2yauFRpq9I\n\
kpadXOsuiP5Wy1N6pD7YVFswwRjzzEZRBx6DuPIR/uHGcqFCnLX75IoDyg2E25US\n\
VtvoDfT7bmvrqzLzZMcbBX3WacHvbOP/AyOqLgQJab4H2POktX939vvni9J5oWpy\n\
TgJG2lQ7Ng3BlgyhVHVD9XPN9nUaZIfZ8uMithd7NkUUWp4TUBEKfh/1gxjFyCmX\n\
C76xng1wMG8+QvF4dsb0m9FRs5yB10Eqn+CpWwIDAQABAoIBAHkf86HEBiuTwnPx\n\
ujM4J+rW2pIpvAS+YIwSlaENqKHzL4RqjUsZ6eEd8ojw33WR+1dJA4JQZI7vysbk\n\
g6CapyOgdSI3P+lPNVQ0bEIg4aozaLjEfK5HHsBy4PNXTvxYFz6EYXoO0R0p9yT6\n\
NwGAB+5v2ChPWVKUoa1R9ZVvWOzQ+OgQDQVfAlRv2CvvIvrsR3tgfj7zid4VRXP/\n\
8s5xq5m8O8Rs08LBD2wMDP6OVcE8GAspGCX7304RCjUjdPQTPADAc15oug3J2whW\n\
z74CKzAZwgUyLhibu88t6frD2pFkUsc+TYaAD1M7bqVYQ3uFN2Ca/CDmN+ZAyD2J\n\
ZaMuQAECgYEA01Z7wHNJtGgFk4Q+31+U9UNHW60rWvgpZEyPv815q4fuQQ4qziSS\n\
+CsaAsb/zChuvMWChFfrdqWcditLTsEflVrRlOhLHQ6bSvpzZJkHnRg9oR99TFlO\n\
XFjhrJXzBjgTF0il4TiO9DutmkCVc9ngZkd94+0qCfV6A2sbQFpe2VsCgYEAxaKP\n\
H1PdbHzEZN/rXgzsXjXUg7ZkGAhAdJmKGdF9iJoGufgK7/Wo56eUhd/KVIguB9oU\n\
V2jTDA1b47IHau5kLjUdV8b6iJEz2olVu+JgZ1mntTMpIBoYOSTzxyLgE39D/+iV\n\
dYCcyHKudK/oDk7MAIGrmfLXruO1tkdEEZVecAECgYAxp3IwB2Zb0szsmffDt8th\n\
zMrpSUiUeRYQkMR9hiN+H9PkyRVZldJKKKZV3LehGibah3Vg7t9N4x9dzFJHUKzB\n\
BLOVTvbG/vWRqkKOcj4NtPJV9vYTiDAXFnL/f8O3xFkH8XO39PfxfkwNn/r9W0WU\n\
Alwbv09PQ7PFNdcTSahbXQKBgCWSWNkgzWhxc7ilpQ41ML5cR3FevDqhXveLtOhh\n\
nhbZCUxTbmjd7+VSQ3cL62AUn4OYnuNbJzwUUhLAZo6akWsDZ/em+Tv7Nrtl/mmA\n\
iMk9DxfwiPH0ZASBFOMXqzepqxi8c6Vp9ORagPXn9xq5Oikifaf/tacm3QWxGKyr\n\
E9ABAoGBANE3hrdt6vzvldbmXfojPaKjZbgXwBqwjgMwQjOfLz8HKKBoAox62Efv\n\
BAacWFvH6tdQn9EyxWB2yRz2PsK5LUcaJ3cNUqwLoarQH5VaPIV4lWtcoFD0hgx/\n\
t1nBBVua4V2ERktQjqeDDBVd4PqEwDFKZrC9uXIfABHH2HNyHTBs\n\
-----END RSA PRIVATE KEY-----";

const char* server_ca_cert = "-----BEGIN CERTIFICATE-----\n\
MIIF4jCCA8qgAwIBAgIJANSXMXyoe8mxMA0GCSqGSIb3DQEBCwUAMIGFMQswCQYD\n\
VQQGEwJJUzEQMA4GA1UECAwHSWNlbGFuZDESMBAGA1UEBwwJUmV5a2phdmlrMRIw\n\
EAYDVQQKDAlNSUFTIFRlc3QxJzAlBgNVBAsMHkNlcnRpZmljYXRlIGlzc3Vpbmcg\n\
ZGVwYXJ0bWVudDETMBEGA1UEAwwKZXhhbXBsZS5pczAeFw0xOTA1MDgxMzMzNDla\n\
Fw0yNDA1MDYxMzMzNDlaMIGFMQswCQYDVQQGEwJJUzEQMA4GA1UECAwHSWNlbGFu\n\
ZDESMBAGA1UEBwwJUmV5a2phdmlrMRIwEAYDVQQKDAlNSUFTIFRlc3QxJzAlBgNV\n\
BAsMHkNlcnRpZmljYXRlIGlzc3VpbmcgZGVwYXJ0bWVudDETMBEGA1UEAwwKZXhh\n\
bXBsZS5pczCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANGX3HlYuRl9\n\
mhg9B7HgspPAkxQfwuCC8S+FheKLh5H91uw2gqmQYnz8wQITFQnWabQrd2f/R2ni\n\
X2nFO3FBddvfOhVead7/3NsDz14jWqpq1ycdHApC8kQKIvrdOtd9zlkAWEMJ0OMb\n\
Y4d4TS/dYMjsFuvtyRPakTLq2WwuZ5JDfitfQYile/c8N5OPUNSA8gdKW7fLj8z0\n\
mitMrzPjcrkotrcMfla66RgIDiNB7+kwOHuLVGkVhCChRH/nzmISelY/fGOUnDWa\n\
jwjih6ECwQkCXb280ek+FWOoOP8wKXUIe9lfRF3rSf8ha5v9URoDdg/oTMAtpIrY\n\
+7V2hTrKeTPH9CNj6AxfIBrnTOgwsatYqHRjnFdWwLnpFu+4qRxL0FmqUrm9dN8T\n\
5rnGGrquT2KAFwgMGktyHR9uK1N+xHA8o4KJOreayjRSBN4//qUApYlOUC5fOZ2M\n\
o0D5AS9Qgq8RkP5maQxhKWiRJHfsXvVru3x2Jq+dRvBXFLeBTjDTIALOvp5UvLjv\n\
+jMIR/KlbLcETXMD4OvEQ0UPl1p+57ePAg4oh8M3hOTlPiYnOhFIoSxhKwqB+3NP\n\
a+X7kVO/4OmWPVOi6rUoGaqIhrOcoNrXKp3eQY56OjJe1G/A8UqNo71kzvazKz16\n\
eVq8ggNNEnXuaXAPnBwtexuer2uMfpjXAgMBAAGjUzBRMB0GA1UdDgQWBBRpIayE\n\
5koFTi+kcdzrlt63MaEEojAfBgNVHSMEGDAWgBRpIayE5koFTi+kcdzrlt63MaEE\n\
ojAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQDAOjfUsGNNpxDu\n\
IoC8fah1g7wry1ndkJCCl+NkCHWvwGC4jMRXD7JOLV0XSu1481F3N+J+OzbXGx6A\n\
Q73NPErVDuEnXNd6ckFvH2g/j0XxV94XVlxxf6x5Dlex9EL6/JBPg9pVenqAqgeU\n\
m2Te8INPzoMUXYaRqAqGsOunJkq0cFX2DIvy3sFgtyWi9NSx/nfpsqqUGqfpjMi8\n\
2hoQbFBrZ9QhiLOPkyaSpp50zDSHvL6+4rRNO2cTPuzCx3QkLPiokz1r9W04XL1Z\n\
NKDVKS7x4OD8TlfZllWXI6r0hlUew/i6cTfOzPLR9f9IETI/sB8axmcVkMJXfIoz\n\
xuBNluvFKZdjnoke8mFZ2mnJlOuq/k6JOzRdhDhCRDxYZocx2BBAIuRZLU3+++BM\n\
SgKs8dEFCiIHnEBTT2l/5vaMp1yL1Q8m334f+1BJig0YfTrbMD7ETBEFxtEkdO7y\n\
z2PV9mXojirG/Kirp1NL3R6oADw2W4ZA8rTKeaoe3X/1NnVfxH9i80FUKGkB6k1s\n\
RrQcvz9ffiwHPWkTclg+e2+k/wvZSqxuorN5s1ISdh9t6xGlfTFIt1cbLAw83twd\n\
P0nWD523hY9SLw9psaOENP7u264X8rsvS6wOiPyAgQ2rlV9QJD8a2V6nfaNWdUFC\n\
OEJKzGK1LSQ7ZS/dmgDfWxozY9lLCw==\n\
-----END CERTIFICATE-----";

typedef struct HTTP_SAMPLE_INFO_TAG
{
    int stop_running;
} HTTP_SAMPLE_INFO;

static void on_http_connected(void* callback_ctx, HTTP_CALLBACK_REASON connect_result)
{
    (void)callback_ctx;
    if (connect_result == HTTP_CALLBACK_REASON_OK)
    {
        (void)printf ("HTTP Connected\r\n");
    }
    else
    {
        (void)printf ("HTTP Connection FAILED\r\n");
    }
}

static void on_http_recv(void* callback_ctx, HTTP_CALLBACK_REASON request_result, const unsigned char* content, size_t content_len, unsigned int statusCode, HTTP_HEADERS_HANDLE responseHeadersHandle)
{
    (void)responseHeadersHandle;
    (void)request_result;
    (void)content_len;
    (void)statusCode;
    (void)content;
    printf("content_len is %d\r\n", (int)content_len);
    if (callback_ctx != NULL)
    {
        HTTP_SAMPLE_INFO* http_info = (HTTP_SAMPLE_INFO*)callback_ctx;
        http_info->stop_running = 1;
    }
    else
    {
        (void)printf("callback_ctx is NULL!!!!!\r\n");
    }
}

static void on_error(void* callback_ctx, HTTP_CALLBACK_REASON error_result)
{
    (void)callback_ctx;
    (void)error_result;
    printf("HTTP client Error Called\r\n");
}

static void on_closed_callback(void* callback_ctx)
{
    (void)callback_ctx;
    printf("Connection closed callback\r\n");
}

static HTTP_CLIENT_HANDLE create_uhttp_client_handle(HTTP_SAMPLE_INFO* sample_info, const char* host_name, int port_num)
{
    SOCKETIO_CONFIG config;
    TLSIO_CONFIG tls_io_config;
    const void* xio_param;
    const IO_INTERFACE_DESCRIPTION* interface_desc;
    if (port_num == HTTPS_PORT_NUM)
    {
        tls_io_config.hostname = host_name;
        tls_io_config.port = port_num;
        tls_io_config.underlying_io_interface = NULL;
        tls_io_config.underlying_io_parameters = NULL;
        xio_param = &tls_io_config;
        // Get the TLS definition
        interface_desc = platform_get_default_tlsio();
    }
    else
    {
        config.accepted_socket = NULL;
        config.hostname = host_name;
        config.port = port_num;
        xio_param = &config;
        // Get the socket definition
        interface_desc = socketio_get_interface_description();
    }
    return uhttp_client_create(interface_desc, xio_param, on_error, sample_info);
}

static void test_http_get(void)
{
    const char* host_name = "localhost";
    int port_num = HTTPS_PORT_NUM;
    HTTP_SAMPLE_INFO sample_info;
    sample_info.stop_running = 0;

    HTTP_CLIENT_HANDLE http_handle = create_uhttp_client_handle(&sample_info, host_name, port_num);
    if (http_handle == NULL)
    {
        (void)printf("FAILED HERE\r\n");
    }
    else
    {
	if (uhttp_client_set_trusted_cert(http_handle, server_ca_cert) != HTTP_CLIENT_OK) {
            (void)printf("FAILED ON trusted_cert\r\n");
	    return;
	}

	if (uhttp_client_set_X509_cert(http_handle, false, client_cert, client_key) != HTTP_CLIENT_OK) {
            (void)printf("FAILED ON x509_cert\r\n");
	    return;
	}

        (void)uhttp_client_set_trace(http_handle, true, true);
        if (uhttp_client_open(http_handle, host_name, port_num, on_http_connected, &sample_info) != HTTP_CLIENT_OK)
        {
            (void)printf("FAILED MORE HERE\r\n");
        }
        else
        {
            if (uhttp_client_execute_request(http_handle, HTTP_CLIENT_REQUEST_GET, "/", NULL, NULL, 0, on_http_recv, &sample_info) != HTTP_CLIENT_OK)
            {
                (void)printf("FAILED FURTHER HERE\r\n");
            }
            else
            {
                do
                {
                    uhttp_client_dowork(http_handle);
                } while (sample_info.stop_running == 0);
            }
            uhttp_client_close(http_handle, on_closed_callback, NULL);
        }
        uhttp_client_destroy(http_handle);
    }
}

int main(void)
{
    int result;

    if (platform_init() != 0)
    {
        (void)printf("platform_init\r\n");
        result = __LINE__;
    }
    else
    {
        result = 0;

        (void)printf("\r\nSending HTTP GET\r\n\r\n");
        test_http_get();

        platform_deinit();
    }

    (void)printf("Press any key to continue:");
    (void)getchar();
    return result;
}
