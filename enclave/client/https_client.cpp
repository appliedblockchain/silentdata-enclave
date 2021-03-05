/*
 *  SSL client with certificate authentication
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/*
 * Modified 2020-11-30 tgrbrooks
 */

#include "enclave/client/https_client.hpp"

namespace
{

// Calculate the time in seconds from Jan 01 1970 (UTC)
int utc_unix_timestamp(const mbedtls_x509_time &time)
{
    struct tm date = {};
    date.tm_year = time.year - 1900;
    date.tm_mon = time.mon - 1;
    date.tm_mday = time.day;
    date.tm_hour = time.hour;
    date.tm_min = time.min;
    date.tm_sec = time.sec;
    return silentdata::enclave::tm_to_timestamp(date);
}

void print_mbedtls_error(const char *name, int ret)
{
    if (ret != 0)
    {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        ERROR_LOG("%s returned with error: -0x%X - %s", name, -ret, error_buf);
    }
}

} // namespace

namespace silentdata
{
namespace enclave
{

// Constructor
HTTPSClient::HTTPSClient(const char *server,
                         const ClientOptions &opt,
                         const std::vector<std::string> &certificates)
    : server_(server), opt_(opt)
{
    request_body_ = NULL;
    length_ = 0;
    output_ = NULL;
    session_saved_ = false;
    session_closed_ = true;
    initial_setup_ = false;
    mbedtls_initialised_ = false;
    for (const auto &cert : certificates)
        pinned_certificates_ += cert;

    // Make sure memory references of MBED TLS objects are valid.
    mbedtls_init();

    // Set the debugging information level if MBEDTLS debugging available
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(opt_.debug_level);
#endif
}

// Destructor
HTTPSClient::~HTTPSClient()
{
    // Make sure the TLS connection has been closed without trying to reconnect
    if (!session_closed_)
    {
        opt_.reconnect = 0;
        close_notify();
    }
    // Clean up the MBED TLS object memory
    mbedtls_free();
}

// Send a GET request and parse the response
HTTPSResponse
HTTPSClient::get(const char *endpoint, const std::vector<char *> &headers, ClientOptions opt)
{
    unsigned char output[opt.output_length];
    opt.request_type = GET_REQUEST_TYPE;
    opt.request_page = endpoint;
    const char *body = "";
    try
    {
        configure_and_send(opt, headers, body, output);
    }
    catch (const EnclaveException &e)
    {
        if (mbedtls_initialised_)
            mbedtls_free();
        EXCEPTION_LOG(e);
        THROW_EXCEPTION(e.get_code(), "Sending GET request failed");
    }

    bool parse_valid = true;
    HTTPParseResult parse_result = parse_http(output);
    if (parse_result.status != httpparser::HttpResponseParser::ParsingCompleted)
        parse_valid = false;

    // Return the response and certificate_chain from the server
    HTTPSResponse https_response(parse_result.response, certificate_chain_str_, parse_valid);
    return https_response;
}

// Send a POST request and parse the response
HTTPSResponse HTTPSClient::post(const char *endpoint,
                                const std::vector<char *> &headers,
                                const char *body,
                                ClientOptions opt)
{
    unsigned char output[opt.output_length];
    opt.request_type = POST_REQUEST_TYPE;
    opt.request_page = endpoint;
    try
    {
        configure_and_send(opt, headers, body, output);
    }
    catch (const EnclaveException &e)
    {
        if (mbedtls_initialised_)
            mbedtls_free();
        EXCEPTION_LOG(e);
        THROW_EXCEPTION(e.get_code(), "Sending POST request failed");
    }

    bool parse_valid = true;
    HTTPParseResult parse_result = parse_http(output);
    if (parse_result.status != httpparser::HttpResponseParser::ParsingCompleted)
        parse_valid = false;

    // Return the response and certificate_chain from the server
    HTTPSResponse https_response(parse_result.response, certificate_chain_str_, parse_valid);
    return https_response;
}

// Initialise mbedtls objects
void HTTPSClient::mbedtls_init()
{
    mbedtls_initialised_ = true;
    mbedtls_net_init(&server_fd_);
    mbedtls_ssl_init(&ssl_);
    mbedtls_ssl_config_init(&conf_);
    memset(&saved_session_, 0, sizeof(mbedtls_ssl_session));
    mbedtls_ctr_drbg_init(&ctr_drbg_);
    mbedtls_x509_crt_init(&cacert_);
    mbedtls_entropy_init(&entropy_);
}

// Free the memory of mbedtls objects
void HTTPSClient::mbedtls_free()
{
    // Reset the flags
    session_saved_ = false;
    session_closed_ = true;
    initial_setup_ = false;
    mbedtls_initialised_ = false;
    // Free the memory of mbedtls objects
    mbedtls_net_free(&server_fd_);
    mbedtls_x509_crt_free(&cacert_);
    mbedtls_ssl_session_free(&saved_session_);
    mbedtls_ssl_free(&ssl_);
    mbedtls_ssl_config_free(&conf_);
    mbedtls_ctr_drbg_free(&ctr_drbg_);
    mbedtls_entropy_free(&entropy_);
}

// Reset the member variables so a new request can be made
void HTTPSClient::configure_and_send(const ClientOptions &opt,
                                     const std::vector<char *> &headers,
                                     const char *request_body,
                                     unsigned char *output)
{
    // Compare old and new configurations to determine if the client needs to be reconfigured
    bool configuration_changed = false;
    if (opt_.transport != opt.transport || opt_.read_timeout != opt.read_timeout ||
        opt_.tickets != opt.tickets || opt_.nbio != opt.nbio)
        configuration_changed = true;

    // Reassign the member variables
    opt_ = opt;
    headers_ = headers;
    request_body_ = const_cast<char *>(request_body);
    output_ = output;
    length_ = opt.output_length;

    // If the client hasn't been previously run before
    if (mbedtls_initialised_ && !initial_setup_)
    {
        DEBUG_LOG("First time running client");
        return run_client();
    }
    // If the client still has a connection open send another request
    if (mbedtls_initialised_ && !session_closed_ && !configuration_changed)
    {
        DEBUG_LOG("Session still open, sending a new request");
        return send_request();
    }
    // If the client has been run before and a session has been saved try to reconnect
    if (mbedtls_initialised_ && session_saved_ && !configuration_changed)
    {
        DEBUG_LOG("Session was previously saved, trying to reconnect");
        return reconnect();
    }
    DEBUG_LOG("Resetting the client");
    // Otherwise we need to reset everything and start again
    // Clean up the MBED TLS object memory
    mbedtls_free();
    // Make sure memory references of MBED TLS objects are valid.
    mbedtls_init();

    return run_client();
}

// Call all of the member functions required to run the client
void HTTPSClient::run_client()
{
    setup_for_request();
    send_request();
    return;
}

// Perform all set up and configuration steps required to make request
void HTTPSClient::setup_for_request()
{
    initialise_random_generator();
    load_certificates();
    start_connection();
    configure_ssl();
    perform_handshake();
    verify_certificate();
    initial_setup_ = true;
    return;
}

//  Initialize the random number generator (CRT-DRBG) with a source of entropy
void HTTPSClient::initialise_random_generator()
{
    INFO_LOG("Seeding the random number generator");
    const char *pers = "ssl_client2";
    int ret;
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg_,
                                     mbedtls_entropy_func,
                                     &entropy_,
                                     (const unsigned char *)pers,
                                     strlen(pers))) != 0)
    {
        print_mbedtls_error("mbedtls_crt_drbg_seed", ret);
        THROW_EXCEPTION(kClientConfigurationError, "Initialising random number generator failed");
    }

    return;
}

//  Load the trusted CA certificates
void HTTPSClient::load_certificates()
{
    INFO_LOG("Loading the pinned leaf certificate(s)");

    // load trusted crts
    int ret = mbedtls_x509_crt_parse(&cacert_,
                                     (const unsigned char *)(pinned_certificates_.c_str()),
                                     pinned_certificates_.size() + 1);
    if (ret != 0)
    {
        print_mbedtls_error("mbedtls_x509_crt_parse", ret);
        THROW_EXCEPTION(kClientCertificateParseError, "Parsing the CA certificates failed");
    }

    return;
}

//  Start the connection to the server in the specified transport mode
void HTTPSClient::start_connection()
{
    if (opt_.server_addr == NULL)
        opt_.server_addr = server_;

    INFO_LOG("Connecting to %s:%s:%s...",
             opt_.transport == MBEDTLS_SSL_TRANSPORT_STREAM ? "TCP" : "UDP",
             opt_.server_addr,
             opt_.server_port);

    int ret;
    if ((ret = mbedtls_net_connect(&server_fd_,
                                   opt_.server_addr,
                                   opt_.server_port,
                                   opt_.transport == MBEDTLS_SSL_TRANSPORT_STREAM
                                       ? MBEDTLS_NET_PROTO_TCP
                                       : MBEDTLS_NET_PROTO_UDP)) != 0)
    {
        print_mbedtls_error("mbedtls_net_connect", ret);
        THROW_EXCEPTION(kClientConnectionError, "Initial connection to server failed");
    }

    // Set blocking or non-blocking I/O
    if (opt_.nbio > 0)
    {
        DEBUG_LOG("Setting non-blocking I/O");
        ret = mbedtls_net_set_nonblock(&server_fd_);
    }
    else
    {
        DEBUG_LOG("Setting blocking I/O");
        ret = mbedtls_net_set_block(&server_fd_);
    }
    if (ret != 0)
    {
        print_mbedtls_error("mbedtls_net_set_(non)block", ret);
        THROW_EXCEPTION(kClientConfigurationError, "Setting blocking or non-blocking I/O failed");
    }

    session_closed_ = false;
    return;
}

//  Set up the SSL client configurations
void HTTPSClient::configure_ssl()
{
    INFO_LOG("Setting up the SSL/TLS structure...");
    // Load the default SSL configuration values
    int ret;
    if ((ret = mbedtls_ssl_config_defaults(
             &conf_, MBEDTLS_SSL_IS_CLIENT, opt_.transport, MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        print_mbedtls_error("mbedtls_ssl_config_defaults", ret);
        THROW_EXCEPTION(kClientConfigurationError, "Loading default configuration values failed");
    }

    // Set the random number generator callback
    mbedtls_ssl_conf_rng(&conf_, mbedtls_ctr_drbg_random, &ctr_drbg_);

    // Set the certificate verification mode top optional as varification performed by the
    // pinned_verify function
    mbedtls_ssl_conf_authmode(&conf_, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_verify(&conf_, pinned_verify, &cacert_);
    // Set the timeout period for mbed_tls_ssl_read()
    DEBUG_LOG("Setting read timeout to %i", opt_.read_timeout);
    mbedtls_ssl_conf_read_timeout(&conf_, opt_.read_timeout);
    // Enable/disable session tickets
    mbedtls_ssl_conf_session_tickets(&conf_, opt_.tickets);

    // Set the data required to verify peer certificate
    mbedtls_ssl_conf_ca_chain(&conf_, &cacert_, NULL);

    // Set up an SSL context for use
    if ((ret = mbedtls_ssl_setup(&ssl_, &conf_)) != 0)
    {
        print_mbedtls_error("mbedtls_ssl_setup", ret);
        THROW_EXCEPTION(kClientConfigurationError, "Setting up SSL context failed");
    }

    // Set or reset the hostname to check against the received server
    // certificate
    if ((ret = mbedtls_ssl_set_hostname(&ssl_, server_)) != 0)
    {
        print_mbedtls_error("mbedtls_ssl_set_hostname", ret);
        THROW_EXCEPTION(kClientConfigurationError, "Checking server hostname failed");
    }

    // Set the underlying blocking/non-blocking I/O callbacks for write, read
    // and read-with-timeout
    mbedtls_ssl_set_bio(&ssl_,
                        &server_fd_,
                        mbedtls_net_send,
                        mbedtls_net_recv,
                        opt_.nbio == 0 ? mbedtls_net_recv_timeout : NULL);

    return;
}

//  Perform SSL handshake and save the session if reconnecting
void HTTPSClient::perform_handshake()
{
    INFO_LOG("Performing the SSL/TLS handshake");
    DEBUG_LOG("Verifying peer X.509 certificate with pinned certificates");
    int ret;
    while ((ret = mbedtls_ssl_handshake(&ssl_)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            print_mbedtls_error("mbedtls_ssl_handshake", ret);
            if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED)
                ERROR_LOG("Unable to verify the server's certificate. Either it is invalid, or you "
                          "didn't set ca_file or ca_path to an appropriate value.");
            THROW_EXCEPTION(kClientHandshakeError, "TLS handshake with server failed");
        }
    }
    DEBUG_LOG("X.509 Verifies");

    INFO_LOG("Hand shake succeeds: [%s, %s]",
             mbedtls_ssl_get_version(&ssl_),
             mbedtls_ssl_get_ciphersuite(&ssl_));

    if ((ret = mbedtls_ssl_get_record_expansion(&ssl_)) >= 0)
        DEBUG_LOG("Record expansion is [%d]", ret);
    else
        DEBUG_LOG("Record expansion is [unknown (compression)]");

    DEBUG_LOG("Maximum fragment length is [%u]", (unsigned int)mbedtls_ssl_get_max_frag_len(&ssl_));

    // Save the server certificate chain in PEM format
    certificate_chain_str_ = get_certificate_chain();

    // Check if any of the certificate chain is expired
    const mbedtls_x509_crt *certificate = mbedtls_ssl_get_peer_cert(&ssl_);
    if (check_certificate_expiration(certificate) == false)
    {
        THROW_EXCEPTION(kClientExpiredCertificate, "Server certificates are expired");
    }

    // If there are reconnect attempts left and the session hasn't already been saved, copy the
    // session data to a session structure
    if ((opt_.reconnect != 0 || opt_.save_session || !opt_.close_session) && !session_saved_)
    {
        INFO_LOG("Saving session for reuse...");

        if ((ret = mbedtls_ssl_get_session(&ssl_, &saved_session_)) != 0)
        {
            print_mbedtls_error("mbedtls_ssl_get_session", ret);
            THROW_EXCEPTION(kClientReconnectionError, "Saving session for reuse failed");
        }

        session_saved_ = true;
    }

    return;
}

// Get the result of the certificate verification and print the peer certificate contents if
// debugging
void HTTPSClient::verify_certificate()
{
    if (mbedtls_ssl_get_peer_cert(&ssl_) != NULL)
    {
        if (opt_.debug_level > 0)
        {
            DEBUG_LOG("Peer certificate information");
            char cert_buffer[MBEDTLS_SSL_MAX_CONTENT_LEN + 1];
            mbedtls_x509_crt_info(
                cert_buffer, sizeof(cert_buffer) - 1, "|-", mbedtls_ssl_get_peer_cert(&ssl_));
            DEBUG_LOG("%s\n", cert_buffer);
        }
    }

    return;
}

// Write the GET/POST request and read the HTTP response
void HTTPSClient::send_request()
{
    unsigned char buffer[MBEDTLS_SSL_MAX_CONTENT_LEN + 1];
    int len = mbedtls_snprintf((char *)buffer,
                               sizeof(buffer) - 1,
                               opt_.request_type == GET_REQUEST_TYPE ? GET_REQUEST : POST_REQUEST,
                               opt_.request_page);

    for (size_t i = 0; i < headers_.size(); i++)
    {
        len +=
            mbedtls_snprintf((char *)buffer + len, sizeof(buffer) - 1 - len, "%s\r\n", headers_[i]);
    }

    // Add body to request if there is one (assumes only POST requests have bodies)
    if ((strlen(request_body_) + len) > (MBEDTLS_SSL_MAX_CONTENT_LEN - 30))
    {
        THROW_EXCEPTION(kClientWriteError,
                        "Request body length is longer than the maximum content length");
    }
    if (strlen(request_body_) > 0)
    {
        len += mbedtls_snprintf((char *)buffer + len,
                                sizeof(buffer) - 1 - len,
                                "Content-Length: %zu\r\n\r\n",
                                strlen(request_body_));
        len +=
            mbedtls_snprintf((char *)buffer + len, sizeof(buffer) - 1 - len, "%s", request_body_);
    }

    int tail_len =
        (int)strlen(opt_.request_type == GET_REQUEST_TYPE ? GET_REQUEST_END : POST_REQUEST_END);

    // Add padding to request to reach opt.request_size in length
    if (opt_.request_size != DFL_REQUEST_SIZE && len + tail_len < opt_.request_size)
    {
        memset(buffer + len, 'A', opt_.request_size - len - tail_len);
        len += opt_.request_size - len - tail_len;
    }

    strncpy((char *)buffer + len,
            opt_.request_type == GET_REQUEST_TYPE ? GET_REQUEST_END : POST_REQUEST_END,
            sizeof(buffer) - len - 1);
    len += tail_len;

    // Truncate if request size is smaller than the "natural" size
    if (opt_.request_size != DFL_REQUEST_SIZE && len > opt_.request_size)
    {
        len = opt_.request_size;

        // Still end with \r\n unless that's really not possible
        if (len >= 2)
            buffer[len - 2] = '\r';
        if (len >= 1)
            buffer[len - 1] = '\n';
    }

    // Try to write exactly (len - written) application data bytes
    int written, frags;
    int ret = 0;
    for (written = 0, frags = 0; written < len; written += ret, frags++)
    {
        while ((ret = mbedtls_ssl_write(&ssl_, buffer + written, len - written)) <= 0)
        {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                print_mbedtls_error("mbedtls_ssl_write", ret);
                THROW_EXCEPTION(kClientWriteError, "Writing HTTPS request failed");
            }
        }
    }

    buffer[written] = '\0';
    DEBUG_LOG("%d bytes written in %d fragments", written, frags);

    //  Read the HTTP response from the stream
    do
    {
        len = length_ - 1;
        memset(output_, 0, length_);
        // Read at most len application data bytes
        ret = mbedtls_ssl_read(&ssl_, output_, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret <= 0)
        {
            switch (ret)
            {
            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                INFO_LOG("Connection was closed by peer");
                // Waiting too long with the session open can cause the server to close it, in this
                // case try to reconnect with a saved session
                if (!opt_.close_session && session_saved_)
                {
                    opt_.close_session = true;
                    return reconnect();
                }
                opt_.close_session = true;
                return close_notify();

            case 0:
            case MBEDTLS_ERR_NET_CONN_RESET:
                WARNING_LOG("Connection was reset by peer");
                //  Reconnect if option selected, otherwise exit
                if (opt_.reconnect != 0 && session_saved_)
                {
                    --opt_.reconnect;
                    return reconnect();
                }
                opt_.close_session = true;
                return close_notify();

            default:
                print_mbedtls_error("mbedtls_ssl_read", ret);
                THROW_EXCEPTION(kClientReadError, "Reading HTTPS response failed");
            }
        }

        len = ret;

        DEBUG_LOG("Get %d bytes ending with %x", len, output_[len - 1]);

        // Parse the HTTP response to determine if the server has finished sending
        httpparser::Response response;
        int used_length = opt_.output_length - length_;
        unsigned char *start_pointer = output_ - used_length;
        HTTPParseResult parse_result = parse_http(start_pointer);
        if (parse_result.status == httpparser::HttpResponseParser::ParsingCompleted)
        {
            output_[len] = 0;
            break;
        }
        else if (parse_result.status == httpparser::HttpResponseParser::ParsingError)
        {
            THROW_EXCEPTION(kClientReadError, "Parsing HTTP response failed");
        }

        output_ += len;
        length_ -= len;
    } while (true);

    //  Continue doing data exchanges?
    if (--opt_.exchanges > 0)
        return send_request();

    return close_notify();
}

// Close the connection if not already done
void HTTPSClient::close_notify()
{
    if (opt_.close_session)
    {
        // No error checking, the connection might be closed already
        int ret;
        do
            ret = mbedtls_ssl_close_notify(&ssl_);
        while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

        INFO_LOG("Closed %s:%s", opt_.server_addr, opt_.server_port);
        session_closed_ = true;

        // Reconnect if option selected, otherwise exit
        if (opt_.reconnect != 0 && session_saved_)
        {
            --opt_.reconnect;
            return reconnect();
        }
    }
    return;
}

//  Reconnect to a saved session
void HTTPSClient::reconnect()
{

    mbedtls_net_free(&server_fd_);
    INFO_LOG("Reconnecting with saved session...");

    int ret;
    if ((ret = mbedtls_ssl_session_reset(&ssl_)) != 0)
    {
        print_mbedtls_error("mbedtls_ssl_session_reset", ret);
        THROW_EXCEPTION(kClientReconnectionError, "Resetting SSL session failed");
    }
    if ((ret = mbedtls_ssl_set_session(&ssl_, &saved_session_)) != 0)
    {
        print_mbedtls_error("mbedtls_ssl_set_session", ret);
        THROW_EXCEPTION(kClientReconnectionError, "Setting SSL session from saved session failed");
    }

    try
    {
        start_connection();
        perform_handshake();
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        ERROR_LOG("Failed to restart session, closing");
        return close_notify();
    }
    return send_request();
}

bool HTTPSClient::check_certificate_expiration(const mbedtls_x509_crt *cert)
{
    mbedtls_x509_crt *certificate = const_cast<mbedtls_x509_crt *>(cert);
    while (certificate != NULL)
    {
        // Get the Leaf certificate and its period of validity
        const mbedtls_x509_time valid_from = certificate->valid_from;
        int valid_from_unix_time = utc_unix_timestamp(valid_from);
        if (opt_.timestamp < valid_from_unix_time)
            return false;

        const mbedtls_x509_time valid_to = certificate->valid_to;
        int valid_to_unix_time = utc_unix_timestamp(valid_to);
        if (opt_.timestamp > valid_to_unix_time)
            return false;

        certificate = certificate->next;
    }

    return true;
}

// Return the certificate chain of the server
std::string HTTPSClient::get_certificate_chain()
{
    std::string certificate_chain;
    // Get the current certificate
    const mbedtls_x509_crt *certificate = mbedtls_ssl_get_peer_cert(&ssl_);
    while (certificate != NULL)
    {
        size_t buffer_length = 10000;
        unsigned char buffer[buffer_length];
        // Get the certificate in DER format (binary)
        mbedtls_x509_buf der_buffer = certificate->raw;
        // Convert to PEM (base64 with header and footer)
        size_t pem_len;
        int ret = mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n",
                                           "-----END CERTIFICATE-----\n",
                                           der_buffer.p,
                                           der_buffer.len,
                                           buffer,
                                           buffer_length,
                                           &pem_len);
        if (ret != 0)
        {
            print_mbedtls_error("mbedtls_pem_write_buffer", ret);
            THROW_EXCEPTION(kClientCertificateParseError, "Failed to write certificate as PEM");
        }
        if (pem_len >= buffer_length)
            THROW_EXCEPTION(kClientCertificateParseError,
                            "Certificate writing failed, buffer not long enough");

        certificate_chain += std::string((char *)buffer);
        certificate = certificate->next;
    }
    if (certificate_chain.length() > 10000)
        THROW_EXCEPTION(kClientCertificateParseError,
                        "Certificate chain longer than maximum output from ECall");

    return certificate_chain;
}

// Parse a HTTP response from a HTTPS client to obtain the body
HTTPSClient::HTTPParseResult HTTPSClient::parse_http(unsigned char *buffer)
{
    const char *begin = static_cast<const char *>(static_cast<void *>(buffer));
    size_t buf_len = strlen(begin);

    httpparser::Response response;
    httpparser::HttpResponseParser parser;
    httpparser::HttpResponseParser::ParseResult res =
        parser.parse(response, begin, begin + buf_len);
    return HTTPParseResult(res, response);
}

// https://github.com/Intevation/mxe/blob/trustbridge/src/curl-2-curlopt-peercert.patch
int HTTPSClient::pinned_verify(void *pinned_chain,
                               mbedtls_x509_crt *crt,
                               int depth,
                               uint32_t *flags)
{
    DEBUG_LOG("Certificate pinning: Verify requested for (Depth %d):", depth);
    // Only allow pinning for leaf (depth 0) certificates
    if (depth != 0)
    {
        DEBUG_LOG("Certificate pinning: Nothing to do here");
        return 0;
    }

    mbedtls_x509_crt *pinned = static_cast<mbedtls_x509_crt *>(pinned_chain);
    mbedtls_x509_crt *leaf = crt;
    int ret;

    if (pinned_chain == NULL || crt == NULL)
    {
        ERROR_LOG("Certificate pinning: Certificates are NULL");
        *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
        return *flags;
    }

    bool found_match = false;
    while (pinned != NULL)
    {
        ret = memcmp(pinned->raw.p, leaf->raw.p, pinned->raw.len);
        if (ret == 0)
            found_match = true;
        pinned = pinned->next;
    }
    if (found_match)
    {
        DEBUG_LOG("Certificate pinning: Found matching certificate");
        *flags = 0;
        return 0;
    }

    ERROR_LOG("Certificate pinning: Didn't find match");
    *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
    return *flags;
}

} // namespace enclave
} // namespace silentdata
