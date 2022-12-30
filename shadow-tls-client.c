#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#include <shlwapi.h>
#include <assert.h>
#include <stdio.h>

#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "secur32.lib")
#pragma comment (lib, "shlwapi.lib")

#define TLS_MAX_PACKET_SIZE (16384+512) // payload + extra over head for header/mac/padding (probably an overestimate)

typedef struct {
    SOCKET sock;
    CredHandle handle;
    CtxtHandle context;
    SecPkgContext_StreamSizes sizes;
    int received;    // byte count in incoming buffer (ciphertext)
    int used;        // byte count used from incoming buffer to decrypt current packet
    int available;   // byte count available for decrypted bytes
    char* decrypted; // points to incoming buffer where data is decrypted inplace
    char incoming[TLS_MAX_PACKET_SIZE];
} tls_socket;

char pubcert[0x800] = {0x00};
int server_msg_len = 0x700;

void patch_msg(char* server_msg, int len, const char* record, int* reslen)
{
    int count = 0;
    char* tmp = server_msg;
    int index[0x10] = { 0 };

    char result[0x1000];
    memset(result, 0, 0x1000);

    int i;
    for (i = 0; i < len; i++)
    {
        if (server_msg[i] == record[0] && server_msg[i + 1] == record[1] && server_msg[i + 2] == record[2])
        {
            index[count] = i;
            count++;
        }
    }

    index[count] = len;

    int current = 0;
    for (i = 0; i < count; i++)
    {
        if (server_msg[index[i] + 5] == 0xb)
        {
            for (int j = 0; j < server_msg_len; j++)
            {
                result[current + j] = pubcert[j];
            }
            current += 7;
        }
        else
        {
            for (int n = 0; n < (index[i+1] - index[i]); n++)
            {
                result[current + n] = server_msg[index[i] + n];
            }
            current += (index[i + 1] - index[i]);
        }
    }

    reslen[0] = current;

    memcpy(server_msg, result, current);

    if (current < len)
    {
        memset((server_msg + current), 0xcc, (len - current));
    }

    return;
}

// returns 0 on success or negative value on error
static int tls_connect(tls_socket* s, const char* hostname, unsigned short port)
{
    // initialize windows sockets
    WSADATA wsadata;
    if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)
    {
        return -1;
    }

    // create TCP IPv4 socket
    s->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (s->sock == INVALID_SOCKET)
    {
        WSACleanup();
        return -1;
    }

    char sport[64];
    wnsprintfA(sport, sizeof(sport), "%u", port);

    // connect to server
    if (!WSAConnectByNameA(s->sock, hostname, sport, NULL, NULL, NULL, NULL, NULL, NULL))
    {
        closesocket(s->sock);
        WSACleanup();
        return -1;
    }

    // initialize schannel
    {
        SCHANNEL_CRED cred;
        cred.dwVersion = SCHANNEL_CRED_VERSION;
        cred.dwFlags = 0x00400000          // use only strong crypto alogorithms
            | SCH_CRED_AUTO_CRED_VALIDATION  // automatically validate server certificate
            | SCH_CRED_NO_DEFAULT_CREDS;     // no client certificate authentication
        cred.grbitEnabledProtocols = SP_PROT_TLS1_2;  // allow only TLS v1.2

        if (AcquireCredentialsHandleA(NULL, (LPSTR)UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &cred, NULL, NULL, &s->handle, NULL) != SEC_E_OK)
        {
            closesocket(s->sock);
            WSACleanup();
            return -1;
        }
    }

    s->received = s->used = s->available = 0;
    s->decrypted = NULL;

    // perform tls handshake
    // 1) call InitializeSecurityContext to create/update schannel context
    // 2) when it returns SEC_E_OK - tls handshake completed
    // 3) when it returns SEC_I_INCOMPLETE_CREDENTIALS - server requests client certificate (not supported here)
    // 4) when it returns SEC_I_CONTINUE_NEEDED - send token to server and read data
    // 5) when it returns SEC_E_INCOMPLETE_MESSAGE - need to read more data from server
    // 6) otherwise read data from server and go to step 1

    CtxtHandle* context = NULL;
    int result = 0;
    for (;;)
    {
        SecBuffer inbuffers[2] = { 0 };
        inbuffers[0].BufferType = SECBUFFER_TOKEN;
        inbuffers[0].pvBuffer = s->incoming;
        inbuffers[0].cbBuffer = s->received;
        inbuffers[1].BufferType = SECBUFFER_EMPTY;

        SecBuffer outbuffers[1] = { 0 };
        outbuffers[0].BufferType = SECBUFFER_TOKEN;

        SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
        SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };

        DWORD flags = ISC_REQ_USE_SUPPLIED_CREDS | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM | ISC_REQ_MANUAL_CRED_VALIDATION;
        SECURITY_STATUS sec = InitializeSecurityContextA(
            &s->handle,
            context,
            context ? NULL : (SEC_CHAR*)hostname,
            flags,
            0,
            0,
            context ? &indesc : NULL,
            0,
            context ? NULL : &s->context,
            &outdesc,
            &flags,
            NULL);

        // after first call to InitializeSecurityContext context is available and should be reused for next calls
        context = &s->context;

        if (inbuffers[1].BufferType == SECBUFFER_EXTRA)
        {
            MoveMemory(s->incoming, s->incoming + (s->received - inbuffers[1].cbBuffer), inbuffers[1].cbBuffer);
            s->received = inbuffers[1].cbBuffer;
        }
        else
        {
            s->received = 0;
        }

        if (sec == SEC_E_OK)
        {
            // tls handshake completed
            break;
        }
        else if (sec == SEC_I_INCOMPLETE_CREDENTIALS)
        {
            // server asked for client certificate, not supported here
            result = -1;
            break;
        }
        else if (sec == SEC_I_CONTINUE_NEEDED)
        {
            // need to send data to server
            char* buffer = (char*)outbuffers[0].pvBuffer;
            int size = outbuffers[0].cbBuffer;

            while (size != 0)
            {
                int d = send(s->sock, buffer, size, 0);
                if (d <= 0)
                {
                    break;
                }
                size -= d;
                buffer += d;
            }
            FreeContextBuffer(outbuffers[0].pvBuffer);
            if (size != 0)
            {
                // failed to fully send data to server
                result = -1;
                break;
            }
        }
        else if (sec != SEC_E_INCOMPLETE_MESSAGE)
        {
            // SEC_E_CERT_EXPIRED - certificate expired or revoked
            // SEC_E_WRONG_PRINCIPAL - bad hostname
            // SEC_E_UNTRUSTED_ROOT - cannot vertify CA chain
            // SEC_E_ILLEGAL_MESSAGE / SEC_E_ALGORITHM_MISMATCH - cannot negotiate crypto algorithms
            result = -1;
            break;
        }

        // read more data from server when possible
        if (s->received == sizeof(s->incoming))
        {
            // server is sending too much data instead of proper handshake?
            result = -1;
            break;
        }

        int r = recv(s->sock, s->incoming + s->received, sizeof(s->incoming) - s->received, 0);
        if (r == 0)
        {
            // server disconnected socket
            return 0;
        }
        else if (r < 0)
        {
            // socket error
            result = -1;
            break;
        }

        //int reslen[1] = { 0 };

        ////patch_msg(s->incoming, r, "\x16\x03\x03", reslen);

        //s->received += reslen[0];
        s->received += r;
    }

    if (result != 0)
    {
        DeleteSecurityContext(context);
        FreeCredentialsHandle(&s->handle);
        closesocket(s->sock);
        WSACleanup();
        return result;
    }

    QueryContextAttributes(context, SECPKG_ATTR_STREAM_SIZES, &s->sizes);
    return 0;
}

// disconnects socket & releases resources (call this even if tls_write/tls_read function return error)
static void tls_disconnect(tls_socket* s)
{
    DWORD type = SCHANNEL_SHUTDOWN;

    SecBuffer inbuffers[1];
    inbuffers[0].BufferType = SECBUFFER_TOKEN;
    inbuffers[0].pvBuffer = &type;
    inbuffers[0].cbBuffer = sizeof(type);

    SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
    ApplyControlToken(&s->context, &indesc);

    SecBuffer outbuffers[1];
    outbuffers[0].BufferType = SECBUFFER_TOKEN;

    SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };
    DWORD flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
    if (InitializeSecurityContextA(&s->handle, &s->context, NULL, flags, 0, 0, &outdesc, 0, NULL, &outdesc, &flags, NULL) == SEC_E_OK)
    {
        char* buffer = (char*)outbuffers[0].pvBuffer;
        int size = outbuffers[0].cbBuffer;
        while (size != 0)
        {
            int d = send(s->sock, buffer, size, 0);
            if (d <= 0)
            {
                // ignore any failures socket will be closed anyway
                break;
            }
            buffer += d;
            size -= d;
        }
        FreeContextBuffer(outbuffers[0].pvBuffer);
    }
    shutdown(s->sock, SD_BOTH);

    DeleteSecurityContext(&s->context);
    FreeCredentialsHandle(&s->handle);
    closesocket(s->sock);
    WSACleanup();
}

// returns 0 on success or negative value on error
static int tls_write(tls_socket* s, const void* buffer, int size)
{
    while (size != 0)
    {
        int use = min(size, s->sizes.cbMaximumMessage);

        char wbuffer[TLS_MAX_PACKET_SIZE];
        assert(s->sizes.cbHeader + s->sizes.cbMaximumMessage + s->sizes.cbTrailer <= sizeof(wbuffer));

        SecBuffer buffers[3];
        buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
        buffers[0].pvBuffer = wbuffer;
        buffers[0].cbBuffer = s->sizes.cbHeader;
        buffers[1].BufferType = SECBUFFER_DATA;
        buffers[1].pvBuffer = wbuffer + s->sizes.cbHeader;
        buffers[1].cbBuffer = use;
        buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
        buffers[2].pvBuffer = wbuffer + s->sizes.cbHeader + use;
        buffers[2].cbBuffer = s->sizes.cbTrailer;

        CopyMemory(buffers[1].pvBuffer, buffer, use);

        SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };
        SECURITY_STATUS sec = EncryptMessage(&s->context, 0, &desc, 0);
        if (sec != SEC_E_OK)
        {
            // this should not happen, but just in case check it
            return -1;
        }

        int total = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
        int sent = 0;
        while (sent != total)
        {
            int d = send(s->sock, wbuffer + sent, total - sent, 0);
            if (d <= 0)
            {
                // error sending data to socket, or server disconnected
                return -1;
            }
            sent += d;
        }

        buffer = (char*)buffer + use;
        size -= use;
    }

    return 0;
}

// blocking read, waits & reads up to size bytes, returns amount of bytes received on success (<= size)
// returns 0 on disconnect or negative value on error
static int tls_read(tls_socket* s, void* buffer, int size)
{
    int result = 0;

    while (size != 0)
    {
        if (s->decrypted)
        {
            // if there is decrypted data available, then use it as much as possible
            int use = min(size, s->available);
            CopyMemory(buffer, s->decrypted, use);
            buffer = (char*)buffer + use;
            size -= use;
            result += use;

            if (use == s->available)
            {
                // all decrypted data is used, remove ciphertext from incoming buffer so next time it starts from beginning
                MoveMemory(s->incoming, s->incoming + s->used, s->received - s->used);
                s->received -= s->used;
                s->used = 0;
                s->available = 0;
                s->decrypted = NULL;
            }
            else
            {
                s->available -= use;
                s->decrypted += use;
            }
        }
        else
        {
            // if any ciphertext data available then try to decrypt it
            if (s->received != 0)
            {
                SecBuffer buffers[4];
                assert(s->sizes.cBuffers == ARRAYSIZE(buffers));

                buffers[0].BufferType = SECBUFFER_DATA;
                buffers[0].pvBuffer = s->incoming;
                buffers[0].cbBuffer = s->received;
                buffers[1].BufferType = SECBUFFER_EMPTY;
                buffers[2].BufferType = SECBUFFER_EMPTY;
                buffers[3].BufferType = SECBUFFER_EMPTY;

                SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };

                SECURITY_STATUS sec = DecryptMessage(&s->context, &desc, 0, NULL);
                if (sec == SEC_E_OK)
                {
                    assert(buffers[0].BufferType == SECBUFFER_STREAM_HEADER);
                    assert(buffers[1].BufferType == SECBUFFER_DATA);
                    assert(buffers[2].BufferType == SECBUFFER_STREAM_TRAILER);

                    s->decrypted = (char*)buffers[1].pvBuffer;
                    s->available = buffers[1].cbBuffer;
                    s->used = s->received - (buffers[3].BufferType == SECBUFFER_EXTRA ? buffers[3].cbBuffer : 0);

                    // data is now decrypted, go back to beginning of loop to copy memory to output buffer
                    continue;
                }
                else if (sec == SEC_I_CONTEXT_EXPIRED)
                {
                    // server closed TLS connection (but socket is still open)
                    s->received = 0;
                    return result;
                }
                else if (sec == SEC_I_RENEGOTIATE)
                {
                    // server wants to renegotiate TLS connection, not implemented here
                    return -1;
                }
                else if (sec != SEC_E_INCOMPLETE_MESSAGE)
                {
                    // some other schannel or TLS protocol error
                    return -1;
                }
                // otherwise sec == SEC_E_INCOMPLETE_MESSAGE which means need to read more data
            }
            // otherwise not enough data received to decrypt

            if (result != 0)
            {
                // some data is already copied to output buffer, so return that before blocking with recv
                break;
            }

            if (s->received == sizeof(s->incoming))
            {
                // server is sending too much garbage data instead of proper TLS packet
                return -1;
            }

            // wait for more ciphertext data from server
            int r = recv(s->sock, s->incoming + s->received, sizeof(s->incoming) - s->received, 0);
            if (r == 0)
            {
                // server disconnected socket
                return 0;
            }
            else if (r < 0)
            {
                // error receiving data from socket
                result = -1;
                break;
            }
            s->received += r;
        }
    }

    return result;
}

int main()
{
    const char* hostname = "www.baidu.com";
    //const char* hostname = "www.google.com";
    //const char* hostname = "badssl.com";
    //const char* hostname = "expired.badssl.com";
    //const char* hostname = "wrong.host.badssl.com";
    //const char* hostname = "self-signed.badssl.com";
    //const char* hostname = "untrusted-root.badssl.com";
    const char* path = "/";

    tls_socket s;
    if (tls_connect(&s, hostname, 443) != 0)
    {
        //printf("Error connecting to %s\n", hostname);
        //return -1;
    }

    //printf("Connected!\n");

    // send request
    char req[1024];
    int len = sprintf(req, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostname);
    if (tls_write(&s, req, len) != 0)
    {
        tls_disconnect(&s);
        return -1;
    }

    // write response to file
    //FILE* f = fopen("response.txt", "wb");
    int received = 0;
    for (;;)
    {
        char buf[65536];
        int r = tls_read(&s, buf, sizeof(buf));
        if (r < 0)
        {
            //printf("Error receiving data\n");
            break;
        }
        else if (r == 0)
        {
            //printf("Socket disconnected\n");
            break;
        }
        else
        {
            //fwrite(buf, 1, r, f);
            //fflush(f);
            received += r;
        }
    }
    //fclose(f);

    //printf("Received %d bytes\n", received);

    tls_disconnect(&s);
}