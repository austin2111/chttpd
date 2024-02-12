#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <microhttpd.h>

#define PORT 8082

struct Request {
    struct Session *session;
    struct MHD_PostProcessor *pp;
    const char *post_url;

};

char * lowercase ( char * instring, size_t length) {
    // This converts alphabetic ASCII characters to lower case
    size_t counter = 0;
    while (counter < length) {
        if ( (instring[counter] > 0x40) && (instring[counter] < 0x5B)) {
            instring[counter] += 0x20;
        }
        counter++;
    }
    return instring;
}

struct Session {
    char buffer[2000];
};

static struct Session * get_session(struct MHD_Connection *connection ) {

    struct Session *ret;
    // Te cookie functionality has been removed since we don't especially need it here.

    // Create fresh session
    ret = calloc (1, sizeof(struct Session));
    if (ret == NULL)
    {
         printf("ERROR: calloc: %s\n", strerror(errno));
         return NULL;
    }
    // TO DO: Re-insert actual cookie things here as needed

    return ret;
}

static int post_parse( void *cls,
                       enum MHD_ValueKind kind,
                       const char *key,
                       const char *filename,
                       const char *content_type,
                       const char *transfer_enconding,
                       const char *data, uint64_t off, size_t size)
{
    struct Request *request = cls;
    struct Session *session = request->session;
    if (strcmp("DONE", key) == 0) {

        return MHD_YES;
    }
    strncpy( session->buffer, data, 1999); // memcpy may be a better choice here
    printf("DEBUG: Buffer value is %s\n", session->buffer);
    return MHD_YES;
}

int answer_to_connection (void *cls, struct MHD_Connection *connection,
                          const char *url,
                          const char *method, const char *version,
                          const char *upload_data,
                          size_t *upload_data_size, void **con_cls)
{
    int ret;
    if (strcmp(method, MHD_HTTP_METHOD_POST) == 0) {
        //printf("DEBUG: POST request URL is %s\n", url);
        if (strcmp(url, "/lower") != 0) {
        struct MHD_Response *response;
        const char * page = "<html><title>404 Not Found</title><body>404 Not Found</body></html>";
        response = MHD_create_response_from_buffer (strlen (page), (void*) page, MHD_RESPMEM_PERSISTENT);
        ret = MHD_queue_response (connection, MHD_HTTP_NOT_FOUND, response);
        MHD_destroy_response (response);
        return ret;
        }

        struct Request *request = *con_cls;
        if (request == NULL) {
            //printf("DEBUG: create_post_processor() invoked!\n");
            request = calloc(1, sizeof(struct Request));
            if (request == NULL) {
                printf( "ERROR: calloc/%s\n", strerror(errno));
                return MHD_NO;
            }
            request->pp = MHD_create_post_processor(connection, 1024, &post_parse, request);
            if (request->pp == NULL) {
                printf("ERROR: Failed to setup post process for %s!\n", url);
                return MHD_NO;
            }
            *con_cls = request;
            return MHD_YES;
        }
        if (request->session == NULL) {
            request->session = get_session(connection);
            if (request->session == NULL) {
                printf("ERROR: Failed to start session for %s\n", url);
                return MHD_NO;
            }
        }
        if (*upload_data_size) {
            //printf("DEBUG: MHD_post_process() invoked!\n");
            MHD_post_process(request->pp, upload_data, *upload_data_size);
            *upload_data_size = 0;
            //printf("DEBUG: MHD_post_process() returned data %s\n", upload_data);
            return MHD_YES;
        }
        else {
            // WARNING: This could easily result in HTTP inclusion sorcery! You, uhh, have been warned. If this gets any real use, have something look for </p>
            //MHD_destroy_post_processor(request->pp); // Don't use if creating and destroyng a response; this'll cause effectively a double free to happen.
            struct MHD_Response *response;
            //printf("DEBUG: response should be %s", request->session->buffer);
            char postpage[2034] = {0};
            snprintf(postpage, 2033, "<html><body><p>%s</p></body></html>", lowercase(request->session->buffer, strlen(request->session->buffer)));
            //const char *page = "<html><body>Response has been submitted.</body></html>";
            response = MHD_create_response_from_buffer (strlen (postpage), (void*) postpage, MHD_RESPMEM_MUST_COPY);
            ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
            MHD_destroy_response (response);
            return ret;
        }
        return MHD_NO; // Until the code's written, we'll have it do this.
    }

    else if (strcmp(method, MHD_HTTP_METHOD_GET) != 0) {
        struct MHD_Response *response;
        const char * page = "<html><title>400 Bad Request</title><body>400 Bad Request</body></html>";
        response = MHD_create_response_from_buffer (strlen (page), (void*) page, MHD_RESPMEM_PERSISTENT);
        ret = MHD_queue_response (connection, MHD_HTTP_BAD_REQUEST, response);
        MHD_destroy_response (response);
        return ret;
    }

    // TO DO: Is strncmp necessary?

    //printf("DEBUG: URL is %s\n", url);
    // For reference, a URL is generally accepted to be a maximum of 2000 characters.

    // Do be aware of any potential HTML injection.
    struct MHD_Response *response;
    if (strncmp("/diskspace", url, 10) == 0) {
        // Return df -h command
        FILE *cmddescriptor = popen("df -h", "r");
        if (cmddescriptor == NULL) {
            printf("ERROR: popen() failed!!\n");
            return MHD_NO;
        }
        // Especially with how big the buffer is here, initializing everything to 0x00 is really important. So uhh, do it.
        char cmdout[9974] = {0};
        fread( cmdout, 9973, 1, cmddescriptor);
        pclose(cmddescriptor);
        response = MHD_create_response_from_buffer (strlen (cmdout), (void*) cmdout, MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header( response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/plain");
        ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
        MHD_destroy_response (response);
        return ret;
    }
    else if (strncmp("/cpuinfo", url, 8) == 0) {
        // Return cat /proc/cpuinfo
        FILE *cmddescriptor = popen("cat /proc/cpuinfo", "r");
        if (cmddescriptor == NULL) {
            printf("ERROR: popen() failed!!\n");
            return MHD_NO;
        }
        char cmdout[15474] = {0};
        fread( cmdout, 15473, 1, cmddescriptor);
        pclose(cmddescriptor);
        response = MHD_create_response_from_buffer (strlen (cmdout), (void*) cmdout, MHD_RESPMEM_MUST_COPY);// Don't use MHD_RESPMEM_PERSISTENT here; the buffer is being stored in transient memory
        MHD_add_response_header( response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/plain");
        ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
        MHD_destroy_response (response);
        return ret;
    }

    else if (strncmp("/mem", url, 4) == 0) {
        // Return free command
        FILE *cmddescriptor = popen("free -h", "r");
        if (cmddescriptor == NULL) {
            printf("ERROR: popen() failed!!\n");
            return MHD_NO;
        }
        char cmdout[9974] = {0};
        fread( cmdout, 9973, 1, cmddescriptor);
        pclose(cmddescriptor);
        response = MHD_create_response_from_buffer (strlen (cmdout), (void*) cmdout, MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header( response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/plain");
        ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
        MHD_destroy_response (response);
        return ret;
    }

    const char * page = "<html><body>This is a website!<br><form action=\"/lower\" method=\"POST\"><label for=\"request\">Have a POST request.</label><br><input type=\"text\" id=\"request\" name=\"request\"><br><input type=\"submit\" value=\"Submit\"></form></body></html>";
    response = MHD_create_response_from_buffer (strlen (page), (void*) page, MHD_RESPMEM_PERSISTENT);
    ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
    MHD_destroy_response (response);

    return ret;
}

void completereq_hdlr( void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe)
{
    struct Request *request = *con_cls;
    if (request == NULL) return;
    if (NULL != request->pp) MHD_destroy_post_processor (request->pp);
    free(request);
    return;
}

int main()
{
    struct MHD_Daemon *daemon;
    daemon = MHD_start_daemon (MHD_USE_INTERNAL_POLLING_THREAD, PORT, NULL, NULL,
    &answer_to_connection, NULL, MHD_OPTION_NOTIFY_COMPLETED, &completereq_hdlr, NULL, MHD_OPTION_END);
    if (NULL == daemon) return 1;

    getchar();

    MHD_stop_daemon (daemon);
    return 0;
}
