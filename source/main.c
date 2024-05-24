#include <libssh/libssh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ENV_PATH "../source/"

typedef struct {
  char host[50];
  char username[50];
  int port;
  int verbosity;
  char passphrase[150];
} ConnectionInfo;

void read_env(ConnectionInfo *credentials) {
  char env_full_path[50];
  int env_print =
      snprintf(env_full_path, sizeof(env_full_path), "%s.env", ENV_PATH);
  if (env_print < 0) {
    printf("Error printing environment path to environment buffer.\n");
    exit(1);
  };

  FILE *file = fopen(env_full_path, "r");
  if (file == NULL) {
    printf("Error opening env file.\n");
    exit(1);
  }

  char line[50];
  while (fgets(line, sizeof(line), file)) {
    char *token = strtok(line, "=");
    if (strcmp(token, "HOST") == 0) { // Fixed comparison
      token = strtok(NULL, "=");
      strcpy(credentials->host, token);
      credentials->host[strcspn(credentials->host, "\n")] = '\0';
    } else if (strcmp(token, "USERNAME") == 0) {
      token = strtok(NULL, "=");
      strcpy(credentials->username, token);
      credentials->username[strcspn(credentials->username, "\n")] = '\0';
    } else if (strcmp(token, "PASSPHRASE") == 0) {
      token = strtok(NULL, "=");
      strcpy(credentials->passphrase, token);
      credentials->passphrase[strcspn(credentials->passphrase, "\n")] = '\0';
    }
  }
  fclose(file);
  credentials->verbosity = SSH_LOG_PROTOCOL;
  credentials->port = 22;
}

// build folder, vps folder name, reminder that the build folder on vps will be
// replaced if it exists

void prompt_for_info(char *path_variable, char *vps_folder_name) {
  puts("Please remember that the target folder on the vps will be deleted if "
       "it already exists. If this is not desired, please cancel.");
  puts("Enter build path:");
  scanf("%s", path_variable);
  puts("Enter vps folder name:");
  scanf("%s", vps_folder_name);
}

void set_ssh_options(ssh_session session, ConnectionInfo *credentials) {
  ssh_options_set(session, SSH_OPTIONS_HOST, &credentials->host);
  ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &credentials->verbosity);
  ssh_options_set(session, SSH_OPTIONS_HOST, &credentials->port);
}

int verify_knownhost(ssh_session session) {
  enum ssh_known_hosts_e state;
  state = ssh_session_is_known_server(session);

  switch (state) {
  case SSH_KNOWN_HOSTS_OK:
    /* OK */

    break;
  case SSH_KNOWN_HOSTS_CHANGED:
    fprintf(stderr, "Host key for server changed: it is now:\n");
    fprintf(stderr, "For security reasons, connection will be stopped\n");
    return -1;
  case SSH_KNOWN_HOSTS_OTHER:
    fprintf(stderr, "The host key for this server was not found but an other"
                    "type of key exists.\n");
    fprintf(stderr,
            "An attacker might change the default server key to"
            "confuse your client into thinking the key does not exist\n");

    return -1;
  case SSH_KNOWN_HOSTS_NOT_FOUND:
    fprintf(stderr, "Could not find known host file.\n");
    fprintf(stderr, "If you accept the host key here, the file will be"
                    "automatically created.\n");

    /* FALL THROUGH*/

  case SSH_KNOWN_HOSTS_UNKNOWN:
    fprintf(stderr, "The server is unknown. Do you trust the host key?\n");
    return -1;
  case SSH_KNOWN_HOSTS_ERROR:
    fprintf(stderr, "Error %s", ssh_get_error(session));
    return -1;
  }

  return 0;
}

int authenticate_pubkey(ssh_session session, char *passphrase, char *username) {
  int rc;
  rc = ssh_userauth_publickey_auto(session, username, passphrase);
  if (rc == SSH_AUTH_ERROR) {
    fprintf(stderr, "Authentication failed: %s\n", ssh_get_error(session));
    return SSH_AUTH_ERROR;
  }

  return rc;
}

/*int dir_exist_check(ssh_session session, char *path, char *dirName) {}
int scp_write(ssh_session session) {
  ssh_scp scp;
  int rc;
}*/

int main(int argc, char *argv[]) {

  ConnectionInfo server_login;
  int rc;
  enum ssh_known_hosts_e state;
  read_env(&server_login);

  char build_path[200], vps_folder_name[256];
  prompt_for_info(build_path, vps_folder_name);
  printf("user input: %s \r %s\n", build_path, vps_folder_name);

  ssh_session ssh_conn = ssh_new();
  if (ssh_conn == NULL) {
    printf("Error creating SSH session.\n");
    exit(-1);
  }

  set_ssh_options(ssh_conn, &server_login);
  rc = ssh_connect(ssh_conn);
  if (rc != SSH_OK) {
    fprintf(stderr, "Error connecting to localhost: %s\n",
            ssh_get_error(ssh_conn));
    exit(-1);
  };

  printf("Connected to server\n");
  if (verify_knownhost(ssh_conn) < 0) {
    printf("Problem with verifying known host");
    ssh_disconnect(ssh_conn);
    ssh_free(ssh_conn);
    exit(-1);
  }
  rc = authenticate_pubkey(ssh_conn, server_login.passphrase,
                           server_login.username);
  if (rc == SSH_AUTH_ERROR) {
    ssh_disconnect(ssh_conn);
    ssh_free(ssh_conn);

    printf("Couldnt authenticate through pubkey");
    exit(-1);
  }
  printf("User was authenticated successfully.\n");

  char command[256], buffer[256];
  int nbytes;
  sprintf(command, "cd %s && ls -a", build_path);

  ssh_channel channel = ssh_channel_new(ssh_conn);
  if (channel == NULL) {
    fprintf(stderr, "Error creating channel.\n");
    ssh_disconnect(ssh_conn);
    ssh_free(ssh_conn);
    exit(-1);
  }

  rc = ssh_channel_open_session(channel);
  if (rc != SSH_OK) {
    fprintf(stderr, "Error openen session on channel\n");
    ssh_channel_free(channel);
    ssh_disconnect(ssh_conn);
    ssh_free(ssh_conn);
    return (-1);
  }

  if (ssh_channel_request_exec(channel, command) != SSH_OK) {
    printf("%s\n", command);
    fprintf(stderr, "Failed to change directory on remote server: %s\n",
            ssh_get_error(ssh_conn));
    ssh_channel_free(channel);
    ssh_disconnect(ssh_conn);
    ssh_free(ssh_conn);
    exit(-1);
  }
  while (ssh_channel_read(channel, buffer, sizeof(buffer), 0) > 0) {
    fwrite(buffer, 1, nbytes, stdout);
  };
  if (nbytes < 0) {
    fprintf(stderr, "Error reading data from channel: %s\n",
            ssh_get_error(ssh_conn));
  };
  printf("Buffer content: %s", buffer);
  ssh_channel_send_eof(channel);
  ssh_channel_close(channel);
  ssh_channel_free(channel);
  ssh_disconnect(ssh_conn);
  ssh_free(ssh_conn); // This should be used after using the session

  return 0;
}
